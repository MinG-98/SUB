#!/usr/bin/env python3
"""Collect per-user counters from the local US proxy cores."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml
from sqlalchemy import delete, select

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.account_policy import is_expired  # noqa: E402
from app.credentials import (  # noqa: E402
    credential_scope_is_allowed,
    credential_stats_id,
)
from app.models import (  # noqa: E402
    CollectorRun,
    FlowRecord,
    Friend,
    Node,
    ProxyTrafficCounter,
    UserNodeCredential,
    make_session_factory,
    utc_iso,
    utcnow,
)
from app.quota import credential_kick_stats_ids  # noqa: E402

STATUS_PATH = Path(
    os.environ.get(
        "SUB_APP_PROXY_STATUS", "/var/lib/sub-app/proxy-collector-status.json"
    )
)
RETENTION_DAYS = 30
VLESS_STATS_BINARY = os.environ.get(
    "SUB_APP_VLESS_STATS_BINARY", "/usr/local/libexec/sub-app-vless-stats"
)
VLESS_STAT_RE = re.compile(r"^user>>>([^>]+)>>>traffic>>>(uplink|downlink)$")


def _bucket(now):
    now = now.astimezone(timezone.utc).replace(tzinfo=None)
    return now.replace(minute=now.minute - now.minute % 5, second=0, microsecond=0)


def _non_negative(current, previous):
    if previous is None or current < previous:
        return 0
    return current - previous


def _loopback_http_base(listen: str) -> str:
    try:
        parsed = urlsplit(f"//{listen}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("Hysteria traffic API 地址无效") from exc
    if (
        not host
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "%" in host
    ):
        raise RuntimeError("Hysteria traffic API 地址无效")
    if host.lower() == "localhost":
        normalized_host = "127.0.0.1"
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise RuntimeError("Hysteria traffic API 必须绑定 loopback") from exc
        if not address.is_loopback:
            raise RuntimeError("Hysteria traffic API 必须绑定 loopback")
        normalized_host = (
            f"[{address.compressed}]" if address.version == 6 else address.compressed
        )
    return f"http://{normalized_host}:{port}"


def _hysteria_endpoint():
    cfg = yaml.safe_load(Path("/etc/hysteria-us-8443/config.yaml").read_text()) or {}
    stats = cfg.get("trafficStats") or {}
    listen = str(stats.get("listen", "127.0.0.1:9999"))
    return _loopback_http_base(listen), str(stats.get("secret", ""))


def _hysteria_stats():
    base, secret = _hysteria_endpoint()
    if not secret:
        raise RuntimeError("Hysteria traffic API 未配置 secret")
    response = httpx.get(
        f"{base}/traffic",
        headers={"Authorization": secret},
        timeout=12,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("Hysteria traffic API 返回格式错误")
    return data


def _hysteria_online():
    base, secret = _hysteria_endpoint()
    if not secret:
        raise RuntimeError("Hysteria traffic API 未配置 secret")
    response = httpx.get(
        f"{base}/online",
        headers={"Authorization": secret},
        timeout=12,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("Hysteria online API 返回格式错误")
    return {
        str(client_id)
        for client_id, count in data.items()
        if type(count) is int and count > 0
    }


def _hysteria_kick(stats_ids: list[str]) -> None:
    if not stats_ids:
        return
    base, secret = _hysteria_endpoint()
    if not secret:
        raise RuntimeError("Hysteria traffic API 未配置 secret")
    response = httpx.post(
        f"{base}/kick",
        headers={"Authorization": secret},
        json=stats_ids,
        timeout=12,
    )
    response.raise_for_status()


def kick_overquota_hysteria_sessions(db) -> dict[str, int]:
    """Kick online local-HY2 sessions whose credentials are no longer valid."""
    node_id = db.scalar(
        select(Node.id).where(
            Node.adapter_kind == "local_hy2", Node.protocol == "hysteria2"
        )
    )
    if node_id is None:
        raise RuntimeError("未配置本机 Hysteria2 适配器节点")
    candidates = credential_kick_stats_ids(db, node_id, "hysteria2")
    if not candidates:
        return {"candidates": 0, "online": 0, "kicked": 0}
    targets = sorted(set(candidates).intersection(_hysteria_online()))
    if targets:
        _hysteria_kick(targets)
    return {
        "candidates": len(candidates),
        "online": len(targets),
        "kicked": len(targets),
    }


def collect_hysteria(db, now):
    node_id = db.scalar(
        select(Node.id).where(
            Node.adapter_kind == "local_hy2", Node.protocol == "hysteria2"
        )
    )
    if node_id is None:
        raise RuntimeError("未配置本机 Hysteria2 适配器节点")
    node = db.get(Node, node_id)
    if not node or is_expired(node.expires_at):
        return {"status": "success", "stats_clients": 0, "samples_written": 0}
    stats = _hysteria_stats()
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == "hysteria2",
            UserNodeCredential.revoked_at.is_(None),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    ).all()
    by_id = {}
    current_time = utcnow().replace(tzinfo=None)
    for row, _friend in rows:
        if not credential_scope_is_allowed(row, _friend):
            continue
        if is_expired(_friend.expires_at):
            continue
        if row.status == "grace" and (
            not row.grace_until or row.grace_until <= current_time
        ):
            continue
        if row.status in {"active", "grace"}:
            by_id[credential_stats_id(row)] = row

    bucket = _bucket(now)
    written = 0
    for client_id, value in stats.items():
        row = by_id.get(str(client_id))
        if row is None or not isinstance(value, dict):
            continue
        current_in = max(0, int(value.get("rx", 0) or 0))
        current_out = max(0, int(value.get("tx", 0) or 0))
        counter = db.scalar(
            select(ProxyTrafficCounter).where(
                ProxyTrafficCounter.source == "hysteria2",
                ProxyTrafficCounter.node_id == node_id,
                ProxyTrafficCounter.credential_key == str(client_id),
            )
        )
        previous_in = counter.last_bytes_in if counter else None
        previous_out = counter.last_bytes_out if counter else None
        delta_in = _non_negative(current_in, previous_in)
        delta_out = _non_negative(current_out, previous_out)
        if counter is None:
            counter = ProxyTrafficCounter(
                source="hysteria2",
                node_id=node_id,
                friend_id=row.friend_id,
                credential_key=str(client_id),
            )
            db.add(counter)
        counter.friend_id = row.friend_id
        counter.last_bytes_in = current_in
        counter.last_bytes_out = current_out
        counter.updated_at = now.replace(tzinfo=None)
        key = f"hysteria2:{node_id}:{client_id}:{bucket.isoformat()}"
        flow = db.scalar(
            select(FlowRecord).where(
                FlowRecord.source == "hysteria2",
                FlowRecord.sample_key == key,
            )
        )
        if flow is None:
            flow = FlowRecord(
                node_id=node_id,
                friend_id=row.friend_id,
                device_id=row.device_id,
                bucket=bucket,
                source="hysteria2",
                sample_key=key,
                bytes_in=delta_in,
                bytes_out=delta_out,
            )
            db.add(flow)
        else:
            flow.friend_id = row.friend_id
            flow.device_id = row.device_id
            flow.bytes_in += delta_in
            flow.bytes_out += delta_out
        written += 1
    return {
        "status": "success",
        "stats_clients": len(stats),
        "samples_written": written,
    }


def _vless_stats():
    result = subprocess.run(
        [VLESS_STATS_BINARY],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("VLESS V2Ray API 查询失败")
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("VLESS V2Ray API 返回格式错误") from exc
    stats = payload.get("stats") if isinstance(payload, dict) else None
    if not isinstance(stats, list):
        raise RuntimeError("VLESS V2Ray API 返回格式错误")
    return stats


def collect_vless(db, now):
    """Collect named VLESS user counters from the loopback V2Ray API."""

    node_id = db.scalar(
        select(Node.id).where(
            Node.adapter_kind == "local_vless", Node.protocol == "vless"
        )
    )
    if node_id is None:
        raise RuntimeError("未配置本机 VLESS 适配器节点")
    node = db.get(Node, node_id)
    if not node or is_expired(node.expires_at):
        return {"status": "success", "stats_users": 0, "samples_written": 0}
    stats = _vless_stats()
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == "vless",
            UserNodeCredential.revoked_at.is_(None),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    ).all()
    by_id = {}
    current_time = utcnow().replace(tzinfo=None)
    for row, _friend in rows:
        if not credential_scope_is_allowed(row, _friend):
            continue
        if is_expired(_friend.expires_at):
            continue
        if row.status == "grace" and (
            not row.grace_until or row.grace_until <= current_time
        ):
            continue
        if row.status in {"active", "grace"}:
            by_id[credential_stats_id(row)] = row

    counters = {}
    for item in stats:
        if not isinstance(item, dict):
            continue
        match = VLESS_STAT_RE.match(str(item.get("name", "")))
        if not match:
            continue
        stats_id, direction = match.groups()
        row = by_id.get(stats_id)
        if row is None:
            continue
        try:
            value = max(0, int(item.get("value", 0) or 0))
        except (TypeError, ValueError):
            continue
        entry = counters.setdefault(stats_id, {"row": row, "in": 0, "out": 0})
        entry["in" if direction == "uplink" else "out"] = value

    bucket = _bucket(now)
    written = 0
    for stats_id, entry in counters.items():
        row = entry["row"]
        current_in = entry["in"]
        current_out = entry["out"]
        counter = db.scalar(
            select(ProxyTrafficCounter).where(
                ProxyTrafficCounter.source == "vless",
                ProxyTrafficCounter.node_id == node_id,
                ProxyTrafficCounter.credential_key == stats_id,
            )
        )
        previous_in = counter.last_bytes_in if counter else None
        previous_out = counter.last_bytes_out if counter else None
        delta_in = _non_negative(current_in, previous_in)
        delta_out = _non_negative(current_out, previous_out)
        if counter is None:
            counter = ProxyTrafficCounter(
                source="vless",
                node_id=node_id,
                friend_id=row.friend_id,
                credential_key=stats_id,
            )
            db.add(counter)
        counter.friend_id = row.friend_id
        counter.last_bytes_in = current_in
        counter.last_bytes_out = current_out
        counter.updated_at = now.replace(tzinfo=None)
        key = f"vless:{node_id}:{stats_id}:{bucket.isoformat()}"
        flow = db.scalar(
            select(FlowRecord).where(
                FlowRecord.source == "vless",
                FlowRecord.sample_key == key,
            )
        )
        if flow is None:
            flow = FlowRecord(
                node_id=node_id,
                friend_id=row.friend_id,
                device_id=row.device_id,
                bucket=bucket,
                source="vless",
                sample_key=key,
                bytes_in=delta_in,
                bytes_out=delta_out,
            )
            db.add(flow)
        else:
            flow.friend_id = row.friend_id
            flow.device_id = row.device_id
            flow.bytes_in += delta_in
            flow.bytes_out += delta_out
        written += 1
    return {
        "status": "success",
        "stats_users": len(counters),
        "samples_written": written,
    }


def _write_status(payload):
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix="proxy-status.", suffix=".json", dir=str(STATUS_PATH.parent)
    )
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(path, 0o600)
        os.replace(path, STATUS_PATH)
    finally:
        path.unlink(missing_ok=True)


def main():
    db_path = os.environ.get("SUB_APP_DB", os.path.join(ROOT, "data.db"))
    factory = make_session_factory(db_path)
    db = factory()
    started_at = datetime.now(timezone.utc)
    run = CollectorRun(
        started_at=started_at.astimezone(timezone.utc).replace(tzinfo=None),
        source="proxy",
        status="running",
    )
    db.add(run)
    db.commit()
    results = {}
    try:
        for name, callback in (
            ("hysteria2", collect_hysteria),
            ("vless", collect_vless),
        ):
            try:
                results[name] = callback(db, started_at)
                db.commit()
                if name == "hysteria2":
                    try:
                        results[name]["quota_kick"] = kick_overquota_hysteria_sessions(
                            db
                        )
                    except Exception as exc:
                        # Traffic samples are already committed. Preserve them
                        # while making an unsuccessful session kick visible.
                        results[name]["status"] = "partial"
                        results[name]["quota_kick_error"] = type(exc).__name__
            except Exception as exc:
                db.rollback()
                results[name] = {
                    "status": "error",
                    "samples_written": 0,
                    "error": type(exc).__name__,
                }
        db.execute(
            delete(FlowRecord).where(
                FlowRecord.source.in_(["hysteria2", "vless"]),
                FlowRecord.bucket
                < (
                    started_at.astimezone(timezone.utc).replace(tzinfo=None)
                    - timedelta(days=RETENTION_DAYS)
                ),
            )
        )
        statuses = [item.get("status") for item in results.values()]
        run.status = (
            "success"
            if statuses == ["success", "not_ready"]
            or all(s == "success" for s in statuses)
            else "partial"
        )
        run.samples_written = sum(
            int(item.get("samples_written", 0)) for item in results.values()
        )
        run.nodes_total = 2
        finished_at = datetime.now(timezone.utc)
        run.finished_at = finished_at.astimezone(timezone.utc).replace(tzinfo=None)
        run.error = "; ".join(
            f"{name}:{item.get('error') or item.get('quota_kick_error')}"
            for name, item in results.items()
            if item.get("error") or item.get("quota_kick_error")
        )[:1000]
        db.commit()
        _write_status(
            {"at": utc_iso(finished_at), "status": run.status, "results": results}
        )
        print(
            json.dumps(
                {"ok": True, "status": run.status, "results": results},
                ensure_ascii=True,
            )
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
