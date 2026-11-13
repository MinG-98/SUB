"""Local proxy-core adapters used by the per-user credential rollout.

The US adapters are local.  The other supported VLESS/Hysteria2 nodes are
controlled by a root-only node agent and are not enabled until that agent has
reported a healthy, applied generation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.account_policy import is_expired
from app.converter import parse_uri
from app.credentials import (
    credential_scope_is_allowed,
    credential_stats_id,
    credential_values,
    deny_all_uuid,
)
from app.models import Friend, Node, NodeAgent, UserNodeCredential, utcnow
from app.quota import flow_limit_reached

ADAPTER_ENV_FILE = Path(
    os.environ.get("SUB_APP_PROXY_ADAPTERS_ENV", "/etc/sub-app/proxy-adapters.env")
)
VLESS_SYNC_HELPER = Path(
    os.environ.get(
        "SUB_APP_VLESS_SYNC_HELPER", "/usr/local/libexec/sub-app-vless-sync-root.py"
    )
)
VLESS_SYNC_SOCKET = os.environ.get(
    "SUB_APP_VLESS_SYNC_SOCKET", "/run/sub-app-vless-sync.sock"
)

ADAPTER_INFO = {
    "local_hy2": {
        "protocol": "hysteria2",
        "source": "hysteria2",
        "label": "Hysteria2 HTTP auth",
    },
    "local_vless": {
        "protocol": "vless",
        "source": "vless",
        "label": "VLESS V2Ray API",
    },
    "remote_agent": {
        "protocols": {"vless", "hysteria2"},
        "source": None,
        "label": "节点 Agent",
    },
}


def adapter_info(node: Node) -> dict | None:
    """Return protocol-specific adapter metadata stored on the node itself."""
    info = ADAPTER_INFO.get(node.adapter_kind)
    if not info:
        return None
    if node.adapter_kind == "remote_agent":
        if node.protocol not in info["protocols"]:
            return None
        return {
            "protocol": node.protocol,
            "source": node.protocol,
            "label": f"{node.protocol.upper()} 节点 Agent",
        }
    if node.protocol != info["protocol"]:
        return None
    return info


def is_remote_agent(node: Node) -> bool:
    return node.adapter_kind == "remote_agent" and adapter_info(node) is not None


def is_local_vless(node: Node) -> bool:
    return node.adapter_kind == "local_vless" and adapter_info(node) is not None


def is_local_hy2(node: Node) -> bool:
    return node.adapter_kind == "local_hy2" and adapter_info(node) is not None


def is_supported_node(node: Node) -> bool:
    return adapter_info(node) is not None


def supported_node_ids(db) -> set[int]:
    return {
        node.id for node in db.scalars(select(Node)).all() if is_supported_node(node)
    }


def _read_env(path: Path = ADAPTER_ENV_FILE) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def adapter_marker() -> dict[str, str]:
    return _read_env()


def adapter_ready(node: Node, db=None) -> bool:
    values = adapter_marker()
    if is_local_hy2(node):
        return values.get("HY2_HTTP_AUTH") == "1"
    if is_local_vless(node):
        return values.get("VLESS_V2RAY_API") == "1"
    if is_remote_agent(node) and db is not None:
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node.id))
        if not agent or agent.status not in {"observe", "ready"} or not agent.last_seen:
            return False
        last_seen = _db_utc(agent.last_seen)
        age = (
            (utcnow().replace(tzinfo=None) - last_seen).total_seconds()
            if last_seen
            else None
        )
        return age is not None and 0 <= age <= 180
    return False


def node_per_user_enabled(node: Node) -> bool:
    """Local adapters are managed by the host; remote adapters are opt-in."""
    return is_local_hy2(node) or is_local_vless(node) or bool(node.per_user_enabled)


def _db_utc(value: datetime | None) -> datetime | None:
    """Normalize SQLite-naive and in-session aware UTC timestamps alike."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def legacy_hysteria_allowed(auth: str) -> bool:
    values = adapter_marker()
    until = values.get("HY2_LEGACY_UNTIL", "")
    digest = values.get("HY2_LEGACY_SHA256", "")
    if not until or not digest:
        return False
    try:
        allowed_until = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        return False
    return utcnow() < allowed_until and hmac.compare_digest(
        hashlib.sha256(auth.encode("utf-8")).hexdigest(), digest
    )


def authenticate_hysteria(db, auth: str) -> str | None:
    """Return the stats ID for a Hysteria auth payload, without logging it."""
    node = db.scalar(
        select(Node).where(
            Node.adapter_kind == "local_hy2", Node.protocol == "hysteria2"
        )
    )
    if node is None or not node.enabled or is_expired(node.expires_at):
        return None
    if legacy_hysteria_allowed(auth):
        return "legacy-shared"
    if ":" not in auth:
        return None
    username, password = auth.split(":", 1)
    node_id = node.id
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == "hysteria2",
            UserNodeCredential.revoked_at.is_(None),
            UserNodeCredential.status.in_(("active", "grace")),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    ).all()
    # SQLite returns DateTime columns without tzinfo; compare both sides in
    # naive UTC while keeping utcnow() itself timezone-aware for API output.
    now = utcnow().replace(tzinfo=None)
    for row, friend in rows:
        if not credential_scope_is_allowed(row, friend):
            continue
        if is_expired(friend.expires_at):
            continue
        if flow_limit_reached(db, friend):
            continue
        grace_until = _db_utc(row.grace_until)
        if row.status == "grace" and (not grace_until or grace_until <= now):
            continue
        if row.status not in {"active", "grace"}:
            continue
        values = credential_values(row)
        if values.get("username") == username and hmac.compare_digest(
            values.get("password", ""), password
        ):
            return credential_stats_id(row)
    return None


def capability(node: Node, db=None) -> dict:
    info = adapter_info(node)
    if not info:
        return {
            "supported": False,
            "ready": False,
            "source": "shared",
            "label": "暂不支持按用户计量",
        }
    ready = adapter_ready(node, db)
    agent = (
        db.scalar(select(NodeAgent).where(NodeAgent.node_id == node.id))
        if is_remote_agent(node) and db is not None
        else None
    )
    if is_remote_agent(node):
        label = (
            "Agent 在线，等待应用配置"
            if ready and agent and agent.status == "observe"
            else (info["label"] if ready else "等待节点 Agent 上报")
        )
    else:
        label = info["label"]
    return {
        "supported": True,
        "adapter_kind": node.adapter_kind,
        "ready": ready,
        "agent_status": agent.status if agent else None,
        "source": info["source"],
        "label": label,
    }


def _apply_vless_sync(payload: dict) -> dict:
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    socket_path = Path(VLESS_SYNC_SOCKET)
    if os.geteuid() == 0 and not socket_path.exists():
        result = subprocess.run(
            [
                "/usr/bin/flock",
                "--exclusive",
                "--timeout",
                "45",
                "/var/lib/sub-app-vless-sync/sync.lock",
                "/usr/bin/python3",
                str(VLESS_SYNC_HELPER),
            ],
            input=body,
            capture_output=True,
            timeout=45,
            check=False,
        )
        response = result.stdout
        if result.returncode:
            raise RuntimeError("VLESS root helper rejected the update")
    else:
        chunks = []
        received = 0
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(45)
            connection.connect(str(socket_path))
            connection.sendall(body)
            connection.shutdown(socket.SHUT_WR)
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                received += len(chunk)
                if received > 65536:
                    raise RuntimeError("VLESS root helper response is too large")
                chunks.append(chunk)
        response = b"".join(chunks)
    try:
        result = json.loads(response.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("VLESS root helper returned an invalid response") from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("VLESS root helper failed to apply the update")
    return result


def _live_vless_rows(db, node_id: int, extra: UserNodeCredential | None = None):
    node = db.get(Node, node_id)
    if (
        node is None
        or node.protocol != "vless"
        or not node.enabled
        or is_expired(node.expires_at)
    ):
        return []
    queried_rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == "vless",
            UserNodeCredential.revoked_at.is_(None),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
        .order_by(UserNodeCredential.friend_id, UserNodeCredential.version)
    ).all()
    rows = [
        row for row, friend in queried_rows if credential_scope_is_allowed(row, friend)
    ]
    now = utcnow().replace(tzinfo=None)
    result = [
        row
        for row in rows
        if row.status == "active"
        and not is_expired(row.friend.expires_at)
        and not flow_limit_reached(db, row.friend)
    ]
    for row in rows:
        grace_until = _db_utc(row.grace_until)
        if (
            row.status == "grace"
            and grace_until
            and grace_until > now
            and not is_expired(row.friend.expires_at)
            and not flow_limit_reached(db, row.friend)
        ):
            result.append(row)
    if (
        extra is not None
        and extra.node_id == node_id
        and extra.protocol == "vless"
        and extra not in result
        and extra.revoked_at is None
        and extra.friend.enabled
        and extra.friend.per_user_credentials
        and credential_scope_is_allowed(extra)
        and not is_expired(extra.friend.expires_at)
        and not flow_limit_reached(db, extra.friend)
    ):
        result.append(extra)
    return result


def sync_vless_config(
    db, extra: UserNodeCredential | None = None, node: Node | None = None
) -> None:
    """Ask the fixed root helper to reconcile VLESS users safely."""

    node = node or db.scalar(
        select(Node).where(Node.adapter_kind == "local_vless", Node.protocol == "vless")
    )
    if node is None or not is_local_vless(node):
        raise RuntimeError("未配置本机 VLESS 适配器节点")
    if not adapter_ready(node, db):
        raise RuntimeError("VLESS V2Ray API 适配器未就绪")
    parsed = parse_uri(node.uri)
    if not parsed or parsed.get("scheme") != "vless":
        raise RuntimeError("本机 VLESS 节点链接无效")
    flow = (parsed.get("params") or {}).get("flow", "")
    if flow == "xtls-r-vision":
        raise RuntimeError("VLESS flow xtls-r-vision 已不支持，请更新节点链接")
    users = []
    for row in _live_vless_rows(db, node.id, extra=extra):
        values = credential_values(row)
        user = {"name": credential_stats_id(row), "uuid": values["uuid"]}
        if flow:
            user["flow"] = flow
        users.append(user)
    _apply_vless_sync(
        {
            "enabled": bool(node.enabled and not is_expired(node.expires_at)),
            "users": users,
            "flow": flow,
            "deny_all_uuid": deny_all_uuid(node.id),
        }
    )


def activate_credential(db, row: UserNodeCredential) -> UserNodeCredential:
    node = db.get(Node, row.node_id)
    if node is None:
        row.status = "error"
        row.last_error = "凭据关联的节点不存在"
        row.last_synced_at = None
        return row
    if row.protocol != node.protocol:
        row.status = "error"
        row.last_error = "凭据协议与节点不一致，拒绝同步"
        row.last_synced_at = None
        return row
    if is_remote_agent(node):
        row.status = "pending"
        row.last_error = "等待节点 Agent 应用期望配置"
        row.last_synced_at = None
        return row
    if not adapter_ready(node, db):
        row.status = "error"
        row.last_error = "节点适配器未就绪"
        row.last_synced_at = None
        return row
    if is_local_vless(node):
        row.status = "active"
        row.last_error = ""
        db.flush()
        try:
            sync_vless_config(db, extra=row, node=node)
        except Exception as exc:
            row.status = "error"
            row.last_error = str(exc)[:1000]
            return row
    else:
        row.status = "active"
        row.last_error = ""
    row.last_synced_at = utcnow()
    return row
