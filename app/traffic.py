"""Nezha node metrics collection and traffic normalization helpers."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import delete, select

from app.models import (
    CollectorRun,
    FetchLog,
    FlowRecord,
    Node,
    NodeMetricSample,
)
from app.node_policy import is_real_node

log = logging.getLogger(__name__)

NEZHA_ENV_FILE = Path(os.environ.get("NEZHA_ENV_FILE", "/etc/sub-app/nezha.env"))
DEFAULT_NEZHA_BASE_URL = "http://127.0.0.1:18008"
RETENTION_DAYS = 30
FETCH_LOG_RETENTION_DAYS = int(os.environ.get("SUB_APP_FETCH_LOG_RETENTION_DAYS", "90"))
POLL_SECONDS = 300


class CollectorError(RuntimeError):
    pass


def _read_env_file(path: Path) -> dict[str, str]:
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


def collector_config() -> tuple[str, str]:
    file_values = _read_env_file(NEZHA_ENV_FILE)
    base_url = (
        os.environ.get("NEZHA_BASE_URL")
        or file_values.get("NEZHA_BASE_URL")
        or DEFAULT_NEZHA_BASE_URL
    ).rstrip("/")
    token = os.environ.get("NEZHA_API_TOKEN") or file_values.get("NEZHA_API_TOKEN", "")
    return base_url, token.strip()


def is_collector_configured() -> bool:
    _base_url, token = collector_config()
    return bool(token)


def _as_int(value, default=0) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _as_datetime(value):
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        stamp = float(value)
        if stamp > 10_000_000_000:
            stamp /= 1000
        return datetime.fromtimestamp(stamp, timezone.utc)
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _online(value) -> bool:
    if isinstance(value, str):
        return value.lower() in {"1", "true", "online", "active", "up"}
    return bool(value)


def normalize_server(item: dict) -> dict:
    status = item.get("status")
    state = item.get("state")
    state_metrics = state if isinstance(state, dict) else {}
    last_active = _as_datetime(item.get("last_active", item.get("last_active_at")))
    online_value = item.get("online", item.get("is_online"))
    if online_value is None and isinstance(status, dict):
        online_value = status.get("online", status.get("active"))
    if online_value is None and isinstance(status, str):
        online_value = status
    if online_value is None and isinstance(state, dict):
        # Nezha V2 puts the latest agent metrics in `state`; an empty state
        # means the agent has no current heartbeat in the inventory response.
        online_value = bool(state)
    if online_value is None and last_active is not None:
        online_value = (
            datetime.now(timezone.utc) - last_active
        ).total_seconds() <= POLL_SECONDS * 2

    def metric_value(*keys):
        for key in keys:
            if item.get(key) is not None:
                return item[key]
            if state_metrics.get(key) is not None:
                return state_metrics[key]
        return None

    return {
        "id": _as_int(item.get("id", item.get("server_id"))),
        "name": str(item.get("name", "")),
        "online": _online(online_value),
        "last_active": last_active,
        "net_in_transfer": _as_int(metric_value("net_in_transfer", "transfer_in")),
        "net_out_transfer": _as_int(metric_value("net_out_transfer", "transfer_out")),
        "net_in_speed": _as_int(metric_value("net_in_speed", "speed_in")),
        "net_out_speed": _as_int(metric_value("net_out_speed", "speed_out")),
    }


def fetch_servers(base_url: str, token: str) -> list[dict]:
    if not token:
        raise CollectorError("NEZHA_API_TOKEN is not configured")
    try:
        response = httpx.get(
            f"{base_url}/api/v1/server",
            headers={"Authorization": f"Bearer {token}"},
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CollectorError(f"Nezha request failed: {type(exc).__name__}") from exc

    if payload.get("success") is False:
        raise CollectorError(str(payload.get("error", "Nezha API error")))
    data = payload.get("data", payload)
    if isinstance(data, dict):
        data = data.get("value", data.get("servers", []))
    if not isinstance(data, list):
        raise CollectorError("Nezha API returned an unexpected server list")
    return [normalize_server(item) for item in data if isinstance(item, dict)]


def _naive_utc(value):
    if value is None:
        return None
    if value.tzinfo:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _bucket(now):
    now = _naive_utc(now)
    minute = now.minute - (now.minute % 5)
    return now.replace(minute=minute, second=0, microsecond=0)


def _previous_sample(db, node_id, bucket):
    return db.scalar(
        select(NodeMetricSample)
        .where(
            NodeMetricSample.node_id == node_id,
            NodeMetricSample.bucket < bucket,
        )
        .order_by(NodeMetricSample.bucket.desc())
        .limit(1)
    )


def _non_negative_delta(current, previous):
    if previous is None or current < previous:
        return 0
    return current - previous


def run_collector(
    db,
    now=None,
    retention_days=RETENTION_DAYS,
    fetch_log_retention_days=FETCH_LOG_RETENTION_DAYS,
):
    started_at = _naive_utc(now or datetime.now(timezone.utc))
    bucket = _bucket(started_at)
    started = CollectorRun(started_at=started_at, source="nezha", status="running")
    db.add(started)
    db.commit()
    base_url, token = collector_config()

    try:
        if fetch_log_retention_days > 0:
            fetch_log_cutoff = started_at - timedelta(days=fetch_log_retention_days)
            db.execute(delete(FetchLog).where(FetchLog.created_at < fetch_log_cutoff))
            # Retention is independent from Nezha availability. Commit before
            # the remote fetch so its failure cannot roll pruning back.
            db.commit()
        servers = fetch_servers(base_url, token)
        by_id = {item["id"]: item for item in servers if item["id"]}
        nodes = [
            node
            for node in db.scalars(
                select(Node).where(Node.nezha_server_id.is_not(None))
            ).all()
            if is_real_node(node)
        ]
        collected_at = _naive_utc(datetime.now(timezone.utc))
        started.nodes_total = len(nodes)
        written = 0
        missing = []

        for node in nodes:
            server = by_id.get(node.nezha_server_id)
            if server is None:
                missing.append(str(node.nezha_server_id))
                continue
            previous = _previous_sample(db, node.id, bucket)
            current_in = server["net_in_transfer"]
            current_out = server["net_out_transfer"]
            delta_in = _non_negative_delta(
                current_in, previous.net_in_transfer if previous else None
            )
            delta_out = _non_negative_delta(
                current_out, previous.net_out_transfer if previous else None
            )
            sample = db.scalar(
                select(NodeMetricSample).where(
                    NodeMetricSample.node_id == node.id,
                    NodeMetricSample.bucket == bucket,
                )
            )
            if sample is None:
                sample = NodeMetricSample(node_id=node.id, bucket=bucket)
                db.add(sample)
            sample.nezha_server_id = node.nezha_server_id
            sample.collected_at = collected_at
            sample.online = server["online"]
            sample.last_active = _naive_utc(server["last_active"])
            sample.net_in_transfer = current_in
            sample.net_out_transfer = current_out
            sample.net_in_speed = server["net_in_speed"]
            sample.net_out_speed = server["net_out_speed"]
            sample.delta_in = delta_in
            sample.delta_out = delta_out

            key = f"node:{node.id}:{bucket.isoformat()}"
            flow = db.scalar(
                select(FlowRecord).where(
                    FlowRecord.source == "nezha",
                    FlowRecord.sample_key == key,
                )
            )
            if flow is None:
                flow = FlowRecord(
                    node_id=node.id,
                    bucket=bucket,
                    source="nezha",
                    sample_key=key,
                )
                db.add(flow)
            flow.bytes_in = delta_in
            flow.bytes_out = delta_out
            written += 1

        cutoff = started_at - timedelta(days=retention_days)
        db.execute(delete(NodeMetricSample).where(NodeMetricSample.bucket < cutoff))
        db.execute(
            delete(FlowRecord).where(
                FlowRecord.source == "nezha",
                FlowRecord.bucket < cutoff,
            )
        )
        db.execute(delete(CollectorRun).where(CollectorRun.started_at < cutoff))
        started.samples_written = written
        started.finished_at = collected_at
        started.status = "partial" if missing else "success"
        started.error = (
            f"Unmapped Nezha server IDs: {', '.join(sorted(set(missing)))}"
            if missing
            else ""
        )
        db.commit()
        return {
            "status": started.status,
            "nodes_total": len(nodes),
            "samples_written": written,
            "servers_seen": len(servers),
            "missing_server_ids": sorted(set(missing)),
        }
    except Exception as exc:
        db.rollback()
        failed = db.get(CollectorRun, started.id)
        failed.finished_at = _naive_utc(datetime.now(timezone.utc))
        failed.status = "unconfigured" if "not configured" in str(exc) else "error"
        failed.error = str(exc)[:1000]
        db.commit()
        raise
