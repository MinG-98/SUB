"""Authenticated control-plane endpoints for per-node agents.

Agents receive only the desired credentials for their own node.  Tokens are
stored as hashes in SQLite; request access logs are disabled on the service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, HTTPException, Request, Response
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from app.account_policy import is_expired
from app.converter import parse_uri
from app.credentials import credential_stats_id, credential_values
from app.models import (
    FlowRecord,
    Friend,
    Node,
    NodeAgent,
    UserNodeCredential,
    utc_iso,
    utcnow,
)
from app.proxy_adapters import (
    adapter_info,
    is_remote_agent,
)
from app.quota import credential_kick_stats_ids, flow_limit_reached

ACTIVE_CREDENTIAL_STATUSES = ("active", "grace")
APPLICABLE_CREDENTIAL_STATUSES = ("pending", "error", "active")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def agent_public_dict(agent: NodeAgent | None) -> dict | None:
    if agent is None:
        return None
    try:
        capabilities = json.loads(agent.capabilities or "{}")
    except (TypeError, ValueError):
        capabilities = {}
    return {
        "id": agent.id,
        "node_id": agent.node_id,
        "status": agent.status,
        "agent_version": agent.agent_version,
        "capabilities": capabilities,
        "desired_generation": agent.desired_generation,
        "applied_generation": agent.applied_generation,
        "last_seen": utc_iso(agent.last_seen),
        "last_error": agent.last_error or "",
        "updated_at": utc_iso(agent.updated_at),
        "rotation_pending": bool(agent.pending_token_hash),
        "pending_last_seen": utc_iso(agent.pending_token_last_seen),
    }


def agent_health_summary(db) -> dict:
    now = utcnow().replace(tzinfo=None)
    rows = db.scalars(select(NodeAgent)).all()
    online = 0
    errors = 0
    for row in rows:
        last_seen = row.last_seen
        if last_seen and last_seen.tzinfo is not None:
            last_seen = last_seen.astimezone(timezone.utc).replace(tzinfo=None)
        if last_seen:
            age = (now - last_seen).total_seconds()
            if 0 <= age <= 180:
                online += 1
        if row.status == "error":
            errors += 1
    return {
        "configured": bool(rows),
        "total": len(rows),
        "online": online,
        "errors": errors,
    }


def _authorization_token(request: Request) -> str:
    direct = request.headers.get("x-sub-app-agent-token", "").strip()
    if direct:
        return direct
    value = request.headers.get("authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def _require_agent(request: Request, db, node_id: int) -> tuple[NodeAgent, bool]:
    agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
    supplied = _authorization_token(request)
    supplied_hash = token_hash(supplied) if supplied else ""
    if agent and supplied_hash and hmac.compare_digest(supplied_hash, agent.token_hash):
        return agent, False
    if agent and agent.pending_token_hash and supplied_hash:
        expires_at = (
            _utc_naive(agent.pending_token_expires_at)
            if agent.pending_token_expires_at
            else None
        )
        if (
            expires_at
            and expires_at > _utc_naive(utcnow())
            and hmac.compare_digest(supplied_hash, agent.pending_token_hash)
        ):
            return agent, True
        if expires_at and expires_at <= _utc_naive(utcnow()):
            agent.pending_token_hash = None
            agent.pending_token_expires_at = None
            agent.pending_token_last_seen = None
    if not agent or not supplied:
        raise HTTPException(status_code=401, detail="节点 Agent 未授权")
    raise HTTPException(status_code=401, detail="节点 Agent 未授权")


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _safe_int(value, default=0) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(value, 9_223_372_036_854_775_807))


def _desired_users(db, node_id: int) -> list[dict]:
    node = db.get(Node, node_id)
    if node is None or is_expired(node.expires_at):
        return []
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.revoked_at.is_(None),
            UserNodeCredential.status.in_(
                (*ACTIVE_CREDENTIAL_STATUSES, "pending", "error")
            ),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
        .order_by(UserNodeCredential.friend_id, UserNodeCredential.version)
    ).all()
    result = []
    for row, friend in rows:
        if is_expired(friend.expires_at) or flow_limit_reached(db, friend):
            continue
        if row.status == "grace" and (
            row.grace_until is None or is_expired(row.grace_until)
        ):
            continue
        values = credential_values(row)
        item = {
            "credential_id": row.id,
            "friend_id": row.friend_id,
            "uid": friend.uid,
            "protocol": row.protocol,
            "version": row.version,
            "status": row.status,
            "stats_id": credential_stats_id(row),
            "grace_until": utc_iso(row.grace_until),
        }
        item.update(values)
        result.append(item)
    return result


def _shared_agent_users(node: Node) -> list[dict]:
    """Render the node's configured shared URI as one Agent-managed user."""
    parsed = parse_uri(node.uri)
    if not parsed or parsed.get("scheme") != node.protocol:
        return []
    common = {
        "credential_id": 0,
        "friend_id": 0,
        "uid": "shared",
        "protocol": node.protocol,
        "version": 0,
        "status": "active",
        "stats_id": "legacy-shared",
    }
    if node.protocol == "vless" and parsed.get("user"):
        user = {**common, "uuid": parsed["user"]}
        flow = (parsed.get("params") or {}).get("flow")
        if flow and flow != "xtls-r-vision":
            user["flow"] = flow
        return [user]
    if node.protocol == "hysteria2":
        username = parsed.get("user", "")
        password = parsed.get("password", "")
        auth = (
            f"{username}:{password}" if username and password else username or password
        )
        if auth:
            return [
                {**common, "username": username, "password": password, "auth": auth}
            ]
    return []


def _desired_payload(
    db, node: Node, agent: NodeAgent, force_observe: bool = False
) -> dict:
    # Local adapters already have their own reconciler. Remote Agents expose
    # three explicit states: per-user credentials, restored shared credentials,
    # and disabled (deny-all). Older Agents do not advertise mode support, so
    # shared-mode config changes wait until they are upgraded.
    remote = is_remote_agent(node)
    try:
        capabilities = json.loads(agent.capabilities or "{}")
    except (TypeError, ValueError):
        capabilities = {}
    supports_modes = isinstance(capabilities, dict) and bool(
        capabilities.get("managed_auth_modes")
    )
    node_available = bool(node.enabled) and not is_expired(node.expires_at)
    mode = (
        "disabled"
        if not node_available
        else "per_user" if node.per_user_enabled else "shared"
    )
    apply_enabled = (
        remote and not force_observe and (mode != "shared" or supports_modes)
    )
    if force_observe:
        users = []
    elif mode == "per_user":
        users = _desired_users(db, node.id)
    elif mode == "shared":
        users = _shared_agent_users(node)
    else:
        users = []
    unsigned = {
        "node_id": node.id,
        "protocol": node.protocol,
        "enabled": node_available,
        "mode": mode,
        "apply": apply_enabled,
        "users": users,
    }
    encoded = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    generation = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if not force_observe:
        agent.desired_generation = generation
        agent.updated_at = utcnow()
    return {
        **unsigned,
        "generation": generation,
        "agent_id": agent.id,
        "poll_after_seconds": 30,
        "legacy_window_hours": 24,
    }


def _record_traffic(db, node_id: int, payload) -> tuple[int, list[str]]:
    if not isinstance(payload, list):
        return 0, []
    rows = db.scalars(
        select(UserNodeCredential)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.revoked_at.is_(None),
            UserNodeCredential.status.in_(ACTIVE_CREDENTIAL_STATUSES),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    ).all()
    by_key = {credential_stats_id(row): row for row in rows}
    node = db.get(Node, node_id)
    info = adapter_info(node) if node else None
    expected_source = info.get("source") if info else None
    written = 0
    acknowledged = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        key = str(item.get("credential_key", ""))[:128]
        row = by_key.get(key)
        sample_key = str(item.get("sample_key", ""))[:128]
        if not row or not sample_key:
            # This sample is permanently un-attributable in the current
            # database state. Tell the durable Agent outbox it was processed
            # and intentionally discarded instead of retrying it forever.
            if sample_key:
                acknowledged.add(sample_key)
            continue
        source = str(item.get("source") or expected_source or row.protocol)[:32]
        if expected_source and source != expected_source:
            acknowledged.add(sample_key)
            continue
        try:
            bucket = _utc_naive(datetime.fromisoformat(str(item.get("bucket"))))
        except (TypeError, ValueError):
            bucket = _utc_naive(utcnow())
        statement = (
            insert(FlowRecord)
            .prefix_with("OR IGNORE")
            .values(
                node_id=node_id,
                friend_id=row.friend_id,
                device_id=None,
                bytes_in=_safe_int(item.get("bytes_in")),
                bytes_out=_safe_int(item.get("bytes_out")),
                bucket=bucket,
                source=source,
                sample_key=sample_key,
                created_at=utcnow(),
            )
        )
        result = db.execute(statement)
        inserted = int(result.rowcount or 0)
        written += inserted
        if inserted:
            acknowledged.add(sample_key)
        else:
            # INSERT OR IGNORE is the expected retry path after a lost HTTP
            # response. Acknowledge only when the existing idempotency record
            # belongs to this same node and user; a conflicting key is not
            # silently treated as accepted.
            existing = db.scalar(
                select(FlowRecord).where(
                    FlowRecord.source == source,
                    FlowRecord.sample_key == sample_key,
                )
            )
            if (
                existing is not None
                and existing.node_id == node_id
                and existing.friend_id == row.friend_id
            ):
                acknowledged.add(sample_key)
    return written, sorted(acknowledged)


def _mark_applied(
    db,
    node_id: int,
    generation: str,
    expected: str,
    eligible_credential_ids: set[int] | None = None,
) -> int:
    if not generation or not hmac.compare_digest(generation, expected):
        return 0
    if eligible_credential_ids is not None and not eligible_credential_ids:
        return 0
    query = (
        select(UserNodeCredential)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.revoked_at.is_(None),
            UserNodeCredential.status.in_(APPLICABLE_CREDENTIAL_STATUSES),
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    )
    if eligible_credential_ids is not None:
        query = query.where(UserNodeCredential.id.in_(eligible_credential_ids))
    rows = db.scalars(query).all()
    changed = 0
    for row in rows:
        if row.status != "grace":
            row.status = "active"
        row.last_synced_at = utcnow()
        row.last_error = ""
        changed += 1
    return changed


def register_agent_routes(app, session_factory, get_db, require_admin):
    @app.get("/api/agent/v1/desired/{node_id}")
    def agent_desired(
        node_id: int,
        request: Request,
        response: Response,
        db=Depends(get_db),
    ):
        agent, pending_token = _require_agent(request, db, node_id)
        node = db.get(Node, node_id)
        if not node or not is_remote_agent(node):
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
        result = _desired_payload(db, node, agent, force_observe=pending_token)
        db.commit()
        return result

    @app.post("/api/agent/v1/heartbeat/{node_id}")
    def agent_heartbeat(
        node_id: int,
        request: Request,
        payload: dict = Body(...),
        db=Depends(get_db),
    ):
        agent, pending_token = _require_agent(request, db, node_id)
        node = db.get(Node, node_id)
        if not node or not is_remote_agent(node):
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")

        status = str(payload.get("status", "observe"))[:16]
        if status not in {"observe", "ready", "error"}:
            status = "error"
        capabilities = payload.get("capabilities", {})
        if not isinstance(capabilities, dict):
            capabilities = {}
        if pending_token:
            if status != "observe" or payload.get("error"):
                agent.pending_token_last_seen = None
                db.commit()
                raise HTTPException(
                    status_code=409,
                    detail="新 token 的观察心跳未成功，不能确认轮换",
                )
            agent.pending_token_last_seen = utcnow()
            db.commit()
            return {
                "ok": True,
                "status": "observe",
                "pending_rotation": True,
                "desired_generation": agent.desired_generation,
                "activated_credentials": 0,
                "traffic_records": 0,
            }
        agent.agent_version = str(payload.get("agent_version", ""))[:64]
        agent.capabilities = json.dumps(
            capabilities, ensure_ascii=True, separators=(",", ":")
        )[:8000]
        agent.updated_at = utcnow()
        agent.last_seen = utcnow()
        agent.applied_generation = str(payload.get("applied_generation", ""))[:128]
        error = str(payload.get("error", ""))[:1000]
        desired = _desired_payload(db, node, agent)
        agent.last_error = error
        agent.status = status
        activated = 0
        if status == "ready" and desired["apply"]:
            activated = _mark_applied(
                db,
                node_id,
                agent.applied_generation,
                desired["generation"],
                eligible_credential_ids={
                    item["credential_id"] for item in desired["users"]
                },
            )
            if not hmac.compare_digest(agent.applied_generation, desired["generation"]):
                agent.status = "error"
                agent.last_error = "节点 Agent 应用版本未匹配中心期望版本"
        recorded, traffic_ack = _record_traffic(db, node_id, payload.get("traffic"))
        kick_stats_ids = []
        if node.protocol == "hysteria2" and capabilities.get("singbox_engine") is False:
            kick_stats_ids = credential_kick_stats_ids(
                db, node_id, protocol="hysteria2"
            )
        db.commit()
        return {
            "ok": True,
            "status": agent.status,
            "desired_generation": desired["generation"],
            "activated_credentials": activated,
            "traffic_records": recorded,
            "traffic_ack": traffic_ack,
            "kick_stats_ids": kick_stats_ids,
            # Keep the old field while Agents are upgraded; the list now also
            # includes revoked, disabled, expired, and otherwise ineligible IDs.
            "quota_kick_stats_ids": kick_stats_ids,
        }

    @app.get("/api/admin/agents")
    def admin_agents(db=Depends(get_db), _=Depends(require_admin)):
        agents = db.scalars(select(NodeAgent).order_by(NodeAgent.node_id)).all()
        return [agent_public_dict(agent) for agent in agents]

    @app.post("/api/admin/agents")
    def register_agent(
        response: Response,
        payload: dict = Body(...),
        db=Depends(get_db),
        _=Depends(require_admin),
    ):
        node_id = payload.get("node_id")
        if isinstance(node_id, bool) or not isinstance(node_id, int) or node_id <= 0:
            raise HTTPException(status_code=422, detail="node_id 必须是正整数")
        node = db.get(Node, node_id)
        if not node or not is_remote_agent(node):
            raise HTTPException(
                status_code=409, detail="请先将节点适配器设为 remote_agent"
            )
        if node.per_user_enabled:
            raise HTTPException(
                status_code=409,
                detail="注册前请先关闭用户级独立凭据，Agent 首次接入保持观察模式",
            )
        if db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id)):
            raise HTTPException(status_code=409, detail="Agent 已注册，请使用轮换接口")

        token = secrets.token_urlsafe(32)
        agent = NodeAgent(
            node_id=node_id, token_hash=token_hash(token), status="pending"
        )
        db.add(agent)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="Agent 已被并发注册") from None
        if response is not None:
            response.headers["Cache-Control"] = "private, no-store"
            response.headers["Pragma"] = "no-cache"
        return {
            "agent": agent_public_dict(agent),
            "token": token,
            "config_template": {
                "endpoint": "https://<SUB_APP_PUBLIC_BASE>",
                "poll_seconds": 30,
                "nodes": [{"node_id": node.id, "protocol": node.protocol}],
            },
            "note": "token 仅返回一次；请填入节点配置。service/引擎/配置路径必须按该主机实际部署补齐。",
        }

    @app.post("/api/admin/agents/{node_id}/rotate")
    def rotate_agent_token(
        node_id: int,
        response: Response,
        db=Depends(get_db),
        _=Depends(require_admin),
    ):
        node = db.get(Node, node_id)
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
        if not node or not is_remote_agent(node) or not agent:
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")
        token = secrets.token_urlsafe(32)
        agent.pending_token_hash = token_hash(token)
        agent.pending_token_expires_at = utcnow() + timedelta(hours=24)
        agent.pending_token_last_seen = None
        agent.updated_at = utcnow()
        db.commit()
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
        return {
            "agent": agent_public_dict(agent),
            "token": token,
            "expires_at": utc_iso(agent.pending_token_expires_at),
            "note": "旧 token 在确认轮换前继续有效；新 token 仅能进行观察。",
        }

    @app.post("/api/admin/agents/{node_id}/rotate/confirm")
    def confirm_agent_token_rotation(
        node_id: int, db=Depends(get_db), _=Depends(require_admin)
    ):
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
        if not agent or not agent.pending_token_hash:
            raise HTTPException(status_code=409, detail="没有待确认的 Agent token 轮换")
        expires_at = (
            _utc_naive(agent.pending_token_expires_at)
            if agent.pending_token_expires_at
            else None
        )
        if not expires_at or expires_at <= _utc_naive(utcnow()):
            agent.pending_token_hash = None
            agent.pending_token_expires_at = None
            agent.pending_token_last_seen = None
            db.commit()
            raise HTTPException(
                status_code=409, detail="待验证 token 已过期，请重新轮换"
            )
        last_seen = (
            _utc_naive(agent.pending_token_last_seen)
            if agent.pending_token_last_seen
            else None
        )
        if not last_seen or (_utc_naive(utcnow()) - last_seen).total_seconds() > 180:
            raise HTTPException(
                status_code=409, detail="新 token 尚未在最近 180 秒内成功上报"
            )
        agent.token_hash = agent.pending_token_hash
        agent.pending_token_hash = None
        agent.pending_token_expires_at = None
        agent.pending_token_last_seen = None
        agent.status = "pending"
        agent.last_seen = None
        agent.applied_generation = ""
        agent.last_error = ""
        agent.updated_at = utcnow()
        db.commit()
        return agent_public_dict(agent)

    @app.delete("/api/admin/agents/{node_id}/rotate")
    def cancel_agent_token_rotation(
        node_id: int, db=Depends(get_db), _=Depends(require_admin)
    ):
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
        if not agent:
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")
        agent.pending_token_hash = None
        agent.pending_token_expires_at = None
        agent.pending_token_last_seen = None
        agent.updated_at = utcnow()
        db.commit()
        return agent_public_dict(agent)

    @app.delete("/api/admin/agents/{node_id}")
    def revoke_agent(node_id: int, db=Depends(get_db), _=Depends(require_admin)):
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
        if not agent:
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")
        db.delete(agent)
        db.commit()
        return {"ok": True}

    @app.get("/api/admin/agents/{node_id}")
    def admin_agent(node_id: int, db=Depends(get_db), _=Depends(require_admin)):
        agent = db.scalar(select(NodeAgent).where(NodeAgent.node_id == node_id))
        if not agent:
            raise HTTPException(status_code=404, detail="节点 Agent 不存在")
        return agent_public_dict(agent)
