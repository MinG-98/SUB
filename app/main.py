import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import delete, func, or_, select

from app.account_policy import is_expired as _is_expired
from app.converter import parse_uri, render
from app.credentials import (
    credential_public_dict,
    ensure_credential,
    per_user_feature_enabled,
)
from app.latency import read_status, start_probe
from app.models import (
    AdminAuditLog,
    AdminAuthState,
    AdminLoginThrottle,
    AdminSession,
    Allocation,
    Announcement,
    AnnouncementAllocation,
    CollectorRun,
    Device,
    FetchLog,
    FlowRecord,
    Friend,
    Node,
    NodeAgent,
    NodeMetricSample,
    UserNodeCredential,
    make_session_factory,
    new_token,
    utc_iso,
    utcnow,
)
from app.node_policy import is_real_node
from app.proxy_adapters import (
    activate_credential,
    adapter_info,
    adapter_marker,
    adapter_ready,
    capability,
    is_local_vless,
    node_per_user_enabled,
    supported_node_ids,
    sync_vless_config,
)
from app.quota import flow_limit_reached, friend_usage
from app.subscription_diagnostics import TARGETS, subscription_diagnostics
from app.subscription_plan import announcement_uri, build_subscription_plan
from app.traffic import (
    CollectorError,
    collector_config,
    fetch_servers,
    is_collector_configured,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("SUB_APP_DB", str(BASE_DIR / "data.db"))
ADMIN_PASSWORD = os.environ.get("SUB_APP_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SUB_APP_SECRET", "")
PUBLIC_BASE = os.environ.get("SUB_APP_PUBLIC_BASE", "").rstrip("/")
ADMIN_USERNAME = os.environ.get("SUB_APP_ADMIN_USERNAME", "admin").strip() or "admin"
SESSION_MAX_AGE = int(os.environ.get("SUB_APP_SESSION_MAX_AGE", 8 * 3600))
ADMIN_LOGIN_MAX_FAILURES = int(os.environ.get("SUB_APP_LOGIN_MAX_FAILURES", 8))
ADMIN_LOGIN_WINDOW_SECONDS = int(
    os.environ.get("SUB_APP_LOGIN_WINDOW_SECONDS", 15 * 60)
)
ADMIN_LOGIN_LOCKOUT_SECONDS = int(
    os.environ.get("SUB_APP_LOGIN_LOCKOUT_SECONDS", 15 * 60)
)
COOKIE_NAME = "sub_app_session"
ADMIN_CREDENTIAL_FINGERPRINT = hmac.new(
    SECRET_KEY.encode(),
    b"sub-app-admin-credentials:"
    + ADMIN_USERNAME.encode()
    + b"\0"
    + ADMIN_PASSWORD.encode(),
    hashlib.sha256,
).hexdigest()

if not ADMIN_PASSWORD:
    raise RuntimeError("SUB_APP_ADMIN_PASSWORD is required")
if not SECRET_KEY:
    raise RuntimeError("SUB_APP_SECRET is required")
if SESSION_MAX_AGE <= 0:
    raise RuntimeError("SUB_APP_SESSION_MAX_AGE must be positive")
if (
    min(
        ADMIN_LOGIN_MAX_FAILURES,
        ADMIN_LOGIN_WINDOW_SECONDS,
        ADMIN_LOGIN_LOCKOUT_SECONDS,
    )
    <= 0
):
    raise RuntimeError("Admin login throttle settings must be positive")

Session = make_session_factory(DB_PATH)
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="sub-app-session")
audit_logger = logging.getLogger("sub_app.admin_audit")


def _session_version_for_config(fingerprint, session_factory=None, secret_key=None):
    """Return a persistent auth epoch that changes whenever credentials change."""
    factory = session_factory or Session
    key = SECRET_KEY if secret_key is None else secret_key
    db = factory()
    try:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        state = db.get(AdminAuthState, 1)
        if state is None:
            state = AdminAuthState(
                id=1,
                config_fingerprint=fingerprint,
                epoch=secrets.token_hex(32),
            )
            db.add(state)
        elif not hmac.compare_digest(state.config_fingerprint, fingerprint):
            state.config_fingerprint = fingerprint
            state.epoch = secrets.token_hex(32)
        epoch = state.epoch
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return hmac.new(
        key.encode(),
        b"sub-app-admin-session-epoch:" + fingerprint.encode() + epoch.encode(),
        hashlib.sha256,
    ).hexdigest()


ADMIN_SESSION_VERSION = _session_version_for_config(ADMIN_CREDENTIAL_FINGERPRINT)

app = FastAPI(title="Sub App", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "; ".join(
            (
                "default-src 'self'",
                "base-uri 'self'",
                "connect-src 'self'",
                "font-src 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
                "img-src 'self' data:",
                "object-src 'none'",
                "script-src 'self'",
                "style-src 'self' 'unsafe-inline'",
            )
        ),
    )
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if forwarded_proto.split(",", 1)[0].strip().lower() == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    if (
        request.url.path.startswith("/api/admin/")
        and request.url.path != "/api/admin/login"
        and request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and response.status_code < 400
    ):
        _record_admin_audit(request, response.status_code)
    return response


def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()


def _admin_login_client_key(request: Request) -> str:
    """Hash the ASGI peer address; never trust client-supplied forwarding headers."""

    peer = request.client.host if request.client else ""
    try:
        peer = ipaddress.ip_address(peer).compressed
    except ValueError:
        peer = peer.strip()[:255] or "unknown"
    return hmac.new(
        SECRET_KEY.encode(),
        b"sub-app-admin-login:" + peer.encode(),
        hashlib.sha256,
    ).hexdigest()


def require_admin(request: Request):
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        payload = serializer.loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        raise HTTPException(status_code=401, detail="登录已失效")
    if (
        not isinstance(payload, dict)
        or payload.get("ok") is not True
        or not hmac.compare_digest(
            str(payload.get("auth_version", "")), ADMIN_SESSION_VERSION
        )
        or not _admin_session_is_active(payload.get("sid"))
    ):
        raise HTTPException(status_code=401, detail="登录已失效")
    return payload


def _admin_session_hash(session_id):
    if not isinstance(session_id, str) or not session_id:
        return None
    return hmac.new(
        SECRET_KEY.encode(),
        b"sub-app-admin-session-id:" + session_id.encode(),
        hashlib.sha256,
    ).hexdigest()


def _admin_session_is_active(session_id):
    session_hash = _admin_session_hash(session_id)
    if not session_hash:
        return False
    db = Session()
    try:
        auth_state = db.get(AdminAuthState, 1)
        if auth_state is None or not hmac.compare_digest(
            auth_state.config_fingerprint, ADMIN_CREDENTIAL_FINGERPRINT
        ):
            return False
        current_version = hmac.new(
            SECRET_KEY.encode(),
            b"sub-app-admin-session-epoch:"
            + auth_state.config_fingerprint.encode()
            + auth_state.epoch.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(current_version, ADMIN_SESSION_VERSION):
            return False
        return (
            db.scalar(
                select(AdminSession.session_hash).where(
                    AdminSession.session_hash == session_hash,
                    AdminSession.revoked_at.is_(None),
                    AdminSession.expires_at > utcnow().replace(tzinfo=None),
                )
            )
            is not None
        )
    except HTTPException:
        raise
    except Exception as exc:
        audit_logger.exception("Could not verify administrator session")
        raise HTTPException(503, "无法验证登录会话，请稍后重试") from exc
    finally:
        db.close()


def _record_admin_audit(request: Request, status_code: int) -> None:
    """Record successful authenticated mutations without storing request bodies."""
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return
    try:
        payload = serializer.loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return
    if (
        not isinstance(payload, dict)
        or payload.get("ok") is not True
        or not hmac.compare_digest(
            str(payload.get("auth_version", "")), ADMIN_SESSION_VERSION
        )
    ):
        return

    actor = hmac.new(
        SECRET_KEY.encode(), b"sub-app-admin-audit:" + raw.encode(), hashlib.sha256
    ).hexdigest()
    db = Session()
    try:
        db.add(
            AdminAuditLog(
                actor_fingerprint=actor,
                method=request.method,
                path=request.url.path[:255],
                status_code=status_code,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        audit_logger.exception("Could not write administrator audit record")
    finally:
        db.close()


def client_ip(request: Request) -> str:
    fwd = request.headers.get("cf-connecting-ip") or request.headers.get(
        "x-forwarded-for", ""
    )
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def fingerprint_of(request: Request, supplied: str | None) -> str:
    if supplied:
        return hashlib.sha256(supplied.encode()).hexdigest()[:32]
    basis = f"{request.headers.get('user-agent', '')}|{client_ip(request)}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


def device_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_legacy_device_value(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{32}", value or ""))


def _public_base(request: Request | None = None) -> str:
    if PUBLIC_BASE:
        return PUBLIC_BASE
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{forwarded.split(',')[0].strip()}://{host}"


def _device_dict(dev: Device, uid: str | None = None) -> dict:
    return {
        "id": dev.id,
        "friend_id": dev.friend_id,
        "friend_uid": uid,
        "access_identifier": dev.fingerprint,
        "fingerprint": dev.fingerprint,
        "identity_source": dev.identity_source or "legacy_ua_ip",
        "device_link_active": bool(
            dev.device_token_hash and dev.device_token_revoked_at is None
        ),
        "label": dev.label,
        "user_agent": dev.user_agent,
        "last_ip": dev.last_ip,
        "fetch_count": dev.fetch_count,
        "blocked": dev.blocked,
        "first_seen": _iso(dev.first_seen),
        "last_seen": _iso(dev.last_seen),
        "device_token_created_at": _iso(dev.device_token_created_at),
        "device_token_revoked_at": _iso(dev.device_token_revoked_at),
    }


def _credential_rows_for_friend(db, friend_id: int):
    return db.scalars(
        select(UserNodeCredential)
        .where(UserNodeCredential.friend_id == friend_id)
        .order_by(UserNodeCredential.node_id, UserNodeCredential.version.desc())
    ).all()


def _revoke_credential(db, row: UserNodeCredential):
    row.status = "revoked"
    row.revoked_at = utcnow()
    row.grace_until = None
    row.last_error = ""


def _reconcile_friend_credentials(db, friend: Friend):
    """Reconcile selected US nodes without affecting shared remote nodes."""
    allocations = db.scalars(
        select(Allocation).where(Allocation.friend_id == friend.id)
    ).all()
    wanted = {
        allocation.node_id
        for allocation in allocations
        if allocation.node is not None
        and is_real_node(allocation.node)
        and not _is_expired(allocation.node.expires_at)
    }
    rows = _credential_rows_for_friend(db, friend.id)
    changed_vless = False
    if (
        not friend.per_user_credentials
        or not friend.enabled
        or _is_expired(friend.expires_at)
    ):
        for row in rows:
            if row.revoked_at is None:
                _revoke_credential(db, row)
                node = db.get(Node, row.node_id)
                changed_vless = changed_vless or bool(node and is_local_vless(node))
        local_vless = db.scalar(
            select(Node).where(
                Node.adapter_kind == "local_vless", Node.protocol == "vless"
            )
        )
        if changed_vless and local_vless and adapter_ready(local_vless, db):
            try:
                sync_vless_config(db)
            except Exception as exc:
                for row in rows:
                    row_node = db.get(Node, row.node_id)
                    if (
                        row_node
                        and is_local_vless(row_node)
                        and row.status == "revoked"
                    ):
                        row.last_error = str(exc)[:1000]
        return rows

    for node_id in wanted:
        node = db.get(Node, node_id)
        if not node or not adapter_info(node) or not node_per_user_enabled(node):
            continue
        row = ensure_credential(db, friend, node)
        if row.status not in {"active", "grace"} or row.revoked_at is not None:
            activate_credential(db, row)
            changed_vless = changed_vless or is_local_vless(node)

    for row in rows:
        if row.node_id not in wanted and row.revoked_at is None:
            _revoke_credential(db, row)
            row_node = db.get(Node, row.node_id)
            changed_vless = changed_vless or bool(row_node and is_local_vless(row_node))

    local_vless = db.scalar(
        select(Node).where(Node.adapter_kind == "local_vless", Node.protocol == "vless")
    )
    if changed_vless and local_vless and adapter_ready(local_vless, db):
        try:
            sync_vless_config(db)
        except Exception as exc:
            for row in _credential_rows_for_friend(db, friend.id):
                row_node = db.get(Node, row.node_id)
                if (
                    row_node
                    and is_local_vless(row_node)
                    and row.status in {"active", "grace"}
                ):
                    row.status = "error"
                    row.last_error = str(exc)[:1000]


# ---------------------------------------------------------------- auth


@app.post("/api/admin/login")
def login(request: Request, response: Response, payload: dict = Body(...)):
    supplied = str(payload.get("password", ""))
    client_key = _admin_login_client_key(request)
    now = utcnow().replace(tzinfo=None)
    db = Session()
    try:
        # Serialize the check-and-update across threads and Uvicorn workers.
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        db.execute(
            delete(AdminLoginThrottle).where(
                AdminLoginThrottle.updated_at < now - timedelta(days=1)
            )
        )
        throttle = db.get(AdminLoginThrottle, client_key)
        if throttle and throttle.blocked_until and throttle.blocked_until > now:
            retry_after = max(
                1, int((throttle.blocked_until - now).total_seconds()) + 1
            )
            db.rollback()
            raise HTTPException(
                status_code=429,
                detail="登录尝试过多，请稍后重试",
                headers={"Retry-After": str(retry_after)},
            )

        if (
            throttle
            and (now - throttle.window_started_at).total_seconds()
            >= ADMIN_LOGIN_WINDOW_SECONDS
        ):
            throttle.failure_count = 0
            throttle.window_started_at = now
            throttle.blocked_until = None

        if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
            if throttle is None:
                throttle = AdminLoginThrottle(
                    client_key=client_key,
                    failure_count=0,
                    window_started_at=now,
                    updated_at=now,
                )
                db.add(throttle)
            throttle.failure_count += 1
            throttle.updated_at = now
            if throttle.failure_count >= ADMIN_LOGIN_MAX_FAILURES:
                throttle.blocked_until = now + timedelta(
                    seconds=ADMIN_LOGIN_LOCKOUT_SECONDS
                )
            blocked_until = throttle.blocked_until
            db.commit()
            if blocked_until and blocked_until > now:
                raise HTTPException(
                    status_code=429,
                    detail="登录尝试过多，请稍后重试",
                    headers={"Retry-After": str(ADMIN_LOGIN_LOCKOUT_SECONDS)},
                )
            raise HTTPException(status_code=401, detail="密码错误")

        if throttle:
            db.delete(throttle)
        db.commit()
    finally:
        db.close()

    session_id = secrets.token_urlsafe(32)
    session_hash = _admin_session_hash(session_id)
    session_now = utcnow().replace(tzinfo=None)
    session_db = Session()
    try:
        session_db.execute(
            delete(AdminSession).where(
                or_(
                    AdminSession.expires_at < session_now - timedelta(days=30),
                    AdminSession.revoked_at < session_now - timedelta(days=30),
                )
            )
        )
        session_db.add(
            AdminSession(
                session_hash=session_hash,
                created_at=session_now,
                expires_at=session_now + timedelta(seconds=SESSION_MAX_AGE),
            )
        )
        session_db.commit()
    except Exception:
        session_db.rollback()
        raise
    finally:
        session_db.close()

    token = serializer.dumps(
        {
            "ok": True,
            "username": ADMIN_USERNAME,
            "role": "admin",
            "auth_version": ADMIN_SESSION_VERSION,
            "sid": session_id,
            "ts": utc_iso(utcnow()),
        }
    )
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return {"ok": True, "username": ADMIN_USERNAME, "role": "admin"}


@app.post("/api/admin/logout")
def logout(request: Request, response: Response):
    raw = request.cookies.get(COOKIE_NAME)
    if raw:
        try:
            payload = serializer.loads(raw, max_age=SESSION_MAX_AGE)
        except BadSignature:
            payload = None
        session_hash = (
            _admin_session_hash(payload.get("sid"))
            if isinstance(payload, dict)
            else None
        )
        if session_hash:
            db = Session()
            try:
                current = db.get(AdminSession, session_hash)
                if current and current.revoked_at is None:
                    current.revoked_at = utcnow().replace(tzinfo=None)
                    db.commit()
            except Exception as exc:
                db.rollback()
                audit_logger.exception("Could not revoke administrator session")
                raise HTTPException(503, "无法撤销登录会话，请稍后重试") from exc
            finally:
                db.close()
    response.delete_cookie(COOKIE_NAME)
    return {"ok": True}


@app.get("/api/admin/me")
def me(request: Request):
    try:
        payload = require_admin(request)
        return {
            "authenticated": True,
            "username": payload.get("username") or ADMIN_USERNAME,
            "role": payload.get("role") or "admin",
        }
    except HTTPException:
        return {"authenticated": False}


# ---------------------------------------------------------------- nodes


def _iso(value):
    return utc_iso(value)


def _parse_expiry(value, field_name="expires_at"):
    """Parse an API expiry as UTC; date-only values expire at end of that day."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise HTTPException(422, f"{field_name} 必须是 ISO 日期或时间")
    try:
        if len(value) == 10:
            parsed_date = date.fromisoformat(value)
            parsed = datetime.combine(parsed_date, time.max, tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise HTTPException(422, f"{field_name} 必须是有效的 ISO 日期或时间") from exc
    # SQLite stores timezone-naive UTC datetimes. Keep comparisons consistent.
    return parsed.replace(tzinfo=None)


def _latest_metric(db, node_id):
    if db is None:
        return None
    return db.scalar(
        select(NodeMetricSample)
        .where(NodeMetricSample.node_id == node_id)
        .order_by(NodeMetricSample.bucket.desc())
        .limit(1)
    )


def _metric_dict(sample):
    if sample is None:
        return {
            "mapped": False,
            "online": None,
            "fresh": False,
            "stale": True,
            "last_active": None,
            "last_heartbeat": None,
            "sampled_at": None,
            "collector_delay_seconds": None,
            "net_in_transfer": None,
            "net_out_transfer": None,
            "net_in_speed": None,
            "net_out_speed": None,
            "delta_in": 0,
            "delta_out": 0,
        }
    collected_at = sample.collected_at
    if collected_at is not None and collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=timezone.utc)
    elif collected_at is not None:
        collected_at = collected_at.astimezone(timezone.utc)
    delay = None
    age_seconds = None
    if collected_at is not None:
        age_seconds = (utcnow() - collected_at).total_seconds()
        if age_seconds >= 0:
            delay = int(age_seconds)
    fresh = age_seconds is not None and 0 <= age_seconds <= 600
    return {
        "mapped": True,
        "online": sample.online if fresh else None,
        "fresh": fresh,
        "stale": not fresh,
        "last_active": _iso(sample.last_active),
        "last_heartbeat": _iso(sample.last_active),
        "sampled_at": _iso(sample.collected_at),
        "collector_delay_seconds": delay,
        "net_in_transfer": sample.net_in_transfer,
        "net_out_transfer": sample.net_out_transfer,
        "net_in_speed": sample.net_in_speed,
        "net_out_speed": sample.net_out_speed,
        "delta_in": sample.delta_in,
        "delta_out": sample.delta_out,
    }


def _node_traffic_summary(db, node_id):
    if db is None:
        return {
            key: {"bytes_in": 0, "bytes_out": 0, "total": 0}
            for key in ("24h", "7d", "30d")
        }
    now = utcnow().replace(tzinfo=None)
    result = {}
    for key, days in (("24h", 1), ("7d", 7), ("30d", 30)):
        since = now - timedelta(days=days)
        bytes_in, bytes_out = db.execute(
            select(
                func.coalesce(func.sum(NodeMetricSample.delta_in), 0),
                func.coalesce(func.sum(NodeMetricSample.delta_out), 0),
            ).where(
                NodeMetricSample.node_id == node_id,
                NodeMetricSample.bucket >= since,
            )
        ).one()
        bytes_in = int(bytes_in or 0)
        bytes_out = int(bytes_out or 0)
        result[key] = {
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "total": bytes_in + bytes_out,
        }
    return result


def node_dict(n: Node, alloc_count: int = 0, db=None):
    parsed = parse_uri(n.uri) or {}
    real = is_real_node(n)
    metric = _metric_dict(_latest_metric(db, n.id))
    metric["mapped"] = n.nezha_server_id is not None
    adapter = capability(n, db)
    agent = (
        db.scalar(select(NodeAgent).where(NodeAgent.node_id == n.id))
        if db is not None
        else None
    )
    return {
        "id": n.id,
        "name": n.name,
        "protocol": n.protocol,
        "adapter_kind": n.adapter_kind,
        "server": n.server,
        "port": parsed.get("port", 0),
        "is_real": real,
        "is_announcement": bool(n.is_announcement),
        "enabled": n.enabled,
        "sort_order": n.sort_order,
        "expires_at": _iso(n.expires_at),
        "updated_at": _iso(n.updated_at),
        "nezha_server_id": n.nezha_server_id,
        "per_user_enabled": bool(n.per_user_enabled),
        "per_user_capability": adapter,
        "agent": (
            {
                "status": agent.status,
                "last_seen": _iso(agent.last_seen),
                "rotation_pending": bool(agent.pending_token_hash),
                "pending_last_seen": _iso(agent.pending_token_last_seen),
            }
            if agent
            else None
        ),
        "allocated_to": alloc_count if real else 0,
        "collector": metric,
        "traffic": (
            _node_traffic_summary(db, n.id)
            if n.enabled
            else {
                key: {"bytes_in": 0, "bytes_out": 0, "total": 0}
                for key in ("24h", "7d", "30d")
            }
        ),
    }


@app.get("/api/admin/nodes")
def list_nodes(request: Request, db=Depends(get_db), _=Depends(require_admin)):
    counts = dict(
        db.execute(
            select(Allocation.node_id, func.count(Allocation.id))
            .join(Node, Node.id == Allocation.node_id)
            .where(Node.is_announcement.is_(False))
            .group_by(Allocation.node_id)
        ).all()
    )
    nodes = db.scalars(
        select(Node)
        .where(Node.is_announcement.is_(False))
        .order_by(Node.sort_order, Node.id)
    ).all()
    return [node_dict(n, counts.get(n.id, 0), db) for n in nodes]


@app.get("/api/admin/nodes/{node_id}/traffic")
def node_traffic(
    node_id: int,
    range: str = "24h",
    db=Depends(get_db),
    _=Depends(require_admin),
):
    node = db.get(Node, node_id)
    if not node or node.is_announcement:
        raise HTTPException(404, "节点不存在")
    days = {"24h": 1, "7d": 7, "30d": 30}.get(range)
    if days is None:
        raise HTTPException(400, "range 只能是 24h、7d 或 30d")
    since = utcnow() - timedelta(days=days)
    rows = (
        db.execute(
            select(NodeMetricSample)
            .where(
                NodeMetricSample.node_id == node_id,
                NodeMetricSample.bucket >= since.replace(tzinfo=None),
            )
            .order_by(NodeMetricSample.bucket)
        )
        .scalars()
        .all()
    )
    total_in = sum(row.delta_in for row in rows)
    total_out = sum(row.delta_out for row in rows)
    return {
        "node": node_dict(node, db=db),
        "range": range,
        "totals": {"bytes_in": total_in, "bytes_out": total_out},
        "points": [
            {
                "at": _iso(row.bucket),
                "online": row.online,
                "bytes_in": row.delta_in,
                "bytes_out": row.delta_out,
                "net_in_transfer": row.net_in_transfer,
                "net_out_transfer": row.net_out_transfer,
                "net_in_speed": row.net_in_speed,
                "net_out_speed": row.net_out_speed,
            }
            for row in rows
        ],
    }


def _topology_agent_state(agent):
    if agent is None:
        return {
            "configured": False,
            "status": "unconfigured",
            "online": False,
            "last_seen": None,
        }
    last_seen = agent.last_seen
    if last_seen is not None and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    elif last_seen is not None:
        last_seen = last_seen.astimezone(timezone.utc)
    online = bool(
        last_seen is not None and (utcnow() - last_seen).total_seconds() <= 180
    )
    return {
        "configured": True,
        "status": agent.status,
        "online": online,
        "last_seen": _iso(agent.last_seen),
    }


@app.get("/api/admin/overview/topology")
def overview_topology(db=Depends(get_db), _=Depends(require_admin)):
    """Build the management graph from current allocations and node endpoints."""
    friends = db.scalars(select(Friend).order_by(Friend.id)).all()
    nodes = db.scalars(select(Node).order_by(Node.sort_order, Node.id)).all()
    allocations = db.execute(
        select(Allocation.friend_id, Allocation.node_id).order_by(
            Allocation.friend_id, Allocation.node_id
        )
    ).all()
    agents = {agent.node_id: agent for agent in db.scalars(select(NodeAgent)).all()}
    by_friend = {}
    for friend_id, node_id in allocations:
        by_friend.setdefault(friend_id, set()).add(node_id)
    nodes_by_id = {node.id: node for node in nodes}
    graph_nodes = {}
    edges = []
    seen_relations = set()

    for friend in friends:
        friend_name = f"用户/{friend.uid}"
        graph_nodes.setdefault(
            friend_name,
            {
                "name": friend_name,
                "type": "user",
                "friend_id": friend.id,
                "enabled": bool(friend.enabled),
                "node_count": 0,
            },
        )
        friend_node_ids = set()
        for node_id in by_friend.get(friend.id, []):
            node = nodes_by_id.get(node_id)
            if node is None:
                continue
            parsed = parse_uri(node.uri) or {}
            if not is_real_node(node):
                continue
            node_name = f"节点/{node.name}"
            host = parsed.get("host") or node.server or "未知"
            server_name = f"服务器/{host}"
            agent_state = _topology_agent_state(agents.get(node.id))
            graph_nodes.setdefault(
                node_name,
                {
                    "name": node_name,
                    "type": "node",
                    "node_id": node.id,
                    "protocol": node.protocol,
                    "enabled": bool(node.enabled),
                    "agent": agent_state,
                },
            )
            graph_nodes.setdefault(
                server_name,
                {
                    "name": server_name,
                    "type": "server",
                    "server": host,
                    "node_ids": [],
                },
            )
            friend_node_ids.add(node.id)
            graph_nodes[friend_name]["node_count"] = len(friend_node_ids)
            if node.id not in graph_nodes[server_name]["node_ids"]:
                graph_nodes[server_name]["node_ids"].append(node.id)
            relation = (friend_name, node_name)
            if relation not in seen_relations:
                edges.append(
                    {
                        "source": friend_name,
                        "target": node_name,
                        "value": 1,
                        "kind": "allocation",
                        "active": bool(friend.enabled and node.enabled),
                    }
                )
                seen_relations.add(relation)
            relation = (node_name, server_name)
            if relation not in seen_relations:
                edges.append(
                    {
                        "source": node_name,
                        "target": server_name,
                        "value": 1,
                        "kind": "endpoint",
                        "active": bool(node.enabled),
                    }
                )
                seen_relations.add(relation)

    return {
        "mode": "management",
        "source": "database_allocations",
        "generated_at": _iso(utcnow()),
        "summary": {
            "users": sum(1 for item in graph_nodes.values() if item["type"] == "user"),
            "nodes": sum(1 for item in graph_nodes.values() if item["type"] == "node"),
            "servers": sum(
                1 for item in graph_nodes.values() if item["type"] == "server"
            ),
            "relations": sum(1 for edge in edges if edge["kind"] == "allocation"),
        },
        "nodes": list(graph_nodes.values()),
        "edges": edges,
    }


COLLECTOR_STALE_AFTER_SECONDS = 15 * 60


def _with_status_freshness(payload):
    """Decorate a timer status file with a conservative 15-minute age check."""
    result = dict(payload) if isinstance(payload, dict) else {"status": "invalid"}
    raw_at = result.get("at") or result.get("finished_at") or result.get("started_at")
    age_seconds = None
    if raw_at:
        try:
            checked_at = datetime.fromisoformat(str(raw_at).replace("Z", "+00:00"))
            if checked_at.tzinfo is None:
                checked_at = checked_at.replace(tzinfo=timezone.utc)
            age = (utcnow() - checked_at.astimezone(timezone.utc)).total_seconds()
            if age >= 0:
                age_seconds = int(age)
        except ValueError:
            pass
    result["age_seconds"] = age_seconds
    result["stale"] = age_seconds is None or age_seconds > COLLECTOR_STALE_AFTER_SECONDS
    return result


def _collector_status(db):
    sqlite_status = _sqlite_runtime_status(sqlite3.sqlite_version)
    proxy_status_path = Path(
        os.environ.get(
            "SUB_APP_PROXY_STATUS", "/var/lib/sub-app/proxy-collector-status.json"
        )
    )
    reconciler_status_path = Path(
        os.environ.get(
            "SUB_APP_RECONCILER_STATUS", "/var/lib/sub-app/reconciler-status.json"
        )
    )
    try:
        proxy_status = _with_status_freshness(
            json.loads(proxy_status_path.read_text(encoding="utf-8"))
        )
    except (FileNotFoundError, ValueError):
        proxy_status = _with_status_freshness({"status": "never_run"})
    try:
        reconciler_status = _with_status_freshness(
            json.loads(reconciler_status_path.read_text(encoding="utf-8"))
        )
    except (FileNotFoundError, ValueError):
        reconciler_status = _with_status_freshness({"status": "never_run"})
    run = db.scalar(
        select(CollectorRun)
        .where(CollectorRun.source == "nezha")
        .order_by(CollectorRun.started_at.desc())
        .limit(1)
    )
    last_success = db.scalar(
        select(CollectorRun)
        .where(
            CollectorRun.source == "nezha",
            CollectorRun.status == "success",
        )
        .order_by(CollectorRun.finished_at.desc())
        .limit(1)
    )
    if run is None:
        return {
            "configured": is_collector_configured(),
            "status": "never_run",
            "started_at": None,
            "finished_at": None,
            "last_success_at": None,
            "age_seconds": None,
            "stale": False,
            **sqlite_status,
            "nodes_total": 0,
            "samples_written": 0,
            "error": "",
            "proxy": proxy_status,
            "reconciler": reconciler_status,
        }
    run_freshness = _with_status_freshness(
        {"status": run.status, "at": _iso(run.finished_at or run.started_at)}
    )
    return {
        "configured": is_collector_configured(),
        "status": run.status,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "last_success_at": _iso(last_success.finished_at) if last_success else None,
        "age_seconds": run_freshness["age_seconds"],
        "stale": run_freshness["stale"],
        **sqlite_status,
        "nodes_total": run.nodes_total,
        "samples_written": run.samples_written,
        "error": run.error or "",
        "proxy": proxy_status,
        "reconciler": reconciler_status,
    }


def _sqlite_runtime_status(version):
    try:
        parsed = tuple(int(part) for part in str(version).split(".")[:3])
        parsed = (parsed + (0, 0, 0))[:3]
    except ValueError:
        parsed = ()
    fixed = parsed >= (3, 51, 3) or parsed in {(3, 50, 7), (3, 44, 6)}
    return {
        "sqlite_version": str(version),
        "sqlite_wal_reset_fix": "fixed" if fixed else "verify_backport",
    }


@app.get("/api/admin/collector/status")
def collector_status(db=Depends(get_db), _=Depends(require_admin)):
    return _collector_status(db)


@app.get("/api/admin/latency")
def latency_status(_=Depends(require_admin)):
    """Return the last real node-entry/proxy-exit probe without secrets."""
    return read_status()


@app.post("/api/admin/latency/probe")
def trigger_latency_probe(_=Depends(require_admin)):
    """Start a bounded background probe; repeated clicks are coalesced."""
    return start_probe()


@app.get("/api/admin/collector/servers")
def collector_servers(_=Depends(require_admin)):
    base_url, token = collector_config()
    try:
        servers = fetch_servers(base_url, token)
    except CollectorError as exc:
        raise HTTPException(503, str(exc))
    return [
        {
            "id": server["id"],
            "name": server["name"],
            "online": server["online"],
            "last_active": _iso(server["last_active"]),
        }
        for server in servers
    ]


@app.post("/api/admin/nodes")
def create_nodes(
    payload: dict = Body(...), db=Depends(get_db), _=Depends(require_admin)
):
    """Accepts either a single node or a bulk paste of URIs."""
    bulk = payload.get("bulk", "")
    created, skipped = [], []

    raw_list = (
        [line.strip() for line in bulk.splitlines() if line.strip()] if bulk else []
    )
    if payload.get("uri"):
        raw_list.append(payload["uri"].strip())

    max_order = db.scalar(select(func.max(Node.sort_order))) or 0
    seen = set()
    for existing_node in db.scalars(select(Node)).all():
        if existing_node.is_announcement:
            continue
        existing = parse_uri(existing_node.uri)
        if existing:
            seen.add(_node_identity(existing))

    for raw in raw_list:
        parsed = parse_uri(raw)
        if not parsed:
            skipped.append(raw[:60])
            continue
        identity = _node_identity(parsed)
        if identity in seen:
            skipped.append(f"重复: {parsed.get('name') or raw[:40]}")
            continue
        seen.add(identity)
        max_order += 1
        node = Node(
            name=payload.get("name")
            or parsed["name"]
            or f"{parsed['scheme']}-{parsed['host']}",
            protocol=parsed["scheme"],
            uri=raw,
            server=parsed["host"],
            sort_order=max_order,
        )
        db.add(node)
        created.append(node.name)

    db.commit()
    return {"created": created, "skipped": skipped}


def _node_identity(parsed):
    """Canonical identity ignores display names and query-string ordering."""
    params = dict(parsed.get("params") or {})
    if parsed.get("scheme") == "vmess":
        for display_key in ("ps", "remark", "remarks"):
            params.pop(display_key, None)
    return (
        str(parsed.get("scheme", "")).lower(),
        str(parsed.get("host", "")).casefold(),
        int(parsed.get("port") or 0),
        str(parsed.get("user", "")),
        str(parsed.get("password", "")),
        json.dumps(params, sort_keys=True, separators=(",", ":"), default=str),
    )


@app.patch("/api/admin/nodes/{node_id}")
def update_node(
    node_id: int,
    payload: dict = Body(...),
    db=Depends(get_db),
    _=Depends(require_admin),
):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "节点不存在")
    if node.is_announcement:
        raise HTTPException(409, "这是已迁移的公告，请使用公告管理接口")
    if "per_user_enabled" in payload and type(payload["per_user_enabled"]) is not bool:
        raise HTTPException(422, "per_user_enabled 必须是布尔值")

    parsed_uri = None
    if payload.get("uri"):
        parsed_uri = parse_uri(payload["uri"])
        if not parsed_uri:
            raise HTTPException(400, "无法解析该节点链接")
    requested_kind = payload.get("adapter_kind", node.adapter_kind)
    requested_protocol = parsed_uri["scheme"] if parsed_uri else node.protocol
    if requested_protocol != node.protocol:
        has_agent = db.scalar(select(NodeAgent.id).where(NodeAgent.node_id == node.id))
        has_history = db.scalar(
            select(UserNodeCredential.id)
            .where(UserNodeCredential.node_id == node.id)
            .limit(1)
        )
        if has_agent or has_history:
            raise HTTPException(
                409,
                "节点已有 Agent 或凭据历史，不能直接更换协议；请创建替代节点，验证后迁移分配。",
            )
    if not isinstance(requested_kind, str):
        raise HTTPException(422, "adapter_kind 必须是字符串")
    if requested_kind not in {"shared", "local_hy2", "local_vless", "remote_agent"}:
        raise HTTPException(422, "adapter_kind 不受支持")
    candidate = Node(
        id=node.id,
        protocol=requested_protocol,
        adapter_kind=requested_kind,
    )
    if requested_kind != "shared" and not adapter_info(candidate):
        raise HTTPException(422, "适配器类型与节点协议不匹配")
    if requested_kind != node.adapter_kind:
        has_agent = db.scalar(select(NodeAgent.id).where(NodeAgent.node_id == node.id))
        has_live_credentials = db.scalar(
            select(UserNodeCredential.id)
            .where(
                UserNodeCredential.node_id == node.id,
                UserNodeCredential.revoked_at.is_(None),
            )
            .limit(1)
        )
        if has_agent or has_live_credentials:
            raise HTTPException(
                409,
                "节点已有 Agent 或未撤销凭据，不能直接更换适配器；请先停用并完成迁移。",
            )
    if requested_kind in {"local_hy2", "local_vless"}:
        conflict = db.scalar(
            select(Node).where(Node.adapter_kind == requested_kind, Node.id != node.id)
        )
        if conflict:
            raise HTTPException(409, "本机适配器类型已绑定其他节点")
    if requested_kind == "remote_agent" and requested_kind != node.adapter_kind:
        node.per_user_enabled = False
    node.adapter_kind = requested_kind
    if parsed_uri and not adapter_info(node) and node.adapter_kind != "shared":
        raise HTTPException(422, "更新后的 URI 协议与适配器类型不匹配")
    if (
        payload.get("per_user_enabled") is True
        and not node.per_user_enabled
        and not adapter_ready(node, db)
    ):
        raise HTTPException(
            409,
            "该节点的代理适配器/Agent 尚未就绪，不能开启用户级独立凭据。"
            "Agent 超过 180 秒未上报或未应用配置；请先恢复 Agent，"
            "或暂不启用独立凭据。节点其他字段保存不受影响。",
        )
    for field in (
        "name",
        "enabled",
        "sort_order",
        "nezha_server_id",
        "per_user_enabled",
        "adapter_kind",
    ):
        if field in payload:
            setattr(node, field, payload[field])
    if "expires_at" in payload:
        node.expires_at = _parse_expiry(payload["expires_at"], "expires_at")
    if payload.get("uri"):
        node.uri = payload["uri"]
        node.protocol = parsed_uri["scheme"]
        node.server = parsed_uri["host"]
    db.commit()
    return node_dict(node, db=db)


@app.post("/api/admin/nodes/{node_id}/per-user/prepare")
def prepare_node_credentials(
    node_id: int, db=Depends(get_db), _=Depends(require_admin)
):
    """Prepare/sync opted-in users for a meterable node."""
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "节点不存在")
    if node.protocol not in ("vless", "hysteria2"):
        raise HTTPException(400, "首批独立凭据只支持 VLESS 和 Hysteria2")
    friends = db.scalars(
        select(Friend)
        .join(Allocation, Allocation.friend_id == Friend.id)
        .where(Allocation.node_id == node_id, Friend.enabled.is_(True))
        .order_by(Friend.id)
    ).all()
    rows = []
    for friend in friends:
        if not friend.per_user_credentials:
            continue
        row = ensure_credential(db, friend, node)
        activate_credential(db, row)
        rows.append(row)
    db.commit()
    return {
        "ok": True,
        "node_id": node_id,
        "feature_enabled": per_user_feature_enabled(),
        "activated": bool(rows) and all(row.status == "active" for row in rows),
        "reason": "adapter sync attempted; failures remain pending/error",
        "credentials": [credential_public_dict(row) for row in rows],
    }


@app.delete("/api/admin/nodes/{node_id}")
def delete_node(node_id: int, db=Depends(get_db), _=Depends(require_admin)):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "节点不存在")
    if node.is_announcement:
        raise HTTPException(409, "这是已迁移的公告，请使用公告管理接口")
    db.delete(node)
    db.commit()
    return {"ok": True}


def announcement_dict(announcement: Announcement, allocated_to: int = 0):
    return {
        "id": announcement.id,
        "legacy_node_id": announcement.legacy_node_id,
        "name": announcement.name,
        "enabled": announcement.enabled,
        "sort_order": announcement.sort_order,
        "allocated_to": allocated_to,
        "created_at": _iso(announcement.created_at),
        "updated_at": _iso(announcement.updated_at),
    }


def _announcement_name(value):
    if not isinstance(value, str):
        raise HTTPException(422, "公告内容必须是文本")
    name = value.strip()
    if not name or len(name) > 160:
        raise HTTPException(422, "公告内容长度必须为 1 到 160 个字符")
    return name


def _announcement_order(db, payload, current=None):
    if "sort_order" not in payload:
        if current is not None:
            return current.sort_order
        node_max = db.scalar(
            select(func.max(Node.sort_order)).where(Node.is_announcement.is_(False))
        )
        announcement_max = db.scalar(select(func.max(Announcement.sort_order)))
        return max(node_max or 0, announcement_max or 0) + 1
    value = payload["sort_order"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HTTPException(422, "sort_order 必须是非负整数")
    return value


@app.get("/api/admin/announcements")
def list_announcements(db=Depends(get_db), _=Depends(require_admin)):
    counts = dict(
        db.execute(
            select(
                AnnouncementAllocation.announcement_id,
                func.count(AnnouncementAllocation.id),
            ).group_by(AnnouncementAllocation.announcement_id)
        ).all()
    )
    rows = db.scalars(
        select(Announcement).order_by(Announcement.sort_order, Announcement.id)
    ).all()
    return [announcement_dict(row, counts.get(row.id, 0)) for row in rows]


@app.post("/api/admin/announcements")
def create_announcement(
    payload: dict = Body(...), db=Depends(get_db), _=Depends(require_admin)
):
    name = _announcement_name(payload.get("name"))
    enabled = payload.get("enabled", True)
    if type(enabled) is not bool:
        raise HTTPException(422, "enabled 必须是布尔值")
    announcement = Announcement(
        name=name,
        enabled=enabled,
        sort_order=_announcement_order(db, payload),
    )
    db.add(announcement)
    db.commit()
    return announcement_dict(announcement)


@app.patch("/api/admin/announcements/{announcement_id}")
def update_announcement(
    announcement_id: int,
    payload: dict = Body(...),
    db=Depends(get_db),
    _=Depends(require_admin),
):
    announcement = db.get(Announcement, announcement_id)
    if not announcement:
        raise HTTPException(404, "公告不存在")
    if "name" in payload:
        announcement.name = _announcement_name(payload["name"])
    if "enabled" in payload:
        if type(payload["enabled"]) is not bool:
            raise HTTPException(422, "enabled 必须是布尔值")
        announcement.enabled = payload["enabled"]
    if "sort_order" in payload:
        announcement.sort_order = _announcement_order(db, payload, announcement)
    db.commit()
    allocated_to = db.scalar(
        select(func.count(AnnouncementAllocation.id)).where(
            AnnouncementAllocation.announcement_id == announcement.id
        )
    )
    return announcement_dict(announcement, allocated_to or 0)


@app.delete("/api/admin/announcements/{announcement_id}")
def delete_announcement(
    announcement_id: int, db=Depends(get_db), _=Depends(require_admin)
):
    announcement = db.get(Announcement, announcement_id)
    if not announcement:
        raise HTTPException(404, "公告不存在")
    assigned_count = db.scalar(
        select(func.count(AnnouncementAllocation.id)).where(
            AnnouncementAllocation.announcement_id == announcement.id
        )
    )
    db.delete(announcement)
    db.commit()
    return {"ok": True, "removed_user_allocations": assigned_count or 0}


# ---------------------------------------------------------------- friends


def _friend_usage(db, friend_id, since=None):
    return friend_usage(db, friend_id, since=since)


def friend_dict(
    f: Friend,
    node_ids: list[int],
    device_count: int = 0,
    usage=None,
    db=None,
    announcement_ids: list[int] | None = None,
):
    base = PUBLIC_BASE or ""
    usage = usage or (
        _friend_usage(db, f.id) if db is not None else {"bytes_in": 0, "bytes_out": 0}
    )
    used = usage["bytes_in"] + usage["bytes_out"]
    limit = f.flow_limit_gb * 1024**3
    percent = (used / limit * 100) if limit else 0
    alert = (
        "over"
        if limit and used >= limit
        else ("warning" if limit and used >= limit * 0.8 else "ok")
    )
    credential_status = []
    last_shared_fallback_nodes = 0
    last_skipped_node_count = 0
    last_expired_node_count = 0
    if db is not None:
        credential_status = [
            credential_public_dict(row) for row in _credential_rows_for_friend(db, f.id)
        ]
        latest_fetch = db.scalar(
            select(FetchLog)
            .where(FetchLog.friend_id == f.id)
            .order_by(FetchLog.created_at.desc(), FetchLog.id.desc())
            .limit(1)
        )
        if latest_fetch is not None:
            last_shared_fallback_nodes = latest_fetch.shared_fallback_count
            last_skipped_node_count = latest_fetch.skipped_node_count
            last_expired_node_count = latest_fetch.expired_node_count
    supported_ids = supported_node_ids(db)
    unsupported = [node_id for node_id in node_ids if node_id not in supported_ids]
    return {
        "id": f.id,
        "uid": f.uid,
        "remark": f.remark,
        "token": f.token,
        "enabled": f.enabled,
        "flow_limit_gb": f.flow_limit_gb,
        "device_limit": f.device_limit,
        "per_user_credentials": f.per_user_credentials,
        "credential_status": credential_status,
        "last_shared_fallback_nodes": last_shared_fallback_nodes,
        "last_skipped_node_count": last_skipped_node_count,
        "last_expired_node_count": last_expired_node_count,
        "unsupported_node_ids": unsupported,
        "node_ids": node_ids,
        "announcement_ids": announcement_ids or [],
        "device_count": device_count,
        "flow_used_bytes": used,
        "flow_in_bytes": usage["bytes_in"],
        "flow_out_bytes": usage["bytes_out"],
        "flow_limit_bytes": limit,
        "flow_percent": round(percent, 2),
        "flow_alert": alert,
        "expires_at": _iso(f.expires_at),
        "updated_at": _iso(f.updated_at),
        "created_at": _iso(f.created_at),
        "links": {
            "clash": f"{base}/sub/{f.token}?target=clash",
            "shadowrocket": f"{base}/sub/{f.token}?target=shadowrocket",
            "v2ray": f"{base}/sub/{f.token}?target=v2ray",
        },
    }


def _real_node_ids(db, raw_ids) -> list[int]:
    """Validate allocation IDs before excluding legacy notice nodes."""

    if not isinstance(raw_ids, list):
        raise HTTPException(422, "node_ids 必须是节点 ID 列表")

    requested: list[int] = []
    for value in raw_ids:
        if isinstance(value, bool):
            raise HTTPException(422, "node_ids 只能包含正整数节点 ID")
        if isinstance(value, int):
            node_id = value
        elif isinstance(value, str) and value.strip().isdecimal():
            normalized = value.strip()
            if len(normalized) > 19:
                raise HTTPException(422, "node_ids 只能包含正整数节点 ID")
            try:
                node_id = int(normalized)
            except ValueError:
                raise HTTPException(422, "node_ids 只能包含正整数节点 ID") from None
        else:
            raise HTTPException(422, "node_ids 只能包含正整数节点 ID")
        if node_id <= 0 or node_id > 9_223_372_036_854_775_807:
            raise HTTPException(422, "node_ids 只能包含正整数节点 ID")
        if node_id not in requested:
            requested.append(node_id)
    if not requested:
        return []
    nodes = db.scalars(select(Node).where(Node.id.in_(requested))).all()
    by_id = {node.id: node for node in nodes}
    missing = [node_id for node_id in requested if node_id not in by_id]
    if missing:
        raise HTTPException(422, f"节点不存在: {', '.join(map(str, missing))}")
    return [node_id for node_id in requested if is_real_node(by_id[node_id])]


def _friend_node_ids(db) -> dict[int, list[int]]:
    """Return only real-node allocations, preserving allocation order."""

    rows = db.execute(
        select(Allocation.friend_id, Allocation.node_id, Node)
        .join(Node, Node.id == Allocation.node_id)
        .order_by(Allocation.friend_id, Allocation.node_id)
    ).all()
    by_friend: dict[int, list[int]] = {}
    for friend_id, node_id, node in rows:
        if is_real_node(node):
            by_friend.setdefault(friend_id, []).append(node_id)
    return by_friend


def _friend_announcement_ids(db) -> dict[int, list[int]]:
    rows = db.execute(
        select(
            AnnouncementAllocation.friend_id,
            AnnouncementAllocation.announcement_id,
        ).order_by(
            AnnouncementAllocation.friend_id,
            AnnouncementAllocation.announcement_id,
        )
    ).all()
    by_friend: dict[int, list[int]] = {}
    for friend_id, announcement_id in rows:
        by_friend.setdefault(friend_id, []).append(announcement_id)
    return by_friend


def _announcement_ids(db, raw_ids) -> list[int]:
    if not isinstance(raw_ids, list):
        raise HTTPException(422, "announcement_ids 必须是公告 ID 列表")
    requested: list[int] = []
    for value in raw_ids:
        if isinstance(value, bool):
            raise HTTPException(422, "announcement_ids 只能包含正整数")
        if isinstance(value, int):
            announcement_id = value
        elif isinstance(value, str) and value.strip().isdecimal():
            normalized = value.strip()
            if len(normalized) > 19:
                raise HTTPException(422, "announcement_ids 只能包含正整数")
            announcement_id = int(normalized)
        else:
            raise HTTPException(422, "announcement_ids 只能包含正整数")
        if announcement_id <= 0 or announcement_id > 9_223_372_036_854_775_807:
            raise HTTPException(422, "announcement_ids 只能包含正整数")
        if announcement_id not in requested:
            requested.append(announcement_id)
    if not requested:
        return []
    existing = set(
        db.scalars(select(Announcement.id).where(Announcement.id.in_(requested))).all()
    )
    missing = [value for value in requested if value not in existing]
    if missing:
        raise HTTPException(422, f"公告不存在: {', '.join(map(str, missing))}")
    return requested


@app.get("/api/admin/friends")
def list_friends(db=Depends(get_db), _=Depends(require_admin)):
    friends = db.scalars(select(Friend).order_by(Friend.id)).all()
    by_friend = _friend_node_ids(db)
    announcements_by_friend = _friend_announcement_ids(db)
    dev_counts = dict(
        db.execute(
            select(Device.friend_id, func.count(Device.id)).group_by(Device.friend_id)
        ).all()
    )
    return [
        friend_dict(
            f,
            by_friend.get(f.id, []),
            dev_counts.get(f.id, 0),
            db=db,
            announcement_ids=announcements_by_friend.get(f.id, []),
        )
        for f in friends
    ]


@app.post("/api/admin/friends")
def create_friend(
    payload: dict = Body(...), db=Depends(get_db), _=Depends(require_admin)
):
    uid = (payload.get("uid") or "").strip()
    if not uid:
        raise HTTPException(400, "UID 不能为空")
    if db.scalar(select(Friend).where(Friend.uid == uid)):
        raise HTTPException(400, "该 UID 已存在")
    node_ids = _real_node_ids(db, payload.get("node_ids", []))
    announcement_ids = _announcement_ids(db, payload.get("announcement_ids", []))
    friend = Friend(
        uid=uid,
        remark=payload.get("remark", ""),
        flow_limit_gb=int(payload.get("flow_limit_gb", 0) or 0),
        device_limit=int(payload.get("device_limit", 0) or 0),
        per_user_credentials=bool(payload.get("per_user_credentials", False)),
        expires_at=_parse_expiry(payload.get("expires_at"), "expires_at"),
        token=new_token(),
    )
    db.add(friend)
    db.flush()
    for nid in node_ids:
        if db.get(Node, nid):
            db.add(Allocation(friend_id=friend.id, node_id=nid))
    for announcement_id in announcement_ids:
        db.add(
            AnnouncementAllocation(friend_id=friend.id, announcement_id=announcement_id)
        )
    db.flush()
    _reconcile_friend_credentials(db, friend)
    db.commit()
    return friend_dict(friend, node_ids, db=db, announcement_ids=announcement_ids)


@app.patch("/api/admin/friends/{friend_id}")
def update_friend(
    friend_id: int,
    payload: dict = Body(...),
    db=Depends(get_db),
    _=Depends(require_admin),
):
    friend = db.get(Friend, friend_id)
    if not friend:
        raise HTTPException(404, "用户不存在")

    wanted = (
        set(_real_node_ids(db, payload["node_ids"])) if "node_ids" in payload else None
    )
    wanted_announcements = (
        set(_announcement_ids(db, payload["announcement_ids"]))
        if "announcement_ids" in payload
        else None
    )

    for field in (
        "remark",
        "enabled",
        "flow_limit_gb",
        "device_limit",
        "per_user_credentials",
    ):
        if field in payload:
            setattr(friend, field, payload[field])
    if "expires_at" in payload:
        friend.expires_at = _parse_expiry(payload["expires_at"], "expires_at")

    if wanted is not None:
        current = {
            a.node_id: a
            for a in db.scalars(
                select(Allocation).where(Allocation.friend_id == friend_id)
            ).all()
        }
        for nid in wanted - current.keys():
            db.add(Allocation(friend_id=friend_id, node_id=nid))
        for nid in current.keys() - wanted:
            db.delete(current[nid])

    if wanted_announcements is not None:
        current_announcements = {
            row.announcement_id: row
            for row in db.scalars(
                select(AnnouncementAllocation).where(
                    AnnouncementAllocation.friend_id == friend_id
                )
            ).all()
        }
        for announcement_id in wanted_announcements - current_announcements.keys():
            db.add(
                AnnouncementAllocation(
                    friend_id=friend_id, announcement_id=announcement_id
                )
            )
        for announcement_id in current_announcements.keys() - wanted_announcements:
            db.delete(current_announcements[announcement_id])

    if payload.get("rotate_token"):
        friend.token = new_token()

    db.flush()
    _reconcile_friend_credentials(db, friend)
    db.commit()
    node_ids = _friend_node_ids(db).get(friend_id, [])
    announcement_ids = _friend_announcement_ids(db).get(friend_id, [])
    return friend_dict(friend, node_ids, db=db, announcement_ids=announcement_ids)


@app.delete("/api/admin/friends/{friend_id}")
def delete_friend(friend_id: int, db=Depends(get_db), _=Depends(require_admin)):
    friend = db.get(Friend, friend_id)
    if not friend:
        raise HTTPException(404, "用户不存在")
    db.delete(friend)
    db.commit()
    return {"ok": True}


@app.get("/api/admin/friends/{friend_id}/traffic")
def friend_traffic(
    friend_id: int,
    range: str = "24h",
    db=Depends(get_db),
    _=Depends(require_admin),
):
    friend = db.get(Friend, friend_id)
    if not friend:
        raise HTTPException(404, "用户不存在")
    days = {"24h": 1, "7d": 7, "30d": 30}.get(range)
    if days is None:
        raise HTTPException(400, "range 只能是 24h、7d 或 30d")
    since = (utcnow() - timedelta(days=days)).replace(tzinfo=None)
    rows = db.execute(
        select(
            FlowRecord.bucket,
            func.coalesce(func.sum(FlowRecord.bytes_in), 0),
            func.coalesce(func.sum(FlowRecord.bytes_out), 0),
        )
        .where(
            FlowRecord.friend_id == friend_id,
            FlowRecord.source != "nezha",
            FlowRecord.bucket >= since,
        )
        .group_by(FlowRecord.bucket)
        .order_by(FlowRecord.bucket)
    ).all()
    return {
        "friend_id": friend_id,
        "range": range,
        "totals": {
            "bytes_in": sum(int(row[1]) for row in rows),
            "bytes_out": sum(int(row[2]) for row in rows),
        },
        "points": [
            {"at": _iso(row[0]), "bytes_in": int(row[1]), "bytes_out": int(row[2])}
            for row in rows
        ],
    }


@app.get("/api/admin/friends/{friend_id}/credentials")
def friend_credentials(friend_id: int, db=Depends(get_db), _=Depends(require_admin)):
    if not db.get(Friend, friend_id):
        raise HTTPException(404, "用户不存在")
    rows = db.scalars(
        select(UserNodeCredential)
        .where(UserNodeCredential.friend_id == friend_id)
        .order_by(UserNodeCredential.node_id, UserNodeCredential.version.desc())
    ).all()
    return [
        {
            "id": row.id,
            "node_id": row.node_id,
            "protocol": row.protocol,
            "credential_name": row.credential_name,
            "version": row.version,
            "status": row.status,
            "created_at": _iso(row.created_at),
            "rotated_at": _iso(row.rotated_at),
            "revoked_at": _iso(row.revoked_at),
            "grace_until": _iso(row.grace_until),
            "last_synced_at": _iso(row.last_synced_at),
            "last_error": row.last_error or "",
        }
        for row in rows
    ]


@app.post("/api/admin/credentials/{credential_id}/sync")
def sync_credential(credential_id: int, db=Depends(get_db), _=Depends(require_admin)):
    row = db.get(UserNodeCredential, credential_id)
    if not row:
        raise HTTPException(404, "凭据不存在")
    friend = db.get(Friend, row.friend_id)
    if not friend or not friend.enabled or not friend.per_user_credentials:
        raise HTTPException(409, "用户未启用独立凭据")
    activate_credential(db, row)
    db.commit()
    return credential_public_dict(row)


@app.post("/api/admin/credentials/{credential_id}/rotate")
def rotate_credential(credential_id: int, db=Depends(get_db), _=Depends(require_admin)):
    old = db.get(UserNodeCredential, credential_id)
    if not old:
        raise HTTPException(404, "凭据不存在")
    friend = db.get(Friend, old.friend_id)
    node = db.get(Node, old.node_id)
    if not friend or not node:
        raise HTTPException(404, "用户或节点不存在")
    if old.protocol != node.protocol:
        raise HTTPException(
            409, "凭据协议与节点不一致，不能轮换；请使用当前协议准备凭据"
        )
    if not friend.enabled or not friend.per_user_credentials:
        raise HTTPException(409, "用户未启用独立凭据")
    latest = db.scalar(
        select(UserNodeCredential)
        .where(
            UserNodeCredential.friend_id == old.friend_id,
            UserNodeCredential.node_id == old.node_id,
            UserNodeCredential.protocol == old.protocol,
        )
        .order_by(UserNodeCredential.version.desc())
        .limit(1)
    )
    now = utcnow()
    if old.revoked_at is None:
        old.status = "grace"
        old.grace_until = now + timedelta(hours=24)
        old.rotated_at = now
    row = UserNodeCredential(
        friend_id=old.friend_id,
        node_id=old.node_id,
        protocol=old.protocol,
        credential_name=f"u{old.friend_id}n{old.node_id}",
        version=(latest.version + 1) if latest else 1,
        status="pending",
        created_at=now,
    )
    db.add(row)
    db.flush()
    activate_credential(db, row)
    if row.status != "active" and old.revoked_at is None:
        old.status = "active"
        old.grace_until = None
        old.last_error = row.last_error
    db.commit()
    return {
        "credential": credential_public_dict(row),
        "previous": credential_public_dict(old),
    }


@app.post("/api/admin/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: int, db=Depends(get_db), _=Depends(require_admin)):
    row = db.get(UserNodeCredential, credential_id)
    if not row:
        raise HTTPException(404, "凭据不存在")
    _revoke_credential(db, row)
    row_node = db.get(Node, row.node_id)
    if row_node and is_local_vless(row_node) and adapter_ready(row_node, db):
        try:
            sync_vless_config(db)
        except Exception as exc:
            row.last_error = str(exc)[:1000]
    db.commit()
    return credential_public_dict(row)


# ---------------------------------------------------------------- devices


@app.get("/api/admin/devices")
def list_devices(db=Depends(get_db), _=Depends(require_admin)):
    rows = db.execute(
        select(Device, Friend.uid).join(Friend, Device.friend_id == Friend.id)
    ).all()
    out = []
    for dev, uid in rows:
        out.append(_device_dict(dev, uid))
    out.sort(key=lambda d: d["last_seen"], reverse=True)
    return out


def _device_links(request: Request, friend: Friend, raw_token: str) -> dict:
    base = _public_base(request)
    encoded = quote(raw_token, safe="")
    return {
        "clash": f"{base}/sub/{friend.token}?device={encoded}&target=clash",
        "shadowrocket": f"{base}/sub/{friend.token}?device={encoded}&target=shadowrocket",
        "v2ray": f"{base}/sub/{friend.token}?device={encoded}&target=v2ray",
    }


@app.post("/api/admin/friends/{friend_id}/devices")
def create_device_link(
    friend_id: int,
    request: Request,
    payload: dict = Body(default={}),
    db=Depends(get_db),
    _=Depends(require_admin),
):
    friend = db.get(Friend, friend_id)
    if not friend:
        raise HTTPException(404, "用户不存在")
    count = (
        db.scalar(select(func.count(Device.id)).where(Device.friend_id == friend_id))
        or 0
    )
    if friend.device_limit and count >= friend.device_limit:
        raise HTTPException(409, "设备数已达上限")
    raw_token = secrets.token_urlsafe(24)
    token_hash = device_token_hash(raw_token)
    now = utcnow()
    dev = Device(
        friend_id=friend_id,
        fingerprint=token_hash[:32],
        device_token_hash=token_hash,
        identity_source="device_link",
        device_token_created_at=now,
        label=str(payload.get("label", ""))[:128],
        first_seen=now,
        last_seen=now,
    )
    db.add(dev)
    db.commit()
    return {
        "ok": True,
        "device": _device_dict(dev, friend.uid),
        "links": _device_links(request, friend, raw_token),
        "notice": "链接只在本次响应中返回；数据库仅保存哈希",
    }


@app.post("/api/admin/devices/{device_id}/rotate-link")
def rotate_device_link(
    device_id: int,
    request: Request,
    db=Depends(get_db),
    _=Depends(require_admin),
):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "设备不存在")
    friend = db.get(Friend, dev.friend_id)
    raw_token = secrets.token_urlsafe(24)
    now = utcnow()
    dev.device_token_hash = device_token_hash(raw_token)
    dev.fingerprint = dev.device_token_hash[:32]
    dev.identity_source = "device_link"
    dev.device_token_created_at = now
    dev.device_token_revoked_at = None
    db.commit()
    return {
        "ok": True,
        "device": _device_dict(dev, friend.uid if friend else None),
        "links": _device_links(request, friend, raw_token) if friend else {},
        "notice": "旧链接已失效；新链接只在本次响应中返回",
    }


@app.post("/api/admin/devices/{device_id}/revoke-link")
def revoke_device_link(device_id: int, db=Depends(get_db), _=Depends(require_admin)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "设备不存在")
    dev.device_token_revoked_at = utcnow()
    db.commit()
    return {"ok": True}


@app.patch("/api/admin/devices/{device_id}")
def update_device(
    device_id: int,
    payload: dict = Body(...),
    db=Depends(get_db),
    _=Depends(require_admin),
):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "设备不存在")
    for field in ("label", "blocked"):
        if field in payload:
            setattr(dev, field, payload[field])
    db.commit()
    uid = db.scalar(select(Friend.uid).where(Friend.id == dev.friend_id))
    return {"ok": True, "device": _device_dict(dev, uid)}


@app.delete("/api/admin/devices/{device_id}")
def delete_device(device_id: int, db=Depends(get_db), _=Depends(require_admin)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "设备不存在")
    db.delete(dev)
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- stats


@app.get("/api/admin/stats")
def stats(db=Depends(get_db), _=Depends(require_admin)):
    now = utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    total_fetch_24h = db.scalar(
        select(func.count(FetchLog.id)).where(FetchLog.created_at >= day_ago)
    )
    active_devices_24h = db.scalar(
        select(func.count(func.distinct(Device.id))).where(Device.last_seen >= day_ago)
    )

    per_friend = db.execute(
        select(Friend.uid, func.count(FetchLog.id))
        .outerjoin(
            FetchLog,
            (FetchLog.friend_id == Friend.id) & (FetchLog.created_at >= week_ago),
        )
        .group_by(Friend.id, Friend.uid)
        .order_by(Friend.id)
    ).all()

    recent = db.execute(
        select(FetchLog, Friend.uid)
        .join(Friend, FetchLog.friend_id == Friend.id, isouter=True)
        .order_by(FetchLog.created_at.desc())
        .limit(30)
    ).all()

    real_nodes = db.scalars(select(Node).where(Node.is_announcement.is_(False))).all()
    announcement_count = db.scalar(select(func.count(Announcement.id))) or 0

    return {
        "nodes": len(real_nodes),
        "nodes_total": len(real_nodes),
        "announcement_nodes": announcement_count,
        "friends": db.scalar(select(func.count(Friend.id))),
        "devices": db.scalar(select(func.count(Device.id))),
        "fetch_24h": total_fetch_24h,
        "active_devices_24h": active_devices_24h,
        "flow_24h_bytes": sum(
            _friend_usage(db, f.id, day_ago)["bytes_in"]
            + _friend_usage(db, f.id, day_ago)["bytes_out"]
            for f in db.scalars(select(Friend)).all()
        ),
        "collector": _collector_status(db),
        "per_friend_week": [{"uid": u, "fetches": c} for u, c in per_friend],
        "recent": [
            {
                "uid": uid,
                "target": log.target,
                "ip": log.ip,
                "user_agent": (log.user_agent or "")[:60],
                "at": _iso(log.created_at),
            }
            for log, uid in recent
        ],
    }


# ---------------------------------------------------------------- subscription


@app.get("/api/admin/friends/{friend_id}/subscription-diagnostics")
def diagnose_subscription(
    friend_id: int,
    response: Response,
    target: str = "shadowrocket",
    device_id: int | None = None,
    db=Depends(get_db),
    _=Depends(require_admin),
):
    response.headers["Cache-Control"] = "private, no-store"
    friend = db.get(Friend, friend_id)
    if friend is None:
        raise HTTPException(404, "用户不存在")
    target = target.lower()
    if target not in TARGETS:
        raise HTTPException(400, "不支持的订阅格式")
    try:
        with db.no_autoflush:
            return subscription_diagnostics(
                db, friend, target, device_id, per_user_feature_enabled()
            )
    except LookupError:
        raise HTTPException(404, "该用户没有此设备记录")


def _announcement_uri(name: str) -> str:
    return announcement_uri(name)


@app.get("/sub/{token}")
def subscription(
    token: str,
    request: Request,
    target: str = "v2ray",
    device: str | None = None,
    db=Depends(get_db),
):
    friend = db.scalar(select(Friend).where(Friend.token == token))
    if not friend or not friend.enabled:
        raise HTTPException(404, "订阅不存在或已停用")

    if _is_expired(friend.expires_at):
        raise HTTPException(403, "用户订阅已到期，请联系管理员续期")

    if flow_limit_reached(db, friend):
        raise HTTPException(403, "用户可计量流量配额已用完")

    supplied_device = (device or "").strip()
    ua = request.headers.get("user-agent", "")[:250]
    ip = client_ip(request)
    device_link = None
    if supplied_device:
        device_link = db.scalar(
            select(Device).where(
                Device.friend_id == friend.id,
                Device.device_token_hash == device_token_hash(supplied_device),
            )
        )
        if device_link is None and not _is_legacy_device_value(supplied_device):
            raise HTTPException(404, "设备订阅链接无效")
    fp = (
        device_link.fingerprint
        if device_link
        else fingerprint_of(request, supplied_device or None)
    )
    dev = device_link or db.scalar(
        select(Device).where(Device.friend_id == friend.id, Device.fingerprint == fp)
    )
    if dev is None:
        existing = db.scalar(
            select(func.count(Device.id)).where(Device.friend_id == friend.id)
        )
        if friend.device_limit and existing >= friend.device_limit:
            raise HTTPException(
                403,
                "设备数已达上限；网络或客户端变化可能被识别为新设备。"
                "请管理员在设备页将对应旧记录转为专属链接，再导入客户端，无需删除历史。",
                headers={"x-sub-app-error-code": "device_limit_reached"},
            )
        dev = Device(
            friend_id=friend.id,
            fingerprint=fp,
            identity_source="legacy_ua_ip",
            user_agent=ua,
            last_ip=ip,
            fetch_count=0,
        )
        db.add(dev)
        db.flush()

    if device_link and device_link.device_token_revoked_at is not None:
        raise HTTPException(403, "该设备链接已撤销")

    if dev.blocked:
        raise HTTPException(403, "该设备已被停用")

    dev.user_agent = ua
    dev.last_ip = ip
    dev.last_seen = utcnow()
    dev.fetch_count += 1

    fetch_log = FetchLog(
        friend_id=friend.id, device_id=dev.id, target=target, ip=ip, user_agent=ua
    )
    db.add(fetch_log)

    plan = build_subscription_plan(db, friend, per_user_feature_enabled())
    uris = plan.uris
    skipped_nodes = plan.skipped_nodes
    shared_fallback_nodes = []
    expired_nodes = plan.expired_nodes
    fetch_log.shared_fallback_count = len(shared_fallback_nodes)
    fetch_log.skipped_node_count = len(skipped_nodes)
    fetch_log.expired_node_count = len(expired_nodes)
    db.commit()

    if not uris:
        if skipped_nodes:
            raise HTTPException(
                503,
                "独立凭据节点尚未同步完成，已安全跳过；请等待适配器恢复并同步，或联系管理员",
            )
        raise HTTPException(404, "尚未分配任何节点")

    try:
        body, content_type = render(uris, target)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    headers = {
        "cache-control": "private, no-store",
        "pragma": "no-cache",
        "profile-update-interval": "12",
        "x-sub-app-skipped-nodes": str(len(skipped_nodes)),
        "x-sub-app-shared-fallback-nodes": str(len(shared_fallback_nodes)),
        "x-sub-app-expired-nodes": str(len(expired_nodes)),
        "content-disposition": (
            f'attachment; filename="{friend.uid}.yaml"'
            if target.startswith("clash") or target == "mihomo"
            else f'attachment; filename="{friend.uid}.txt"'
        ),
    }
    return PlainTextResponse(body, media_type=content_type, headers=headers)


# ---------------------------------------------------------------- frontend

STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    # index.html has no Cache-Control by default, so a plain (non-hard)
    # refresh can serve a browser-cached copy pointing at an old, already
    # replaced build's hashed asset filenames — defeating the whole point of
    # content-hashed assets, which rely on index.html itself always being
    # revalidated. no-cache still allows a cheap 304 via Last-Modified; it
    # just stops the browser from skipping that check.
    return FileResponse(
        str(STATIC_DIR / "index.html"), headers={"Cache-Control": "no-cache"}
    )


def _healthz_details(db) -> dict:
    """Return operational details for authenticated administrators only."""

    adapters = adapter_marker()
    proxy_status = {}
    status_path = Path(
        os.environ.get(
            "SUB_APP_PROXY_STATUS", "/var/lib/sub-app/proxy-collector-status.json"
        )
    )
    try:
        proxy_status = _with_status_freshness(
            json.loads(status_path.read_text(encoding="utf-8"))
        )
    except (FileNotFoundError, ValueError):
        proxy_status = _with_status_freshness({"status": "never_run"})
    collector_state = _collector_status(db)
    return {
        "ok": True,
        "generated_at": _iso(utcnow()),
        "database": "ok",
        "collector": collector_state,
        "proxy_collector": proxy_status,
        "reconciler": collector_state.get("reconciler", {"status": "never_run"}),
        "agents": agent_health_summary(db),
        "adapters": {
            "hysteria2": adapters.get("HY2_HTTP_AUTH") == "1",
            "vless": adapters.get("VLESS_V2RAY_API") == "1",
        },
    }


@app.get("/healthz")
def healthz():
    """Expose only liveness publicly; operational details require admin auth."""

    db = Session()
    try:
        db.execute(select(1))
        return {"ok": True, "generated_at": _iso(utcnow())}
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "generated_at": utcnow().isoformat()},
        )
    finally:
        db.close()


@app.get("/api/admin/healthz")
def admin_healthz(db=Depends(get_db), _=Depends(require_admin)):
    """Return the detailed health snapshot to authenticated administrators."""

    return _healthz_details(db)


@app.get("/api/admin/audit-logs")
def admin_audit_logs(limit: int = 100, db=Depends(get_db), _=Depends(require_admin)):
    if not 1 <= limit <= 250:
        raise HTTPException(400, "limit 必须在 1 到 250 之间")
    rows = db.scalars(
        select(AdminAuditLog)
        .order_by(AdminAuditLog.created_at.desc(), AdminAuditLog.id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "actor_fingerprint": row.actor_fingerprint,
            "method": row.method,
            "path": row.path,
            "status_code": row.status_code,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


# ---------------------------------------------------------------- node agents

from app.agent_api import agent_health_summary, register_agent_routes  # noqa: E402

register_agent_routes(app, Session, get_db, require_admin)
