"""Safe, deterministic per-user credential material for the rollout phase."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from urllib.parse import quote, urlsplit, urlunsplit

from sqlalchemy import select

from app.models import Friend, Node, UserNodeCredential, utc_iso, utcnow


def per_user_feature_enabled() -> bool:
    return os.environ.get("SUB_APP_PER_USER_CREDENTIALS", "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _key_material() -> bytes:
    secret = os.environ.get("SUB_APP_SECRET", "")
    if not secret:
        raise RuntimeError("SUB_APP_SECRET is required for credential derivation")
    return secret.encode("utf-8")


def _digest(friend_id: int, node_id: int, protocol: str, version: int) -> bytes:
    message = f"sub-app-credential:v1:{friend_id}:{node_id}:{protocol}:{version}"
    return hmac.new(_key_material(), message.encode("utf-8"), hashlib.sha256).digest()


def deny_all_uuid(node_id: int) -> str:
    """Return a stable, secret-derived VLESS UUID for an unadvertised deny-all user."""

    message = f"sub-app-deny-all:v1:{int(node_id)}".encode("utf-8")
    raw = bytearray(hmac.new(_key_material(), message, hashlib.sha256).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def credential_values(row: UserNodeCredential) -> dict[str, str]:
    digest = _digest(row.friend_id, row.node_id, row.protocol, row.version)
    password = base64.urlsafe_b64encode(digest[16:]).decode().rstrip("=")
    if row.protocol == "vless":
        return {"uuid": str(uuid.UUID(bytes=digest[:16]))}
    if row.protocol == "hysteria2":
        return {"username": row.credential_name, "password": password}
    raise ValueError(f"unsupported per-user protocol: {row.protocol}")


def credential_stats_id(row: UserNodeCredential) -> str:
    """Stable internal ID returned to a proxy stats backend."""
    return f"f{row.friend_id}n{row.node_id}v{row.version}"


def ensure_credential(db, friend: Friend, node: Node) -> UserNodeCredential:
    row = db.scalar(
        select(UserNodeCredential)
        .where(
            UserNodeCredential.friend_id == friend.id,
            UserNodeCredential.node_id == node.id,
            UserNodeCredential.protocol == node.protocol,
        )
        .order_by(UserNodeCredential.version.desc())
        .limit(1)
    )
    if row is not None and row.revoked_at is None:
        return row
    next_version = (row.version + 1) if row is not None else 1
    row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=node.protocol,
        credential_name=f"u{friend.id}n{node.id}",
        version=next_version,
        status="pending",
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _host_port(parts):
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{parts.port}" if parts.port else host


def render_credential_uri(node: Node, row: UserNodeCredential) -> str:
    values = credential_values(row)
    parts = urlsplit(node.uri)
    host_port = _host_port(parts)
    if row.protocol == "vless":
        netloc = f"{quote(values['uuid'])}@{host_port}"
    elif row.protocol == "hysteria2":
        netloc = f"{quote(values['username'])}:{quote(values['password'])}@{host_port}"
    else:
        raise ValueError(f"unsupported per-user protocol: {row.protocol}")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def credential_public_dict(row: UserNodeCredential) -> dict:
    return {
        "id": row.id,
        "friend_id": row.friend_id,
        "node_id": row.node_id,
        "protocol": row.protocol,
        "credential_name": row.credential_name,
        "version": row.version,
        "status": row.status,
        "created_at": utc_iso(row.created_at),
        "rotated_at": utc_iso(row.rotated_at),
        "revoked_at": utc_iso(row.revoked_at),
        "grace_until": utc_iso(row.grace_until),
        "last_synced_at": utc_iso(row.last_synced_at),
        "last_error": row.last_error or "",
    }
