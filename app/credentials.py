"""Safe, deterministic per-user credential material for the rollout phase."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from urllib.parse import quote, urlsplit, urlunsplit

from sqlalchemy import func, select

from app.converter import parse_uri, uri_with_name
from app.models import Device, Friend, Node, UserNodeCredential, utc_iso, utcnow


def per_user_feature_enabled() -> bool:
    return os.environ.get("SUB_APP_PER_USER_CREDENTIALS", "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def credential_scope_is_allowed(
    row: UserNodeCredential, friend: Friend | None = None
) -> bool:
    """Whether this row belongs in the currently selected auth mode."""
    friend = friend or row.friend
    mode = getattr(friend, "device_credentials_mode", "off") or "off"
    if row.device_id is None:
        return mode in {"off", "preparing", "restoring"}
    device = row.device
    return bool(
        mode in {"preparing", "required", "restoring"}
        and device is not None
        and device.device_token_hash
        and device.device_token_revoked_at is None
        and not device.blocked
    )


def _key_material() -> bytes:
    secret = os.environ.get("SUB_APP_SECRET", "")
    if not secret:
        raise RuntimeError("SUB_APP_SECRET is required for credential derivation")
    return secret.encode("utf-8")


def _digest(
    friend_id: int,
    node_id: int,
    protocol: str,
    version: int,
    device_scope: str | None = None,
) -> bytes:
    if device_scope:
        message = (
            f"sub-app-device-credential:v1:{friend_id}:{device_scope}:"
            f"{node_id}:{protocol}:{version}"
        )
    else:
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
    device_scope = None
    if row.device_id is not None:
        device = row.device
        if device is None or not device.credential_scope:
            raise ValueError("device-scoped credential has no stable device scope")
        device_scope = device.credential_scope
    digest = _digest(
        row.friend_id, row.node_id, row.protocol, row.version, device_scope
    )
    password = base64.urlsafe_b64encode(digest[16:]).decode().rstrip("=")
    if row.protocol == "vless":
        return {"uuid": str(uuid.UUID(bytes=digest[:16]))}
    if row.protocol == "hysteria2":
        return {"username": row.credential_name, "password": password}
    raise ValueError(f"unsupported per-user protocol: {row.protocol}")


def credential_stats_id(row: UserNodeCredential) -> str:
    """Stable internal ID returned to a proxy stats backend."""
    if row.device_id is not None:
        device = row.device
        if device is None or not device.credential_scope:
            raise ValueError("device-scoped credential has no stable device scope")
        scope_tag = hashlib.sha256(device.credential_scope.encode("utf-8")).hexdigest()[
            :12
        ]
        return (
            f"f{row.friend_id}d{row.device_id}-{scope_tag}n{row.node_id}v{row.version}"
        )
    return f"f{row.friend_id}n{row.node_id}v{row.version}"


def ensure_credential(
    db, friend: Friend, node: Node, device: Device | int | None = None
) -> UserNodeCredential:
    device_id = device.id if isinstance(device, Device) else device
    scope_query = select(UserNodeCredential).where(
        UserNodeCredential.friend_id == friend.id,
        UserNodeCredential.node_id == node.id,
        UserNodeCredential.protocol == node.protocol,
    )
    scope_query = scope_query.where(
        UserNodeCredential.device_id.is_(None)
        if device_id is None
        else UserNodeCredential.device_id == device_id
    )
    row = db.scalar(scope_query.order_by(UserNodeCredential.version.desc()).limit(1))
    if row is not None and row.revoked_at is None:
        return row
    latest_version = (
        db.scalar(
            select(func.max(UserNodeCredential.version)).where(
                UserNodeCredential.friend_id == friend.id,
                UserNodeCredential.node_id == node.id,
                UserNodeCredential.protocol == node.protocol,
            )
        )
        or 0
    )
    next_version = latest_version + 1
    device_label = f"d{device_id}" if device_id is not None else ""
    row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        device_id=device_id,
        protocol=node.protocol,
        credential_name=f"u{friend.id}{device_label}n{node.id}",
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
    parsed = parse_uri(node.uri)
    if (
        row.protocol != node.protocol
        or (node.id is not None and row.node_id != node.id)
        or not parsed
        or parsed["scheme"] != node.protocol
    ):
        raise ValueError("credential and node protocol/identity mismatch")
    values = credential_values(row)
    parts = urlsplit(node.uri)
    host_port = _host_port(parts)
    if row.protocol == "vless":
        netloc = f"{quote(values['uuid'])}@{host_port}"
    elif row.protocol == "hysteria2":
        netloc = f"{quote(values['username'])}:{quote(values['password'])}@{host_port}"
    else:
        raise ValueError(f"unsupported per-user protocol: {row.protocol}")
    return uri_with_name(
        urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)),
        node.name,
    )


def credential_public_dict(row: UserNodeCredential) -> dict:
    return {
        "id": row.id,
        "friend_id": row.friend_id,
        "device_id": row.device_id,
        "device_label": row.device.label if row.device_id and row.device else None,
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
