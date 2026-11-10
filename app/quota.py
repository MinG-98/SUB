"""Shared helpers for user-attributed traffic and quota enforcement."""

from __future__ import annotations

from sqlalchemy import func, select

from app.account_policy import is_expired
from app.credentials import credential_stats_id
from app.models import FlowRecord, Friend, Node, UserNodeCredential


def friend_usage(db, friend_id: int, since=None) -> dict[str, int]:
    query = select(
        func.coalesce(func.sum(FlowRecord.bytes_in), 0),
        func.coalesce(func.sum(FlowRecord.bytes_out), 0),
    ).where(
        FlowRecord.friend_id == friend_id,
        FlowRecord.source != "nezha",
    )
    if since is not None:
        query = query.where(FlowRecord.bucket >= since)
    bytes_in, bytes_out = db.execute(query).one()
    return {"bytes_in": int(bytes_in or 0), "bytes_out": int(bytes_out or 0)}


def flow_limit_reached(db, friend) -> bool:
    """Whether observed, user-attributed traffic has reached the configured cap."""
    limit_gb = int(friend.flow_limit_gb or 0)
    if limit_gb <= 0:
        return False
    usage = friend_usage(db, friend.id)
    return usage["bytes_in"] + usage["bytes_out"] >= limit_gb * 1024**3


def quota_exceeded_stats_ids(db, node_id: int, protocol: str) -> list[str]:
    """Return this node's credential IDs for enabled users already over quota.

    Include old credential versions too: a proxy session authenticated before
    rotation/revocation can remain alive until the proxy explicitly disconnects
    it. The proxy still receives only IDs belonging to this node and protocol.
    """
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == protocol,
            Friend.enabled.is_(True),
            Friend.per_user_credentials.is_(True),
        )
    ).all()
    ids = {
        credential_stats_id(row)
        for row, friend in rows
        if flow_limit_reached(db, friend)
    }
    return sorted(ids)


def credential_kick_stats_ids(db, node_id: int, protocol: str) -> list[str]:
    """Return every credential on this node that must no longer stay connected."""

    node = db.get(Node, node_id)
    node_expired = node is None or is_expired(node.expires_at)
    node_disabled = node is None or not node.enabled
    shared_mode = bool(
        node is not None
        and node.adapter_kind == "remote_agent"
        and not node.per_user_enabled
    )
    rows = db.execute(
        select(UserNodeCredential, Friend)
        .join(Friend, Friend.id == UserNodeCredential.friend_id)
        .where(
            UserNodeCredential.node_id == node_id,
            UserNodeCredential.protocol == protocol,
        )
    ).all()
    ids = set()
    for row, friend in rows:
        grace_expired = row.status == "grace" and (
            row.grace_until is None or is_expired(row.grace_until)
        )
        invalid = (
            node_expired
            or node_disabled
            or shared_mode
            or row.revoked_at is not None
            or not friend.enabled
            or not friend.per_user_credentials
            or is_expired(friend.expires_at)
            or row.status not in {"active", "grace"}
            or grace_expired
            or flow_limit_reached(db, friend)
        )
        if invalid:
            ids.add(credential_stats_id(row))
    if protocol == "hysteria2" and (node_expired or node_disabled):
        ids.add("legacy-shared")
    return sorted(ids)
