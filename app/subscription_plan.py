"""Read-only subscription selection shared by delivery and administrator diagnostics.

The internal plan contains credential-bearing URIs. Only explicitly selected
metadata may cross the diagnostics API boundary; never serialize the plan.
"""

from dataclasses import dataclass, field
from urllib.parse import quote

from sqlalchemy import select

from app.account_policy import is_expired
from app.converter import uri_with_name
from app.credentials import render_credential_uri
from app.models import (
    Allocation,
    Announcement,
    AnnouncementAllocation,
    Node,
    UserNodeCredential,
    utc_iso,
)
from app.node_policy import is_real_node
from app.proxy_adapters import adapter_info, node_per_user_enabled


def announcement_uri(name):
    return (
        "vless://00000000-0000-0000-0000-000000000000"
        f"@127.0.0.1:1?encryption=none#{quote(name, safe='')}"
    )


@dataclass(repr=False)
class SubscriptionPlan:
    uris: list[str] = field(default_factory=list)
    nodes: list[dict] = field(default_factory=list)
    node_uris: dict[int, str] = field(default_factory=dict)
    skipped_nodes: list[int] = field(default_factory=list)
    expired_nodes: list[int] = field(default_factory=list)
    announcement_count: int = 0


def build_subscription_plan(db, friend, feature_enabled: bool) -> SubscriptionPlan:
    """Select exactly the material delivered to an admitted device; never write."""
    plan = SubscriptionPlan()
    nodes = db.scalars(
        select(Node)
        .join(Allocation, Allocation.node_id == Node.id)
        .where(Allocation.friend_id == friend.id)
        .order_by(Node.sort_order, Node.id)
    ).all()
    announcements = db.scalars(
        select(Announcement)
        .join(
            AnnouncementAllocation,
            AnnouncementAllocation.announcement_id == Announcement.id,
        )
        .where(
            AnnouncementAllocation.friend_id == friend.id,
            Announcement.enabled.is_(True),
        )
    ).all()
    items = []
    for node in nodes:
        if not is_real_node(node):
            continue
        metadata = {
            "node_id": node.id,
            "name": node.name,
            "protocol": node.protocol,
            "included": False,
            "code": "disabled",
            "message": "节点已停用",
            "credential_status": None,
            "credential_synced_at": None,
        }
        plan.nodes.append(metadata)
        if not node.enabled:
            continue
        if is_expired(node.expires_at):
            plan.expired_nodes.append(node.id)
            metadata.update(code="expired", message="节点已到期")
            continue
        use_per_user = (
            friend.per_user_credentials
            and feature_enabled
            and adapter_info(node)
            and node_per_user_enabled(node)
        )
        if use_per_user:
            row = db.scalar(
                select(UserNodeCredential)
                .where(
                    UserNodeCredential.friend_id == friend.id,
                    UserNodeCredential.node_id == node.id,
                    UserNodeCredential.protocol == node.protocol,
                    UserNodeCredential.revoked_at.is_(None),
                    UserNodeCredential.status == "active",
                )
                .order_by(UserNodeCredential.version.desc())
                .limit(1)
            )
            if row is None:
                plan.skipped_nodes.append(node.id)
                metadata.update(
                    code="credential_unavailable", message="没有匹配协议的已生效凭据"
                )
                continue
            metadata.update(
                credential_status=row.status,
                credential_synced_at=utc_iso(row.last_synced_at),
            )
            try:
                uri = render_credential_uri(node, row)
            except ValueError:
                plan.skipped_nodes.append(node.id)
                metadata.update(
                    code="credential_invalid",
                    message="凭据与节点信息不一致，已安全跳过",
                )
                continue
        else:
            uri = uri_with_name(node.uri, node.name)
        metadata.update(
            included=True,
            code="per_user" if use_per_user else "shared",
            message="使用已生效独立凭据" if use_per_user else "使用共享节点链接",
        )
        plan.node_uris[node.id] = uri
        items.append(((node.sort_order, node.id, 0), uri))
    for announcement in announcements:
        plan.announcement_count += 1
        items.append(
            (
                (
                    announcement.sort_order,
                    announcement.legacy_node_id or announcement.id,
                    1,
                ),
                announcement_uri(announcement.name),
            )
        )
    plan.uris = [uri for _, uri in sorted(items, key=lambda item: item[0])]
    return plan
