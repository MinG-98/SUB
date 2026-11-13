"""Credential-free, non-mutating administrator subscription diagnostics."""

from sqlalchemy import select

from app.account_policy import _utc_naive, is_expired
from app.converter import parse_uri, render, to_clash_proxy
from app.models import Device, Node, NodeAgent, utc_iso, utcnow
from app.quota import flow_limit_reached
from app.subscription_plan import build_subscription_plan

TARGETS = {"clash", "clashmeta", "mihomo", "shadowrocket", "v2ray", "base64", "raw"}


def _decision(allowed, code, message):
    return {"allowed": allowed, "code": code, "message": message}


def _agent_state(agent):
    if agent is None:
        return {"state": "unregistered", "generation_matches": None}
    age = (
        (_utc_naive(utcnow()) - _utc_naive(agent.last_seen)).total_seconds()
        if agent.last_seen
        else None
    )
    fresh = age is not None and 0 <= age <= 180
    return {
        "state": (
            "stale" if not fresh else "error" if agent.status == "error" else "online"
        ),
        # Equality is a reported configuration claim, not proof of connectivity.
        "generation_matches": bool(
            fresh
            and agent.status == "ready"
            and agent.desired_generation
            and agent.desired_generation == agent.applied_generation
        ),
    }


def subscription_diagnostics(db, friend, target, device_id, feature_enabled):
    """Simulate admission for a new device or a selected existing record.

    Selecting a row does not prove possession of its bearer token or reproduce
    the IP/UA fingerprint of an unknown request. No network probes are run.
    """
    devices = db.scalars(
        select(Device).where(Device.friend_id == friend.id).order_by(Device.id)
    ).all()
    selected = next((d for d in devices if d.id == device_id), None)
    if device_id is not None and selected is None:
        raise LookupError("该用户没有此设备记录")
    account = _decision(True, "allowed", "账户允许刷新订阅")
    account_status = 200
    if not friend.enabled:
        account = _decision(False, "disabled", "用户已停用")
        account_status = 404
    elif is_expired(friend.expires_at):
        account = _decision(False, "expired", "用户订阅已到期")
        account_status = 403
    elif flow_limit_reached(db, friend):
        account = _decision(False, "quota_exceeded", "可计量流量配额已用完")
        account_status = 403

    device = _decision(True, "allowed", "新设备可准入，但本次不会创建记录")
    if selected:
        device = _decision(
            True, "allowed", "此记录可准入；须使用匹配的指纹或有效专属链接"
        )
        if (
            friend.device_credentials_mode == "required"
            and not selected.device_token_hash
        ):
            device = _decision(
                False, "device_link_required", "严格设备模式要求使用登记设备的专属链接"
            )
        elif (
            selected.device_token_hash and selected.device_token_revoked_at is not None
        ):
            device = _decision(False, "link_revoked", "该记录的专属链接已撤销")
        elif selected.blocked:
            device = _decision(False, "blocked", "设备已停用")
    elif friend.device_credentials_mode == "required":
        device = _decision(
            False, "device_link_required", "严格设备模式不允许未登记设备刷新"
        )
    elif friend.device_limit and len(devices) >= friend.device_limit:
        device = _decision(
            False,
            "device_limit_reached",
            "新设备将被拒绝；可在设备页将对应旧记录转为专属链接，无需删除历史",
        )
    device.update(
        scenario="existing_record" if selected else "new_device",
        selected_id=device_id,
        count=len(devices),
        limit=friend.device_limit,
    )

    plan = build_subscription_plan(
        db,
        friend,
        feature_enabled,
        device_id=(
            selected.id
            if selected
            and selected.device_token_hash
            and selected.device_token_revoked_at is None
            and not selected.blocked
            else None
        ),
    )
    agents = {
        row.node_id: row
        for row in db.scalars(
            select(NodeAgent).where(
                NodeAgent.node_id.in_([n["node_id"] for n in plan.nodes])
            )
        ).all()
    }
    managed_ids = set(
        db.scalars(
            select(Node.id).where(
                Node.id.in_([n["node_id"] for n in plan.nodes]),
                Node.adapter_kind == "remote_agent",
            )
        ).all()
    )
    rendered_count = 0
    render_ok = True
    try:
        # Exercise the same renderer without returning or persisting its output.
        render(plan.uris, target)
        for node in plan.nodes:
            uri = plan.node_uris.get(node["node_id"])
            if uri is None:
                continue
            if target in {"clash", "clashmeta", "mihomo"}:
                parsed = parse_uri(uri)
                if not parsed or not to_clash_proxy(parsed):
                    node.update(
                        included=False,
                        code="format_unsupported",
                        message="该链接无法转换为所选格式，会被转换器省略",
                    )
                    continue
            rendered_count += 1
    except ValueError:
        render_ok = False
    status, code = 200, "ready"
    if not account["allowed"]:
        status, code = account_status, account["code"]
    elif not device["allowed"]:
        status, code = 403, device["code"]
    elif not plan.uris:
        status, code = (
            (503, "credentials_unavailable")
            if plan.skipped_nodes
            else (404, "no_nodes")
        )
    elif not render_ok:
        status, code = 400, "render_error"
    elif rendered_count == 0:
        code = "no_proxy_nodes"
    elif plan.skipped_nodes or plan.expired_nodes:
        code = "partial"
    for node in plan.nodes:
        node["agent"] = (
            _agent_state(agents.get(node["node_id"]))
            if node["node_id"] in managed_ids
            else {"state": "not_managed", "generation_matches": None}
        )
    return {
        "friend_id": friend.id,
        "uid": friend.uid,
        "generated_at": utc_iso(utcnow()),
        "target": target,
        "account": account,
        "device": device,
        "devices": [
            {
                "id": row.id,
                "label": row.label or f"设备 #{row.id}",
                "identity_source": row.identity_source,
                "blocked": row.blocked,
                "link_revoked": bool(row.device_token_revoked_at),
            }
            for row in devices
        ],
        "subscription": {
            "http_status": status,
            "code": code,
            "assigned_count": len(plan.nodes),
            "eligible_count": len(plan.node_uris),
            "rendered_count": rendered_count if render_ok else 0,
            "announcement_count": plan.announcement_count,
        },
        "nodes": plan.nodes,
        "notice": "只读模拟，不新增设备、不记录拉取、不返回凭证。节点数量是在准入后计算；"
        "所选设备记录不证明链接持有权，Agent 自报版本一致也不代表外部代理验证通过。",
    }
