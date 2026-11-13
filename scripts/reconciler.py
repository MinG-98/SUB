#!/usr/bin/env python3
"""Reconcile user allocations with the local US proxy adapters.

The admin UI/API is the desired-state writer.  This bounded agent is the
eventual-consistency and retry loop, so adding a user or checking a node does
not require a manual server operation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.account_policy import is_expired  # noqa: E402
from app.credentials import ensure_credential  # noqa: E402
from app.models import (  # noqa: E402
    Allocation,
    Device,
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
    utcnow,
)
from app.proxy_adapters import (  # noqa: E402
    activate_credential,
    adapter_info,
    adapter_ready,
    is_local_vless,
    node_per_user_enabled,
    sync_vless_config,
)
from app.quota import flow_limit_reached  # noqa: E402

STATUS_PATH = Path(
    os.environ.get(
        "SUB_APP_RECONCILER_STATUS", "/var/lib/sub-app/reconciler-status.json"
    )
)


def reconcile(db):
    activated = 0
    errors = 0
    revoked = 0
    vless_rows_to_sync = []
    vless_rows_to_revoke = []
    friends = db.scalars(select(Friend).order_by(Friend.id)).all()
    for friend in friends:
        allocations = db.scalars(
            select(Allocation).where(Allocation.friend_id == friend.id)
        ).all()
        wanted = {item.node_id for item in allocations}
        rows = db.scalars(
            select(UserNodeCredential).where(UserNodeCredential.friend_id == friend.id)
        ).all()
        if (
            not friend.enabled
            or not friend.per_user_credentials
            or is_expired(friend.expires_at)
            or flow_limit_reached(db, friend)
        ):
            for row in rows:
                if row.revoked_at is not None:
                    continue
                row.status = "revoked"
                row.revoked_at = utcnow()
                row.grace_until = None
                revoked_node = db.get(Node, row.node_id)
                if revoked_node and is_local_vless(revoked_node):
                    vless_rows_to_revoke.append(row)
                revoked += 1
            continue

        mode = friend.device_credentials_mode or "off"
        if mode not in {"off", "preparing", "required", "restoring"}:
            mode = "off"
        global_modes = {"off", "preparing", "restoring"}
        device_modes = {"preparing", "required", "restoring"}
        active_devices = []
        if mode in device_modes:
            active_devices = db.scalars(
                select(Device).where(
                    Device.friend_id == friend.id,
                    Device.device_token_hash.is_not(None),
                    Device.device_token_revoked_at.is_(None),
                    Device.blocked.is_(False),
                )
            ).all()
        wanted_scopes = set()
        for node_id in wanted:
            node = db.get(Node, node_id)
            if (
                not node
                or not node.enabled
                or is_expired(node.expires_at)
                or not adapter_info(node)
                or not node_per_user_enabled(node)
            ):
                for row in rows:
                    if row.node_id == node_id and row.revoked_at is None:
                        row.status = "revoked"
                        row.revoked_at = utcnow()
                        row.grace_until = None
                        if is_local_vless(node):
                            vless_rows_to_revoke.append(row)
                        revoked += 1
                continue
            scopes = []
            if mode in global_modes:
                scopes.append(None)
            if mode in device_modes:
                scopes.extend(device.id for device in active_devices)
            for device_id in scopes:
                device = db.get(Device, device_id) if device_id is not None else None
                row = ensure_credential(db, friend, node, device=device)
                wanted_scopes.add((node_id, device_id))
                if row.status in {"active", "grace"} and row.revoked_at is None:
                    continue
                if is_local_vless(node):
                    if not adapter_ready(node, db):
                        row.status = "error"
                        row.last_error = "VLESS V2Ray API 适配器未就绪"
                        row.last_synced_at = None
                        errors += 1
                        continue
                    row.status = "active"
                    row.last_error = ""
                    row.last_synced_at = None
                    vless_rows_to_sync.append(row)
                else:
                    activate_credential(db, row)
                    if row.status == "active":
                        activated += 1
                    else:
                        errors += 1

        for row in rows:
            allocated_node = db.get(Node, row.node_id)
            if (
                (row.node_id, row.device_id) not in wanted_scopes
                or not allocated_node
                or not allocated_node.enabled
                or is_expired(allocated_node.expires_at)
                or not node_per_user_enabled(allocated_node)
            ) and row.revoked_at is None:
                row.status = "revoked"
                row.revoked_at = utcnow()
                row.grace_until = None
                if allocated_node and is_local_vless(allocated_node):
                    vless_rows_to_revoke.append(row)
                revoked += 1
    local_vless = db.scalar(
        select(Node).where(Node.adapter_kind == "local_vless", Node.protocol == "vless")
    )
    if local_vless:
        try:
            # The adapter's applied-generation marker makes this idempotent
            # and lets every timer pass retry a failed apply.
            db.flush()
            sync_vless_config(db, node=local_vless)
            synced_at = utcnow()
            for row in vless_rows_to_sync:
                row.last_synced_at = synced_at
                activated += 1
        except Exception as exc:
            errors += 1
            message = str(exc)[:1000] or "VLESS 配置同步失败"
            for row in vless_rows_to_sync:
                row.status = "error"
                row.last_error = message
            for row in vless_rows_to_revoke:
                row.last_error = (
                    f"VLESS 配置同步失败，已撤销凭据可能仍在代理中：{message}"
                )
    db.commit()
    return {"activated": activated, "errors": errors, "revoked": revoked}


def write_status(payload):
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix="reconciler.", suffix=".json", dir=str(STATUS_PATH.parent)
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
    db_path = os.environ.get("SUB_APP_DB", str(ROOT / "data.db"))
    factory = make_session_factory(db_path)
    db = factory()
    started = datetime.now(timezone.utc)
    try:
        result = reconcile(db)
        status = "success" if result["errors"] == 0 else "partial"
        payload = {"status": status, "at": started.isoformat(), **result}
        write_status(payload)
        print(json.dumps({"ok": True, **payload}, ensure_ascii=True))
    except Exception as exc:
        db.rollback()
        payload = {
            "status": "error",
            "at": started.isoformat(),
            "error": type(exc).__name__,
        }
        write_status(payload)
        print(json.dumps({"ok": False, **payload}, ensure_ascii=True))
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
