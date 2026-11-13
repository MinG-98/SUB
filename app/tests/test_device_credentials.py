from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select

from app import agent_api
from app.credentials import (
    credential_stats_id,
    credential_values,
    ensure_credential,
)
from app.models import (
    Allocation,
    Device,
    FlowRecord,
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
    migrate_database,
)
from app.subscription_plan import build_subscription_plan


@pytest.fixture
def db_factory():
    factory = make_session_factory(":memory:")
    yield factory
    factory.kw["bind"].dispose()


def test_v17_migration_preserves_legacy_credentials_and_assigns_device_scopes():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (16, 'test')"
            )
            conn.exec_driver_sql("CREATE TABLE friends (id INTEGER PRIMARY KEY)")
            conn.exec_driver_sql(
                "CREATE TABLE devices (id INTEGER PRIMARY KEY, friend_id INTEGER, "
                "fingerprint TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "CREATE TABLE user_node_credentials (id INTEGER PRIMARY KEY, "
                "friend_id INTEGER NOT NULL, node_id INTEGER NOT NULL, "
                "protocol TEXT NOT NULL, credential_name TEXT NOT NULL, "
                "version INTEGER NOT NULL, status TEXT NOT NULL)"
            )
            conn.exec_driver_sql("INSERT INTO friends(id) VALUES (1)")
            conn.exec_driver_sql(
                "INSERT INTO devices(id, friend_id, fingerprint) "
                "VALUES (9, 1, 'legacy-fingerprint')"
            )
            conn.exec_driver_sql(
                "INSERT INTO user_node_credentials "
                "(id, friend_id, node_id, protocol, credential_name, version, status) "
                "VALUES (4, 1, 2, 'vless', 'legacy-user', 1, 'active')"
            )

        migrate_database(engine)
        migrate_database(engine)
        with engine.connect() as conn:
            assert (
                conn.exec_driver_sql(
                    "SELECT device_credentials_mode FROM friends WHERE id=1"
                ).scalar_one()
                == "off"
            )
            scope = conn.exec_driver_sql(
                "SELECT credential_scope FROM devices WHERE id=9"
            ).scalar_one()
            assert len(scope) == 48
            assert (
                conn.exec_driver_sql(
                    "SELECT device_id FROM user_node_credentials WHERE id=4"
                ).scalar_one()
                is None
            )
            assert (
                conn.exec_driver_sql(
                    "SELECT MAX(version) FROM schema_migrations"
                ).scalar_one()
                == 17
            )
    finally:
        engine.dispose()


def test_device_credentials_are_distinct_and_keep_legacy_derivation(
    db_factory, monkeypatch
):
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-credential-secret")
    db = db_factory()
    friend = Friend(
        uid="scope-test", token="scope-test-token", per_user_credentials=True
    )
    node = Node(
        name="test-hy2",
        protocol="hysteria2",
        adapter_kind="local_hy2",
        uri="hysteria2://shared:password@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    first = Device(friend_id=friend.id, fingerprint="device-one")
    second = Device(friend_id=friend.id, fingerprint="device-two")
    db.add_all([first, second])
    db.flush()

    legacy = ensure_credential(db, friend, node)
    first_row = ensure_credential(db, friend, node, first)
    second_row = ensure_credential(db, friend, node, second)
    db.flush()

    assert first_row.version != second_row.version
    legacy_values = credential_values(legacy)
    assert credential_values(first_row) != credential_values(second_row)
    assert credential_values(first_row) != legacy_values
    assert credential_stats_id(first_row) != credential_stats_id(second_row)
    assert credential_stats_id(legacy) == f"f{friend.id}n{node.id}v{legacy.version}"


def test_desired_agent_users_only_expose_the_selected_device_mode(
    db_factory, monkeypatch
):
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-agent-secret")
    db = db_factory()
    friend = Friend(
        uid="agent-device-test",
        token="agent-device-token",
        per_user_credentials=True,
        device_credentials_mode="required",
    )
    node = Node(
        name="remote-hy2",
        protocol="hysteria2",
        adapter_kind="remote_agent",
        per_user_enabled=True,
        uri="hysteria2://shared:password@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="device-token-id",
        device_token_hash="a" * 64,
    )
    db.add(device)
    db.flush()
    global_row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=node.protocol,
        credential_name="account-credential",
        version=1,
        status="active",
    )
    device_row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        device_id=device.id,
        protocol=node.protocol,
        credential_name="device-credential",
        version=2,
        status="active",
    )
    db.add_all([global_row, device_row])
    db.commit()

    assert [
        item["credential_id"] for item in agent_api._desired_users(db, node.id)
    ] == [device_row.id]
    friend.device_credentials_mode = "preparing"
    db.commit()
    assert {
        item["credential_id"] for item in agent_api._desired_users(db, node.id)
    } == {
        global_row.id,
        device_row.id,
    }


def test_device_credential_progress_uses_latest_version_per_scope(
    db_factory, monkeypatch
):
    monkeypatch.setenv("SUB_APP_ADMIN_PASSWORD", "test-device-admin")
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-progress-secret")
    from app import main

    db = db_factory()
    friend = Friend(
        uid="progress-device-test",
        token="progress-device-token",
        per_user_credentials=True,
        device_credentials_mode="preparing",
    )
    node = Node(
        name="progress-vless",
        protocol="vless",
        adapter_kind="local_vless",
        uri="vless://00000000-0000-4000-8000-000000000001@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="progress-device",
        device_token_hash="e" * 64,
    )
    db.add(device)
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    db.add_all(
        [
            UserNodeCredential(
                friend_id=friend.id,
                node_id=node.id,
                device_id=device.id,
                protocol="vless",
                credential_name="device-vless",
                version=1,
                status="active",
            ),
            UserNodeCredential(
                friend_id=friend.id,
                node_id=node.id,
                device_id=device.id,
                protocol="vless",
                credential_name="device-vless",
                version=2,
                status="pending",
            ),
        ]
    )
    db.commit()

    progress = main._device_credentials_progress(db, friend)

    assert progress["required_credentials"] == 1
    assert progress["active_credentials"] == 0
    assert progress["ready"] is False


def test_reconcile_batches_local_vless_device_credential_apply(db_factory, monkeypatch):
    monkeypatch.setenv("SUB_APP_ADMIN_PASSWORD", "test-device-admin")
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-batch-secret")
    from app import main

    db = db_factory()
    friend = Friend(
        uid="batch-vless-test",
        token="batch-vless-token",
        per_user_credentials=True,
        device_credentials_mode="preparing",
    )
    node = Node(
        name="batch-vless",
        protocol="vless",
        adapter_kind="local_vless",
        uri="vless://00000000-0000-4000-8000-000000000001@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    db.add_all(
        [
            Device(
                friend_id=friend.id,
                fingerprint=f"batch-device-{index}",
                device_token_hash=f"{index:064x}",
            )
            for index in range(1, 4)
        ]
    )
    db.commit()
    monkeypatch.setattr(main, "adapter_ready", lambda _node, _db: True)
    applied_counts = []

    def apply_once(session):
        applied_counts.append(
            session.scalar(
                select(func.count(UserNodeCredential.id)).where(
                    UserNodeCredential.friend_id == friend.id,
                    UserNodeCredential.status == "active",
                    UserNodeCredential.revoked_at.is_(None),
                )
            )
        )

    monkeypatch.setattr(main, "sync_vless_config", apply_once)
    main._reconcile_friend_credentials(db, friend)

    assert applied_counts == [4]
    assert all(
        row.last_synced_at is not None
        for row in db.scalars(
            select(UserNodeCredential).where(UserNodeCredential.friend_id == friend.id)
        )
    )


def test_reconcile_reports_vless_revocation_apply_failure(db_factory, monkeypatch):
    monkeypatch.setenv("SUB_APP_ADMIN_PASSWORD", "test-device-admin")
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-revoke-secret")
    from app import main

    db = db_factory()
    friend = Friend(
        uid="vless-revoke-test",
        token="vless-revoke-token",
        per_user_credentials=True,
        device_credentials_mode="required",
    )
    node = Node(
        name="vless-revoke",
        protocol="vless",
        adapter_kind="local_vless",
        uri="vless://00000000-0000-4000-8000-000000000001@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="vless-revoke-device",
        device_token_hash="a" * 64,
        device_token_revoked_at=datetime.now(timezone.utc),
    )
    db.add(device)
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    row = ensure_credential(db, friend, node, device=device)
    row.status = "active"
    db.commit()

    monkeypatch.setattr(main, "adapter_ready", lambda _node, _db: True)

    def fail_apply(_db):
        raise RuntimeError("temporary V2Ray API failure")

    monkeypatch.setattr(main, "sync_vless_config", fail_apply)
    result = main._reconcile_friend_credentials(db, friend)

    assert result["proxy_config_sync_error"] == "temporary V2Ray API failure"
    assert row.status == "revoked"
    assert row.last_error == (
        "凭据已撤销，但代理端配置尚未确认同步：temporary V2Ray API failure"
    )
    db.commit()
    db.refresh(row)
    assert row.last_error.startswith("凭据已撤销，但代理端配置尚未确认同步：")


def test_subscription_plan_never_falls_back_to_account_credential_in_required_mode(
    db_factory, monkeypatch
):
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-plan-secret")
    db = db_factory()
    friend = Friend(
        uid="plan-device-test",
        token="plan-device-token",
        per_user_credentials=True,
        device_credentials_mode="required",
    )
    node = Node(
        name="device-hy2",
        protocol="hysteria2",
        adapter_kind="local_hy2",
        uri="hysteria2://shared:password@example.test:443?insecure=1#hy2",
    )
    db.add_all([friend, node])
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    first = Device(
        friend_id=friend.id,
        fingerprint="first",
        device_token_hash="b" * 64,
    )
    second = Device(
        friend_id=friend.id,
        fingerprint="second",
        device_token_hash="c" * 64,
    )
    db.add_all([first, second])
    db.flush()
    account_row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=node.protocol,
        credential_name="account-user",
        version=1,
        status="active",
    )
    device_row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        device_id=first.id,
        protocol=node.protocol,
        credential_name="device-user",
        version=2,
        status="active",
    )
    db.add_all([account_row, device_row])
    db.commit()

    plan = build_subscription_plan(db, friend, True, device_id=first.id)
    assert plan.nodes[0]["code"] == "per_user"
    assert "device-user" in plan.uris[0]
    other_device_plan = build_subscription_plan(db, friend, True, device_id=second.id)
    assert other_device_plan.uris == []
    assert other_device_plan.skipped_nodes == [node.id]
    no_device_plan = build_subscription_plan(db, friend, True)
    assert no_device_plan.uris == []
    assert no_device_plan.skipped_nodes == [node.id]


def test_device_mode_prepare_activate_subscription_and_revoke(
    db_factory, monkeypatch, tmp_path
):
    monkeypatch.setenv("SUB_APP_ADMIN_PASSWORD", "test-device-admin")
    monkeypatch.setenv("SUB_APP_SECRET", "test-device-transition-secret")
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    monkeypatch.setenv("SUB_APP_DB", str(tmp_path / "device-mode-test.db"))
    from app import main

    monkeypatch.setattr(main, "adapter_ready", lambda _node, _db: True)

    def activate(_db, row):
        row.status = "active"
        row.last_synced_at = datetime.now(timezone.utc)
        return row

    monkeypatch.setattr(main, "activate_credential", activate)
    db = db_factory()
    friend = Friend(
        uid="transition-device-test",
        token="transition-device-token",
        per_user_credentials=True,
    )
    node = Node(
        name="transition-hy2",
        protocol="hysteria2",
        adapter_kind="local_hy2",
        uri="hysteria2://shared:password@example.test:443?insecure=1#hy2",
    )
    second_node = Node(
        name="transition-hy2-second",
        protocol="hysteria2",
        adapter_kind="remote_agent",
        per_user_enabled=True,
        uri="hysteria2://shared:password@second.example.test:443?insecure=1#hy2",
        sort_order=1,
    )
    db.add_all([friend, node, second_node])
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="transition-device",
        device_token_hash=main.device_token_hash("known-device-token"),
        identity_source="device_link",
    )
    db.add(device)
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    db.add(Allocation(friend_id=friend.id, node_id=second_node.id))
    db.commit()

    main.prepare_device_credentials(friend.id, db=db, _={})
    assert friend.device_credentials_mode == "preparing"
    rows = db.scalars(
        select(UserNodeCredential).where(UserNodeCredential.friend_id == friend.id)
    ).all()
    assert {row.device_id for row in rows} == {None, device.id}
    main.activate_device_credentials(friend.id, db=db, _={})
    assert friend.device_credentials_mode == "required"
    assert all(row.revoked_at is not None for row in rows if row.device_id is None)

    from starlette.requests import Request

    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    pending_device_row = next(
        row
        for row in rows
        if row.device_id == device.id and row.node_id == second_node.id
    )
    pending_device_row.status = "pending"
    db.commit()
    with pytest.raises(HTTPException) as incomplete:
        main.subscription(
            friend.token,
            request,
            target="raw",
            device="known-device-token",
            db=db,
        )
    assert incomplete.value.status_code == 503
    assert (
        incomplete.value.headers["x-sub-app-error-code"] == "device_credentials_pending"
    )

    pending_device_row.status = "active"
    db.commit()
    response = main.subscription(
        friend.token,
        request,
        target="raw",
        device="known-device-token",
        db=db,
    )
    assert response.status_code == 200
    legacy_row = next(row for row in rows if row.device_id is None)
    body = response.body.decode("utf-8")
    assert all(
        credential_values(row)["username"] in body
        for row in rows
        if row.device_id == device.id
    )
    assert credential_values(legacy_row)["username"] not in body
    assert "@example.test:443" in body
    with pytest.raises(HTTPException) as denied:
        main.subscription(friend.token, request, target="raw", device=None, db=db)
    assert denied.value.status_code == 403
    assert denied.value.headers["x-sub-app-error-code"] == "device_link_required"

    main.revoke_device_link(device.id, db=db, _={})
    assert device.device_token_revoked_at is not None
    assert all(row.revoked_at is not None for row in rows if row.device_id == device.id)

    restored = main.restore_compatible_credentials(friend.id, db=db, _={})
    assert restored["mode"] == "off"
    assert any(
        row.device_id is None and row.status == "active" and row.revoked_at is None
        for row in db.scalars(
            select(UserNodeCredential).where(UserNodeCredential.friend_id == friend.id)
        )
    )


def test_device_list_includes_device_scoped_traffic_and_credential_state(db_factory):
    from app import main

    db = db_factory()
    friend = Friend(
        uid="device-list-test",
        token="device-list-test-token",
        device_credentials_mode="required",
    )
    db.add(friend)
    db.flush()
    node = Node(
        name="device-list-hy2",
        protocol="hysteria2",
        adapter_kind="local_hy2",
        uri="hysteria2://shared:password@example.test:443",
    )
    db.add(node)
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="device-list-fingerprint",
        device_token_hash="d" * 64,
        label="phone",
    )
    db.add(device)
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add_all(
        [
            UserNodeCredential(
                friend_id=friend.id,
                node_id=node.id,
                device_id=device.id,
                protocol="hysteria2",
                credential_name="device-credential",
                version=1,
                status="active",
            ),
            FlowRecord(
                friend_id=friend.id,
                device_id=device.id,
                node_id=node.id,
                bucket=now - timedelta(days=1),
                source="hysteria2",
                bytes_in=100,
                bytes_out=250,
            ),
            FlowRecord(
                friend_id=friend.id,
                device_id=device.id,
                node_id=node.id,
                bucket=now - timedelta(days=31),
                source="hysteria2",
                bytes_in=900,
                bytes_out=900,
            ),
        ]
    )
    db.commit()

    result = main.list_devices(db=db, _={})

    assert len(result) == 1
    assert result[0]["friend_device_credentials_mode"] == "required"
    assert result[0]["device_credentials"] == {"active": 1}
    assert result[0]["traffic"]["bytes_in"] == 100
    assert result[0]["traffic"]["bytes_out"] == 250
    assert result[0]["traffic"]["last_seen"] is not None


def test_reconciler_preserves_required_device_scope(db_factory):
    from scripts.reconciler import reconcile

    db = db_factory()
    friend = Friend(
        uid="strict-reconcile-test",
        token="strict-reconcile-token",
        per_user_credentials=True,
        device_credentials_mode="required",
    )
    node = Node(
        name="strict-reconcile-hy2",
        protocol="hysteria2",
        adapter_kind="remote_agent",
        per_user_enabled=True,
        uri="hysteria2://shared:password@example.test:443",
    )
    db.add_all([friend, node])
    db.flush()
    device = Device(
        friend_id=friend.id,
        fingerprint="strict-reconcile-device",
        device_token_hash="f" * 64,
    )
    db.add(device)
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    account_credential = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=node.protocol,
        credential_name="account-credential",
        version=1,
        status="active",
    )
    db.add(account_credential)
    db.commit()

    reconcile(db)
    db.expire_all()
    rows = db.scalars(
        select(UserNodeCredential).where(UserNodeCredential.friend_id == friend.id)
    ).all()

    assert len(rows) == 2
    assert next(row for row in rows if row.device_id is None).status == "revoked"
    assert next(row for row in rows if row.device_id == device.id).status == "pending"
