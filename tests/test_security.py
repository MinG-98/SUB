"""Regression tests for public health and agent traffic boundaries."""

# Environment variables must be set before importing app.main.
# ruff: noqa: E402

from __future__ import annotations

import atexit
import base64
import hashlib
import os
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="sub-app-tests-"))
atexit.register(shutil.rmtree, _TEST_ROOT, ignore_errors=True)
os.environ.setdefault("SUB_APP_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("SUB_APP_SECRET", "test-secret-for-tests")
os.environ["SUB_APP_DB"] = str(_TEST_ROOT / "app.db")
os.environ["SUB_APP_PROXY_STATUS"] = str(_TEST_ROOT / "proxy-status.json")
os.environ["SUB_APP_RECONCILER_STATUS"] = str(_TEST_ROOT / "reconciler-status.json")

import yaml
from fastapi import HTTPException, Request, Response
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

import app.main as main_module
import app.proxy_adapters as proxy_adapters
from app.agent_api import _desired_users, _mark_applied, _record_traffic
from app.credentials import credential_stats_id, credential_values
from app.main import Session, app
from app.models import (
    AdminLoginThrottle,
    AdminSession,
    Allocation,
    Announcement,
    AnnouncementAllocation,
    Device,
    FetchLog,
    FlowRecord,
    Friend,
    Node,
    NodeAgent,
    NodeMetricSample,
    UserNodeCredential,
    make_session_factory,
    utcnow,
)

client = TestClient(app, base_url="https://testserver")


def _seed_subscription() -> None:
    db = Session()
    try:
        if db.query(Friend).filter_by(uid="security-test-user").first():
            return
        friend = Friend(
            uid="security-test-user",
            token="security-test-token",
            remark="test",
        )
        node = Node(
            name="Security Test",
            protocol="vless",
            uri=(
                "vless://00000000-0000-0000-0000-000000000001"
                "@example.com:443?security=tls#Security-Test"
            ),
            server="example.com",
        )
        db.add_all([friend, node])
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node.id))
        db.commit()
    finally:
        db.close()


def test_public_health_is_liveness_only() -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert set(response.json()) == {"ok", "generated_at"}
    assert client.get("/api/admin/healthz").status_code == 401


def test_detailed_health_requires_admin_authentication() -> None:
    login = client.post("/api/admin/login", json={"password": "test-admin-password"})
    assert login.status_code == 200
    assert login.json()["role"] == "admin"
    assert "Max-Age=28800" in login.headers["set-cookie"]

    response = client.get("/api/admin/healthz")

    assert response.status_code == 200
    assert {"collector", "agents", "adapters"} <= set(response.json())

    identity = client.get("/api/admin/me")
    assert identity.json() == {
        "authenticated": True,
        "username": "admin",
        "role": "admin",
    }


def test_admin_mutations_write_redacted_append_only_audit_records() -> None:
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    response = client.post(
        "/api/admin/nodes",
        json={
            "uri": "hysteria2://dummy-secret-audit-fixture@audit.example:443#audit-test"
        },
    )
    assert response.status_code == 200

    rows = client.get("/api/admin/audit-logs").json()
    entry = next(
        row
        for row in rows
        if row["path"] == "/api/admin/nodes" and row["method"] == "POST"
    )
    assert entry["status_code"] == 200
    assert len(entry["actor_fingerprint"]) == 64
    assert "dummy-secret-audit-fixture" not in str(rows)

    engine = Session.kw["bind"]
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "DELETE FROM admin_audit_logs WHERE id=?", (entry["id"],)
            )
    except IntegrityError as exc:
        assert "append-only" in str(exc)
    else:
        raise AssertionError("audit log deletion should be rejected by SQLite")

    assert any(
        row["id"] == entry["id"] for row in client.get("/api/admin/audit-logs").json()
    )


def test_admin_login_throttles_peer_and_ignores_forwarded_ip_headers() -> None:
    db = Session()
    try:
        db.query(AdminLoginThrottle).delete()
        db.commit()
    finally:
        db.close()

    for attempt in range(main_module.ADMIN_LOGIN_MAX_FAILURES):
        response = client.post(
            "/api/admin/login",
            json={"password": "wrong-password"},
            headers={
                "x-forwarded-for": f"198.51.100.{attempt + 1}",
                "cf-connecting-ip": f"203.0.113.{attempt + 1}",
            },
        )
        expected = 429 if attempt == main_module.ADMIN_LOGIN_MAX_FAILURES - 1 else 401
        assert response.status_code == expected

    locked = client.post(
        "/api/admin/login",
        json={"password": "test-admin-password"},
        headers={
            "x-forwarded-for": "198.51.100.250",
            "cf-connecting-ip": "203.0.113.250",
        },
    )
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0
    assert "sub_app_session" not in locked.headers.get("set-cookie", "")

    db = Session()
    try:
        throttle = db.query(AdminLoginThrottle).one()
        assert throttle.failure_count == main_module.ADMIN_LOGIN_MAX_FAILURES
        assert throttle.blocked_until is not None
        db.delete(throttle)
        db.commit()
    finally:
        db.close()


def test_admin_session_is_invalidated_when_password_version_changes() -> None:
    login = client.post("/api/admin/login", json={"password": "test-admin-password"})
    assert login.status_code == 200
    assert client.get("/api/admin/healthz").status_code == 200
    original_version = main_module.ADMIN_SESSION_VERSION
    try:
        main_module.ADMIN_SESSION_VERSION = "rotated-password-version"
        assert client.get("/api/admin/healthz").status_code == 401
        assert client.get("/api/admin/me").json()["authenticated"] is False
    finally:
        main_module.ADMIN_SESSION_VERSION = original_version

    assert client.get("/api/admin/healthz").status_code == 200


def test_admin_auth_epoch_prevents_old_password_restore_from_reviving_cookie(
    tmp_path: Path,
) -> None:
    factory = make_session_factory(tmp_path / "auth-epoch.db")
    try:
        fingerprint_a = "a" * 64
        fingerprint_b = "b" * 64
        version_a = main_module._session_version_for_config(
            fingerprint_a, factory, "isolated-test-secret"
        )
        assert (
            main_module._session_version_for_config(
                fingerprint_a, factory, "isolated-test-secret"
            )
            == version_a
        )
        version_b = main_module._session_version_for_config(
            fingerprint_b, factory, "isolated-test-secret"
        )
        restored_version_a = main_module._session_version_for_config(
            fingerprint_a, factory, "isolated-test-secret"
        )

        assert version_b != version_a
        assert restored_version_a != version_a
    finally:
        factory.kw["bind"].dispose()


def test_persistent_auth_epoch_rotation_rejects_an_issued_cookie(
    tmp_path: Path, monkeypatch
) -> None:
    factory = make_session_factory(tmp_path / "auth-epoch-cookie.db")
    monkeypatch.setattr(main_module, "Session", factory)
    fingerprint_a = "c" * 64
    fingerprint_b = "d" * 64
    monkeypatch.setattr(main_module, "ADMIN_CREDENTIAL_FINGERPRINT", fingerprint_a)
    version_a = main_module._session_version_for_config(
        fingerprint_a, factory, main_module.SECRET_KEY
    )
    monkeypatch.setattr(main_module, "ADMIN_SESSION_VERSION", version_a)

    session_id = "persistent-epoch-cookie-test-session"
    now = utcnow().replace(tzinfo=None)
    db = factory()
    try:
        db.add(
            AdminSession(
                session_hash=main_module._admin_session_hash(session_id),
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        db.commit()
    finally:
        db.close()

    raw_cookie = main_module.serializer.dumps(
        {
            "ok": True,
            "username": "admin",
            "role": "admin",
            "auth_version": version_a,
            "sid": session_id,
            "ts": utcnow().isoformat(),
        }
    )
    operator = TestClient(app, base_url="https://testserver")
    operator.cookies.set(main_module.COOKIE_NAME, raw_cookie)
    try:
        assert operator.get("/api/admin/healthz").status_code == 200

        main_module._session_version_for_config(
            fingerprint_b, factory, main_module.SECRET_KEY
        )
        assert operator.get("/api/admin/healthz").status_code == 401
    finally:
        factory.kw["bind"].dispose()


def test_logout_revokes_a_copied_admin_session_cookie() -> None:
    operator = TestClient(app, base_url="https://testserver")
    copied = TestClient(app, base_url="https://testserver")
    login = operator.post("/api/admin/login", json={"password": "test-admin-password"})
    assert login.status_code == 200
    raw_cookie = operator.cookies.get(main_module.COOKIE_NAME)
    assert raw_cookie
    copied.cookies.set(main_module.COOKIE_NAME, raw_cookie)
    assert copied.get("/api/admin/healthz").status_code == 200

    logged_out = operator.post("/api/admin/logout")
    assert logged_out.status_code == 200
    assert copied.get("/api/admin/healthz").status_code == 401

    payload = main_module.serializer.loads(
        raw_cookie, max_age=main_module.SESSION_MAX_AGE
    )
    db = Session()
    try:
        session_row = db.get(
            AdminSession, main_module._admin_session_hash(payload["sid"])
        )
        assert session_row is not None
        assert session_row.revoked_at is not None
    finally:
        db.close()


def test_status_files_become_stale_after_fifteen_minutes() -> None:
    fresh = main_module._with_status_freshness(
        {"status": "success", "at": (utcnow() - timedelta(minutes=5)).isoformat()}
    )
    stale = main_module._with_status_freshness(
        {"status": "success", "at": (utcnow() - timedelta(minutes=16)).isoformat()}
    )
    malformed = main_module._with_status_freshness(["invalid-shape"])

    assert fresh["stale"] is False
    assert stale["stale"] is True
    assert malformed["stale"] is True


def test_sqlite_wal_reset_fix_status_respects_fixed_release_and_backports() -> None:
    assert (
        main_module._sqlite_runtime_status("3.54.1")["sqlite_wal_reset_fix"] == "fixed"
    )
    assert (
        main_module._sqlite_runtime_status("3.51.3")["sqlite_wal_reset_fix"] == "fixed"
    )
    assert (
        main_module._sqlite_runtime_status("3.50.7")["sqlite_wal_reset_fix"] == "fixed"
    )
    assert (
        main_module._sqlite_runtime_status("3.44.6")["sqlite_wal_reset_fix"] == "fixed"
    )
    assert (
        main_module._sqlite_runtime_status("3.51.2")["sqlite_wal_reset_fix"]
        == "verify_backport"
    )


def test_admin_login_throttle_serializes_parallel_attempts() -> None:
    db = Session()
    try:
        db.query(AdminLoginThrottle).delete()
        db.commit()
    finally:
        db.close()

    def attempt(index: int) -> int:
        request = Request(
            {
                "type": "http",
                "headers": [
                    (b"x-forwarded-for", f"198.51.100.{index}".encode()),
                ],
                "client": ("192.0.2.77", 40000 + index),
            }
        )
        try:
            main_module.login(
                request,
                Response(),
                {"password": "wrong-password"},
            )
        except HTTPException as exc:
            return exc.status_code
        raise AssertionError("an incorrect password must not authenticate")

    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(attempt, range(12)))

    assert statuses.count(401) == main_module.ADMIN_LOGIN_MAX_FAILURES - 1
    assert statuses.count(429) == 12 - (main_module.ADMIN_LOGIN_MAX_FAILURES - 1)

    db = Session()
    try:
        throttle = db.query(AdminLoginThrottle).one()
        assert throttle.failure_count == main_module.ADMIN_LOGIN_MAX_FAILURES
        db.delete(throttle)
        db.commit()
    finally:
        db.close()


def test_public_responses_include_browser_security_headers() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-robots-tag"] == "noindex, nofollow"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")


def test_subscription_is_explicitly_not_cacheable() -> None:
    _seed_subscription()

    response = client.get("/sub/security-test-token?target=raw")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"


def test_subscription_quota_is_enforced_before_creating_device() -> None:
    friend = Friend(
        uid="quota-enforced-user",
        token="quota-enforced-token",
        flow_limit_gb=1,
    )
    db = Session()
    try:
        db.add(friend)
        db.flush()
        db.add(
            FlowRecord(
                friend_id=friend.id,
                source="sing-box",
                bytes_in=1024**3,
                bytes_out=0,
                bucket=utcnow(),
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/sub/quota-enforced-token?target=raw")
    assert response.status_code == 403
    assert response.json()["detail"] == "用户可计量流量配额已用完"

    db = Session()
    try:
        assert db.query(Device).filter_by(friend_id=friend.id).count() == 0
        assert db.query(FetchLog).filter_by(friend_id=friend.id).count() == 0
    finally:
        db.close()


def test_quota_suppresses_existing_independent_credentials() -> None:
    friend = Friend(
        uid="quota-data-plane-user",
        token="quota-data-plane-token",
        flow_limit_gb=1,
        per_user_credentials=True,
    )
    remote = Node(
        name="Quota remote HY2",
        protocol="hysteria2",
        uri="hysteria2://shared@example.com:443",
        adapter_kind="remote_agent",
        per_user_enabled=True,
    )
    local = Node(
        name="Quota local HY2",
        protocol="hysteria2",
        uri="hysteria2://shared@local.example:443",
        adapter_kind="local_hy2",
    )
    db = Session()
    try:
        db.add_all([friend, remote, local])
        db.flush()
        remote_credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=remote.id,
            protocol="hysteria2",
            credential_name=f"u{friend.id}n{remote.id}",
            version=1,
            status="pending",
        )
        local_credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=local.id,
            protocol="hysteria2",
            credential_name=f"u{friend.id}n{local.id}",
            version=1,
            status="active",
        )
        db.add_all([remote_credential, local_credential])
        db.add(
            FlowRecord(
                friend_id=friend.id,
                source="hysteria2",
                bytes_in=1024**3,
                bytes_out=0,
                bucket=utcnow(),
            )
        )
        db.flush()

        assert _desired_users(db, remote.id) == []
        assert (
            _mark_applied(db, remote.id, "quota-generation", "quota-generation", set())
            == 0
        )
        assert remote_credential.status == "pending"
        values = credential_values(local_credential)
        auth = f"{values['username']}:{values['password']}"
        assert proxy_adapters.authenticate_hysteria(db, auth) is None

        db.query(FlowRecord).filter_by(friend_id=friend.id).update(
            {FlowRecord.bytes_in: 0}
        )
        assert len(_desired_users(db, remote.id)) == 1
        assert proxy_adapters.authenticate_hysteria(db, auth) == credential_stats_id(
            local_credential
        )
        db.commit()
    finally:
        db.close()


def test_native_hysteria_agent_receives_quota_session_kick_ids() -> None:
    token = "quota-kick-agent-token"
    db = Session()
    try:
        friend = Friend(
            uid="quota-kick-agent-user",
            token="quota-kick-agent-subscription",
            flow_limit_gb=1,
            per_user_credentials=True,
        )
        node = Node(
            name="Quota kick native agent",
            protocol="hysteria2",
            adapter_kind="remote_agent",
            per_user_enabled=True,
            uri="hysteria2://shared@quota-kick.example:443",
        )
        db.add_all([friend, node])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{friend.id}n{node.id}",
            version=1,
            status="active",
        )
        agent = NodeAgent(
            node_id=node.id,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
        )
        db.add_all([credential, agent])
        db.add(
            FlowRecord(
                friend_id=friend.id,
                node_id=node.id,
                source="hysteria2",
                sample_key="quota-kick-before-crossing",
                bytes_in=1024**3 - 1,
                bytes_out=0,
                bucket=utcnow(),
            )
        )
        db.commit()
        node_id = node.id
        stats_id = credential_stats_id(credential)
    finally:
        db.close()

    headers = {"X-Sub-App-Agent-Token": token}
    desired = client.get(f"/api/agent/v1/desired/{node_id}", headers=headers)
    assert desired.status_code == 200
    assert [item["stats_id"] for item in desired.json()["users"]] == [stats_id]

    heartbeat = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=headers,
        json={
            "status": "ready",
            "agent_version": "test",
            "capabilities": {"singbox_engine": False},
            "applied_generation": desired.json()["generation"],
            "traffic": [
                {
                    "source": "hysteria2",
                    "credential_key": stats_id,
                    "sample_key": "quota-kick-crossing-sample",
                    "bytes_in": 1,
                    "bytes_out": 0,
                    "bucket": utcnow().isoformat(),
                }
            ],
        },
    )

    assert heartbeat.status_code == 200
    assert heartbeat.json()["quota_kick_stats_ids"] == [stats_id]
    refreshed = client.get(f"/api/agent/v1/desired/{node_id}", headers=headers)
    assert refreshed.json()["users"] == []


def test_subscription_expiry_is_validated_and_enforced() -> None:
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    created = client.post(
        "/api/admin/friends",
        json={"uid": "expires-today-user", "expires_at": "2026-12-09"},
    )
    assert created.status_code == 200
    assert created.json()["expires_at"] == "2026-12-09T23:59:59.999999+00:00"
    assert created.json()["updated_at"]

    invalid = client.post(
        "/api/admin/friends",
        json={"uid": "invalid-expiry-user", "expires_at": "2026-02-30"},
    )
    assert invalid.status_code == 422

    expired_friend = Friend(
        uid="expired-subscription-user",
        token="expired-subscription-token",
        expires_at=datetime(2020, 1, 1),
    )
    db = Session()
    try:
        db.add(expired_friend)
        db.commit()
        friend_id = expired_friend.id
    finally:
        db.close()

    response = client.get("/sub/expired-subscription-token?target=raw")
    assert response.status_code == 403
    assert response.json()["detail"] == "用户订阅已到期，请联系管理员续期"
    db = Session()
    try:
        assert db.query(Device).filter_by(friend_id=friend_id).count() == 0
        assert db.query(FetchLog).filter_by(friend_id=friend_id).count() == 0
    finally:
        db.close()


def test_subscription_skips_expired_nodes_and_reports_count() -> None:
    friend = Friend(uid="node-expiry-user", token="node-expiry-token")
    expired = Node(
        name="Expired Node",
        protocol="vless",
        uri="vless://00000000-0000-0000-0000-000000000002@expired.example:443?security=tls#expired",
        server="expired.example",
        expires_at=datetime(2020, 1, 1),
    )
    current = Node(
        name="Current Node",
        protocol="vless",
        uri="vless://00000000-0000-0000-0000-000000000003@current.example:443?security=tls#current",
        server="current.example",
    )
    db = Session()
    try:
        db.add_all([friend, expired, current])
        db.flush()
        db.add_all(
            [
                Allocation(friend_id=friend.id, node_id=expired.id),
                Allocation(friend_id=friend.id, node_id=current.id),
            ]
        )
        token = friend.token
        db.commit()
    finally:
        db.close()

    response = client.get(f"/sub/{token}?target=raw")
    assert response.status_code == 200
    assert response.text == current.uri
    assert response.headers["x-sub-app-expired-nodes"] == "1"
    db = Session()
    try:
        saved_friend = db.query(Friend).filter_by(token=token).one()
        assert (
            main_module.friend_dict(saved_friend, [], db=db)["last_expired_node_count"]
            == 1
        )
    finally:
        db.close()


def test_bulk_node_import_deduplicates_name_and_query_order_variants() -> None:
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    first = "vless://00000000-0000-0000-0000-000000000010@dedupe.example:443?security=tls&sni=cdn.example#first"
    second = "vless://00000000-0000-0000-0000-000000000010@dedupe.example:443?sni=cdn.example&security=tls#renamed"
    response = client.post("/api/admin/nodes", json={"bulk": f"{first}\n{second}"})
    assert response.status_code == 200
    assert len(response.json()["created"]) == 1
    assert len(response.json()["skipped"]) == 1

    later_duplicate = client.post(
        "/api/admin/nodes",
        json={
            "uri": "vless://00000000-0000-0000-0000-000000000010@dedupe.example:443?security=tls&sni=cdn.example#third"
        },
    )
    assert later_duplicate.status_code == 200
    assert later_duplicate.json()["created"] == []
    assert len(later_duplicate.json()["skipped"]) == 1

    invalid_port = client.post(
        "/api/admin/nodes",
        json={"bulk": "hysteria2://secret@bad-port.example:70000"},
    )
    assert invalid_port.status_code == 200
    assert invalid_port.json()["created"] == []
    assert len(invalid_port.json()["skipped"]) == 1


def test_missing_per_user_credential_is_skipped_and_reported(monkeypatch) -> None:
    monkeypatch.setattr(main_module, "per_user_feature_enabled", lambda: True)
    friend = Friend(
        uid="shared-fallback-user",
        token="shared-fallback-token",
        per_user_credentials=True,
    )
    node = Node(
        name="Unready HY2",
        protocol="hysteria2",
        uri="hysteria2://shared-auth@example.com:443?sni=example.com#unready",
        server="example.com",
        adapter_kind="remote_agent",
        per_user_enabled=True,
    )
    db = Session()
    try:
        db.add_all([friend, node])
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node.id))
        db.commit()
        friend_id, node_id, token = friend.id, node.id, friend.token
    finally:
        db.close()

    response = client.get(f"/sub/{token}?target=raw")
    assert response.status_code == 503
    assert node.uri not in response.text
    assert response.json()["detail"].startswith("独立凭据节点尚未同步完成")

    db = Session()
    try:
        friend = db.get(Friend, friend_id)
        payload = main_module.friend_dict(friend, [node_id], db=db)
        assert payload["last_shared_fallback_nodes"] == 0
        assert payload["last_skipped_node_count"] == 1
        log = db.query(FetchLog).filter_by(friend_id=friend_id).one()
        assert log.skipped_node_count == 1
    finally:
        db.close()


def test_legacy_announcement_is_hidden_from_node_ops_but_preserved_in_subscriptions() -> (
    None
):
    db = Session()
    try:
        friend = Friend(uid="notice-regression", token="notice-regression-token")
        node = Node(
            name="使用前请更新订阅",
            protocol="vless",
            uri="vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1#notice",
            server="127.0.0.1",
            is_announcement=True,
        )
        db.add_all([friend, node])
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node.id))
        announcement = Announcement(
            id=node.id,
            legacy_node_id=node.id,
            name=node.name,
            enabled=True,
            sort_order=4,
        )
        db.add(announcement)
        db.flush()
        db.add(
            AnnouncementAllocation(friend_id=friend.id, announcement_id=announcement.id)
        )
        db.commit()
        announcement_id = announcement.id
    finally:
        db.close()

    client.post("/api/admin/login", json={"password": "test-admin-password"})
    node_rows = client.get("/api/admin/nodes").json()
    assert all(row["id"] != node.id for row in node_rows)
    announcements = client.get("/api/admin/announcements").json()
    assert any(row["id"] == announcement_id for row in announcements)

    friend_row = next(
        row
        for row in client.get("/api/admin/friends").json()
        if row["uid"] == "notice-regression"
    )
    assert friend_row["node_ids"] == []
    assert friend_row["announcement_ids"] == [announcement_id]

    raw = client.get("/sub/notice-regression-token?target=raw")
    expected_uri = main_module._announcement_uri("使用前请更新订阅")
    assert raw.status_code == 200
    assert raw.text == expected_uri
    assert client.get("/sub/notice-regression-token?target=v2ray").status_code == 200
    assert (
        client.get("/sub/notice-regression-token?target=shadowrocket").status_code
        == 200
    )
    clash = client.get("/sub/notice-regression-token?target=clash")
    assert clash.status_code == 200
    assert yaml.safe_load(clash.text)["proxies"][0]["name"] == "使用前请更新订阅"
    mihomo = client.get("/sub/notice-regression-token?target=mihomo")
    assert mihomo.status_code == 200
    assert mihomo.headers["content-disposition"].endswith('.yaml"')

    stats = client.get("/api/admin/stats").json()
    assert stats["nodes"] == stats["nodes_total"]
    assert stats["announcement_nodes"] >= 1


def test_announcement_crud_and_user_assignment_are_independent_of_node_allocations() -> (
    None
):
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    first = client.post(
        "/api/admin/announcements",
        json={"name": "维护提示 A", "enabled": True},
    )
    second = client.post(
        "/api/admin/announcements",
        json={"name": "维护提示 B", "enabled": False},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] != second.json()["id"]

    friend = client.post(
        "/api/admin/friends",
        json={
            "uid": "announcement-allocation-regression",
            "node_ids": [],
            "announcement_ids": [first.json()["id"]],
        },
    )
    assert friend.status_code == 200
    assert friend.json()["announcement_ids"] == [first.json()["id"]]

    updated = client.patch(
        f"/api/admin/friends/{friend.json()['id']}",
        json={"remark": "keep the announcement allocation"},
    )
    assert updated.status_code == 200
    assert updated.json()["announcement_ids"] == [first.json()["id"]]

    edited = client.patch(
        f"/api/admin/announcements/{first.json()['id']}",
        json={"name": "维护提示 A2", "enabled": False},
    )
    assert edited.status_code == 200
    assert edited.json()["allocated_to"] == 1
    deleted = client.delete(f"/api/admin/announcements/{second.json()['id']}")
    assert deleted.status_code == 200


def test_subscription_includes_only_assigned_enabled_announcements_in_all_formats():
    db = Session()
    try:
        friend = Friend(
            uid="announcement-format-regression",
            token="announcement-format-regression-token",
        )
        node = Node(
            name="Real node",
            protocol="vless",
            uri="vless://11111111-1111-1111-1111-111111111111@node.example.test:443?security=tls#Real%20node",
            server="node.example.test",
            sort_order=20,
        )
        assigned = Announcement(
            name="已分配 & 已发布",
            enabled=True,
            sort_order=10,
        )
        disabled = Announcement(name="已分配但草稿", enabled=False, sort_order=1)
        unassigned = Announcement(name="未分配", enabled=True, sort_order=2)
        db.add_all([friend, node, assigned, disabled, unassigned])
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node.id))
        db.add_all(
            [
                AnnouncementAllocation(
                    friend_id=friend.id, announcement_id=assigned.id
                ),
                AnnouncementAllocation(
                    friend_id=friend.id, announcement_id=disabled.id
                ),
            ]
        )
        db.commit()
        friend_id = friend.id
        expected = [
            main_module._announcement_uri(assigned.name),
            node.uri,
        ]
    finally:
        db.close()

    raw = client.get("/sub/announcement-format-regression-token?target=raw")
    assert raw.status_code == 200
    assert raw.text.splitlines() == expected

    for target in ("v2ray", "base64", "shadowrocket"):
        response = client.get(
            f"/sub/announcement-format-regression-token?target={target}"
        )
        assert response.status_code == 200
        assert base64.b64decode(response.text).decode("utf-8").splitlines() == expected

    for target in ("clash", "clashmeta", "mihomo"):
        response = client.get(
            f"/sub/announcement-format-regression-token?target={target}"
        )
        assert response.status_code == 200
        proxies = yaml.safe_load(response.text)["proxies"]
        assert [proxy["name"] for proxy in proxies] == ["已分配 & 已发布", "Real node"]

    client.post("/api/admin/login", json={"password": "test-admin-password"})
    friend_row = next(
        row for row in client.get("/api/admin/friends").json() if row["id"] == friend_id
    )
    assert len(friend_row["announcement_ids"]) == 2
    removed = client.patch(
        f"/api/admin/friends/{friend_id}",
        json={"announcement_ids": []},
    )
    assert removed.status_code == 200
    assert removed.json()["announcement_ids"] == []
    after_removal = client.get("/sub/announcement-format-regression-token?target=raw")
    assert after_removal.status_code == 200
    assert after_removal.text == node.uri


def test_weekly_stats_keep_users_with_no_recent_fetches() -> None:
    db = Session()
    try:
        zero = Friend(uid="zero-weekly-regression", token="zero-weekly-token")
        old = Friend(uid="old-weekly-regression", token="old-weekly-token")
        db.add_all([zero, old])
        db.flush()
        db.add(
            FetchLog(
                friend_id=old.id,
                target="raw",
                created_at=utcnow() - timedelta(days=30),
            )
        )
        db.commit()
    finally:
        db.close()

    client.post("/api/admin/login", json={"password": "test-admin-password"})
    rows = client.get("/api/admin/stats").json()["per_friend_week"]
    counts = {row["uid"]: row["fetches"] for row in rows}
    assert counts["zero-weekly-regression"] == 0
    assert counts["old-weekly-regression"] == 0


def test_device_link_is_written_and_accepted_by_subscription() -> None:
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    friend = next(
        row
        for row in client.get("/api/admin/friends").json()
        if row["uid"] == "security-test-user"
    )

    created = client.post(
        f"/api/admin/friends/{friend['id']}/devices",
        json={"label": "regression device"},
    )
    assert created.status_code == 200
    links = created.json()["links"]
    assert {"clash", "shadowrocket", "v2ray"} <= links.keys()
    link = links["shadowrocket"]
    parts = urlsplit(link)
    query = parse_qs(parts.query)
    response = client.get(f"{parts.path}?{parts.query}")

    assert response.status_code == 200
    assert query["device"]
    assert base64.b64decode(response.text).decode("utf-8").startswith("vless://")
    db = Session()
    try:
        device = db.query(Device).filter_by(label="regression device").one()
        assert device.identity_source == "device_link"
        assert device.device_token_hash
    finally:
        db.close()


def test_invalid_node_ids_do_not_silently_remove_existing_allocations() -> None:
    client.post("/api/admin/login", json={"password": "test-admin-password"})
    friend = next(
        row
        for row in client.get("/api/admin/friends").json()
        if row["uid"] == "security-test-user"
    )
    original_node_ids = friend["node_ids"]
    assert original_node_ids

    malformed = client.patch(
        f"/api/admin/friends/{friend['id']}",
        json={"node_ids": [original_node_ids[0], "not-a-node-id"]},
    )
    assert malformed.status_code == 422
    assert "正整数" in malformed.json()["detail"]

    missing = client.patch(
        f"/api/admin/friends/{friend['id']}",
        json={"node_ids": [original_node_ids[0], 9_223_372_036_854_775_807]},
    )
    assert missing.status_code == 422
    assert "节点不存在" in missing.json()["detail"]

    null_ids = client.patch(
        f"/api/admin/friends/{friend['id']}",
        json={"remark": "must not be persisted", "node_ids": None},
    )
    assert null_ids.status_code == 422
    oversized_id = client.patch(
        f"/api/admin/friends/{friend['id']}",
        json={"node_ids": ["9" * 100]},
    )
    assert oversized_id.status_code == 422

    unchanged = next(
        row
        for row in client.get("/api/admin/friends").json()
        if row["id"] == friend["id"]
    )
    assert unchanged["node_ids"] == original_node_ids
    assert unchanged["remark"] == friend["remark"]


def test_node_metric_freshness_has_strict_ten_minute_boundary_and_rejects_future(
    monkeypatch,
) -> None:
    fixed = datetime(2026, 11, 10, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(main_module, "utcnow", lambda: fixed)
    fresh = NodeMetricSample(
        node_id=1,
        nezha_server_id=1,
        bucket=(fixed - timedelta(minutes=5)).replace(tzinfo=None),
        collected_at=fixed - timedelta(minutes=5),
        online=True,
    )
    stale = NodeMetricSample(
        node_id=1,
        nezha_server_id=1,
        bucket=(fixed - timedelta(minutes=11)).replace(tzinfo=None),
        collected_at=fixed - timedelta(minutes=11),
        online=True,
    )
    at_boundary = NodeMetricSample(
        node_id=1,
        nezha_server_id=1,
        bucket=(fixed - timedelta(seconds=600)).replace(tzinfo=None),
        collected_at=fixed - timedelta(seconds=600),
        online=True,
    )
    just_past_boundary = NodeMetricSample(
        node_id=1,
        nezha_server_id=1,
        bucket=(fixed - timedelta(seconds=600, microseconds=1)).replace(tzinfo=None),
        collected_at=fixed - timedelta(seconds=600, microseconds=1),
        online=True,
    )
    future = NodeMetricSample(
        node_id=1,
        nezha_server_id=1,
        bucket=(fixed + timedelta(seconds=1)).replace(tzinfo=None),
        collected_at=fixed + timedelta(seconds=1),
        online=True,
    )

    fresh_result = main_module._metric_dict(fresh)
    stale_result = main_module._metric_dict(stale)
    boundary_result = main_module._metric_dict(at_boundary)
    past_boundary_result = main_module._metric_dict(just_past_boundary)
    future_result = main_module._metric_dict(future)

    assert fresh_result["online"] is True
    assert fresh_result["fresh"] is True
    assert fresh_result["stale"] is False
    assert stale_result["online"] is None
    assert stale_result["fresh"] is False
    assert stale_result["stale"] is True
    assert boundary_result["fresh"] is True
    assert past_boundary_result["fresh"] is False
    assert future_result["online"] is None
    assert future_result["fresh"] is False
    assert future_result["collector_delay_seconds"] is None


def test_unready_adapter_only_blocks_enabling_per_user_credentials(
    monkeypatch,
) -> None:
    db = Session()
    try:
        occupied = {value for (value,) in db.query(Node.id).all()}
        node_ids = [
            node_id for node_id in (17, 12, 13, 14, 15, 16) if node_id not in occupied
        ]
        assert len(node_ids) >= 2
        enabled_node, disabled_node = node_ids[:2]
        db.add_all(
            [
                Node(
                    id=enabled_node,
                    name="unready-enabled-node",
                    protocol="vless",
                    uri=f"vless://00000000-0000-0000-0000-{enabled_node:012d}@node.example:443?security=tls",
                    server="node.example",
                    per_user_enabled=True,
                ),
                Node(
                    id=disabled_node,
                    name="unready-disabled-node",
                    protocol="vless",
                    uri=f"vless://00000000-0000-0000-0000-{disabled_node:012d}@node.example:443?security=tls",
                    server="node.example",
                    per_user_enabled=False,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(
        main_module,
        "adapter_ready",
        lambda _node_id, _db=None: False,
    )
    client.post("/api/admin/login", json={"password": "test-admin-password"})

    unchanged_flag = client.patch(
        f"/api/admin/nodes/{enabled_node}",
        json={"name": "renamed while agent is offline", "per_user_enabled": True},
    )
    assert unchanged_flag.status_code == 200
    assert unchanged_flag.json()["name"] == "renamed while agent is offline"

    unrelated_edit = client.patch(
        f"/api/admin/nodes/{disabled_node}",
        json={"name": "ordinary edit while agent is offline"},
    )
    assert unrelated_edit.status_code == 200

    enable_attempt = client.patch(
        f"/api/admin/nodes/{disabled_node}",
        json={"per_user_enabled": True},
    )
    assert enable_attempt.status_code == 409
    assert "180 秒" in enable_attempt.json()["detail"]

    for invalid_flag in (1, 0, "true", None):
        invalid_attempt = client.patch(
            f"/api/admin/nodes/{disabled_node}",
            json={"per_user_enabled": invalid_flag},
        )
        assert invalid_attempt.status_code == 422
        assert "布尔值" in invalid_attempt.json()["detail"]

    disable_attempt = client.patch(
        f"/api/admin/nodes/{enabled_node}",
        json={"per_user_enabled": False},
    )
    assert disable_attempt.status_code == 200
    assert disable_attempt.json()["per_user_enabled"] is False


def test_node_api_reports_persisted_flag_separately_from_adapter_readiness(
    monkeypatch,
) -> None:
    db = Session()
    try:
        occupied = {value for (value,) in db.query(Node.id).all()}
        node_id = next(
            value for value in (17, 12, 13, 14, 15, 16) if value not in occupied
        )
        db.add(
            Node(
                id=node_id,
                name="adapter-ready-but-not-enabled",
                protocol="vless",
                adapter_kind="remote_agent",
                uri=f"vless://00000000-0000-0000-0000-{node_id:012d}@node.example:443?security=tls",
                server="node.example",
                per_user_enabled=False,
            )
        )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(main_module, "adapter_ready", lambda _node_id, _db=None: True)
    monkeypatch.setattr(
        proxy_adapters,
        "adapter_ready",
        lambda _node_id, _db=None: True,
    )
    client.post("/api/admin/login", json={"password": "test-admin-password"})

    row = next(
        node for node in client.get("/api/admin/nodes").json() if node["id"] == node_id
    )
    assert row["per_user_enabled"] is False
    assert row["per_user_capability"]["ready"] is True


def _agent_db(tmp_path: Path):
    return make_session_factory(str(tmp_path / "agent.db"))


def _add_agent_fixture(
    db, *, friend: Friend, node: Node, status: str, version: int = 1
):
    row = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=node.protocol,
        credential_name=f"u{friend.id}n{node.id}v{version}",
        version=version,
        status=status,
    )
    db.add(row)
    db.flush()
    return row


def test_agent_traffic_accepts_only_active_enabled_user_credentials(tmp_path: Path):
    session_factory = _agent_db(tmp_path)
    db = session_factory()
    try:
        node = Node(
            id=5,
            name="Remote VLESS",
            protocol="vless",
            adapter_kind="remote_agent",
            uri="vless://uuid@example.com:443#remote",
        )
        active_friend = Friend(uid="active", token="active-token")
        disabled_friend = Friend(uid="disabled", token="disabled-token", enabled=False)
        pending_friend = Friend(uid="pending", token="pending-token")
        for friend in (active_friend, disabled_friend, pending_friend):
            friend.per_user_credentials = True
        db.add_all([node, active_friend, disabled_friend, pending_friend])
        db.flush()
        active = _add_agent_fixture(
            db, friend=active_friend, node=node, status="active"
        )
        _add_agent_fixture(db, friend=disabled_friend, node=node, status="active")
        _add_agent_fixture(db, friend=pending_friend, node=node, status="pending")

        payload = [
            {
                "credential_key": credential_stats_id(active),
                "sample_key": "accepted",
                "source": "vless",
                "bucket": "2026-08-09T00:00:00+00:00",
                "bytes_in": 10,
                "bytes_out": 20,
            },
            {
                "credential_key": credential_stats_id(active),
                "sample_key": "wrong-source",
                "source": "hysteria2",
                "bucket": "2026-08-09T00:00:00+00:00",
                "bytes_in": 100,
                "bytes_out": 100,
            },
        ]

        inserted, acknowledged = _record_traffic(db, node.id, payload)
        assert inserted == 1
        assert acknowledged == ["accepted", "wrong-source"]
        record = db.query(FlowRecord).one()
        assert (record.bytes_in, record.bytes_out, record.source) == (10, 20, "vless")
    finally:
        db.close()


def test_agent_registration_is_one_time_and_token_rotation_is_staged():
    db = Session()
    try:
        node = Node(
            name="Agent onboarding regression",
            protocol="vless",
            uri="vless://00000000-0000-0000-0000-000000000001@agent.example:443#agent",
            server="agent.example",
        )
        db.add(node)
        db.commit()
        node_id = node.id
    finally:
        db.close()

    client.post("/api/admin/login", json={"password": "test-admin-password"})
    configured = client.patch(
        f"/api/admin/nodes/{node_id}", json={"adapter_kind": "remote_agent"}
    )
    assert configured.status_code == 200
    assert configured.json()["adapter_kind"] == "remote_agent"
    registered = client.post("/api/admin/agents", json={"node_id": node_id})
    assert registered.status_code == 200
    first_token = registered.json()["token"]
    assert registered.headers["cache-control"] == "private, no-store"
    assert len(first_token) >= 40
    assert "token" not in client.get("/api/admin/agents").text

    old_headers = {"X-Sub-App-Agent-Token": first_token}
    initial_desired = client.get(
        f"/api/agent/v1/desired/{node_id}", headers=old_headers
    ).json()
    assert initial_desired["apply"] is False
    observed = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=old_headers,
        json={
            "status": "observe",
            "applied_generation": initial_desired["generation"],
        },
    )
    assert observed.status_code == 200
    node_state = next(
        row for row in client.get("/api/admin/nodes").json() if row["id"] == node_id
    )
    assert node_state["per_user_capability"]["ready"] is True
    assert node_state["per_user_capability"]["agent_status"] == "observe"
    enabled = client.patch(
        f"/api/admin/nodes/{node_id}", json={"per_user_enabled": True}
    )
    assert enabled.status_code == 200
    db = Session()
    try:
        friend = Friend(
            uid="agent-rotation-secret-user",
            token="agent-rotation-secret-token",
            per_user_credentials=True,
        )
        db.add(friend)
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node_id))
        db.add(
            UserNodeCredential(
                friend_id=friend.id,
                node_id=node_id,
                protocol="vless",
                credential_name=f"u{friend.id}n{node_id}v1",
                version=1,
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    active_desired = client.get(f"/api/agent/v1/desired/{node_id}", headers=old_headers)
    assert active_desired.status_code == 200
    assert active_desired.headers["cache-control"] == "private, no-store"
    assert active_desired.json()["apply"] is True
    assert len(active_desired.json()["users"]) == 1

    db = Session()
    try:
        agent = db.query(NodeAgent).filter_by(node_id=node_id).one()
        assert agent.token_hash == hashlib.sha256(first_token.encode()).hexdigest()
        assert agent.pending_token_hash is None
    finally:
        db.close()

    rotated = client.post(f"/api/admin/agents/{node_id}/rotate")
    assert rotated.status_code == 200
    second_token = rotated.json()["token"]
    assert rotated.headers["cache-control"] == "private, no-store"
    pending_headers = {"X-Sub-App-Agent-Token": second_token}
    db = Session()
    try:
        generation_before_pending_poll = (
            db.query(NodeAgent).filter_by(node_id=node_id).one().desired_generation
        )
    finally:
        db.close()
    pending_response = client.get(
        f"/api/agent/v1/desired/{node_id}", headers=pending_headers
    )
    pending_desired = pending_response.json()
    assert pending_desired["apply"] is False
    assert pending_desired["users"] == []
    assert pending_response.headers["cache-control"] == "private, no-store"
    db = Session()
    try:
        generation_after_pending_poll = (
            db.query(NodeAgent).filter_by(node_id=node_id).one().desired_generation
        )
    finally:
        db.close()
    assert generation_after_pending_poll == generation_before_pending_poll
    failed_heartbeat = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=pending_headers,
        json={"status": "error", "error": "test failure"},
    )
    assert failed_heartbeat.status_code == 409
    cannot_confirm = client.post(f"/api/admin/agents/{node_id}/rotate/confirm")
    assert cannot_confirm.status_code == 409
    assert (
        client.get(f"/api/agent/v1/desired/{node_id}", headers=old_headers).status_code
        == 200
    )

    heartbeat = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=pending_headers,
        json={"status": "observe", "applied_generation": "ignored"},
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "observe"
    assert heartbeat.json()["traffic_records"] == 0
    assert (
        client.get(f"/api/agent/v1/desired/{node_id}", headers=old_headers).status_code
        == 200
    )

    confirmed = client.post(f"/api/admin/agents/{node_id}/rotate/confirm")
    assert confirmed.status_code == 200
    assert (
        client.get(f"/api/agent/v1/desired/{node_id}", headers=old_headers).status_code
        == 401
    )
    assert (
        client.get(f"/api/agent/v1/desired/{node_id}", headers=pending_headers).json()[
            "apply"
        ]
        is True
    )


def test_pending_agent_heartbeat_cannot_change_active_capabilities():
    db = Session()
    try:
        node = Node(
            name="Staged capability isolation",
            protocol="vless",
            uri="vless://00000000-0000-4000-8000-000000000002@capability.example:443",
            server="capability.example",
        )
        db.add(node)
        db.commit()
        node_id = node.id
    finally:
        db.close()

    client.post("/api/admin/login", json={"password": "test-admin-password"})
    configured = client.patch(
        f"/api/admin/nodes/{node_id}", json={"adapter_kind": "remote_agent"}
    )
    assert configured.status_code == 200
    registered = client.post("/api/admin/agents", json={"node_id": node_id})
    assert registered.status_code == 200
    active_headers = {"X-Sub-App-Agent-Token": registered.json()["token"]}

    initial = client.get(f"/api/agent/v1/desired/{node_id}", headers=active_headers)
    assert initial.status_code == 200
    assert initial.json()["apply"] is False
    assert initial.json()["users"][0]["uuid"].startswith("00000000-")
    active_heartbeat = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=active_headers,
        json={
            "status": "observe",
            "agent_version": "trusted-version",
            "capabilities": {"managed_auth_modes": False},
        },
    )
    assert active_heartbeat.status_code == 200

    rotated = client.post(f"/api/admin/agents/{node_id}/rotate")
    assert rotated.status_code == 200
    pending_headers = {"X-Sub-App-Agent-Token": rotated.json()["token"]}
    pending_heartbeat = client.post(
        f"/api/agent/v1/heartbeat/{node_id}",
        headers=pending_headers,
        json={
            "status": "observe",
            "agent_version": "untrusted-staged-version",
            "capabilities": {"managed_auth_modes": True},
        },
    )
    assert pending_heartbeat.status_code == 200

    still_active = client.get(
        f"/api/agent/v1/desired/{node_id}", headers=active_headers
    )
    assert still_active.status_code == 200
    assert still_active.json()["apply"] is False
    assert len(still_active.json()["users"]) == 1

    db = Session()
    try:
        agent = db.query(NodeAgent).filter_by(node_id=node_id).one()
        assert agent.agent_version == "trusted-version"
        assert agent.capabilities == '{"managed_auth_modes":false}'
    finally:
        db.close()


def test_agent_apply_does_not_reactivate_disabled_or_grace_credentials(tmp_path: Path):
    session_factory = _agent_db(tmp_path)
    db = session_factory()
    try:
        node = Node(name="Remote Hy2", protocol="hysteria2", uri="hysteria2://x")
        enabled = Friend(uid="enabled", token="enabled-token")
        enabled.per_user_credentials = True
        disabled = Friend(uid="disabled", token="disabled-token", enabled=False)
        disabled.per_user_credentials = True
        db.add_all([node, enabled, disabled])
        db.flush()
        active = _add_agent_fixture(db, friend=enabled, node=node, status="active")
        pending = _add_agent_fixture(
            db, friend=enabled, node=node, status="pending", version=2
        )
        grace = _add_agent_fixture(
            db, friend=enabled, node=node, status="grace", version=3
        )
        disabled_row = _add_agent_fixture(
            db, friend=disabled, node=node, status="pending"
        )

        assert _mark_applied(db, node.id, "generation", "generation") == 2
        assert active.status == "active"
        assert pending.status == "active"
        assert grace.status == "grace"
        assert disabled_row.status == "pending"
    finally:
        db.close()
