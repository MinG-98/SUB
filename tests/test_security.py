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

import pytest
import yaml
from fastapi import HTTPException, Request, Response
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

import app.main as main_module
import app.proxy_adapters as proxy_adapters
from app.agent_api import _desired_users, _mark_applied, _record_traffic
from app.converter import uri_with_name
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


@pytest.fixture
def diagnostics_db(tmp_path):
    factory = make_session_factory(str(tmp_path / "diagnostics.db"))
    db = factory()
    friend = Friend(uid="diagnostics", token="private-user-token", device_limit=1)
    node = Node(
        name="fixture",
        protocol="hysteria2",
        uri="hysteria2://private-password@node.invalid:443",
    )
    db.add_all([friend, node])
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    device = Device(
        friend_id=friend.id, fingerprint="private-fingerprint", fetch_count=7
    )
    db.add(device)
    db.commit()
    yield db, friend, node, device
    db.close()


def test_subscription_diagnostics_no_mutation_or_secrets(diagnostics_db):
    import json

    from sqlalchemy import event

    db, friend, node, device = diagnostics_db
    statements = []
    connection = db.connection()

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(connection, "before_cursor_execute", capture)
    try:
        report = main_module.diagnose_subscription(
            friend.id, Response(), target="shadowrocket", device_id=None, db=db, _={}
        )
    finally:
        event.remove(connection, "before_cursor_execute", capture)
    assert statements and all(
        s.lstrip().upper().startswith("SELECT") for s in statements
    )
    assert not db.new and not db.dirty and not db.deleted
    assert report["subscription"]["http_status"] == 403
    assert report["device"]["code"] == "device_limit_reached"
    assert report["subscription"]["rendered_count"] == 1
    encoded = json.dumps(report)
    for secret in [friend.token, node.uri, "private-password", device.fingerprint]:
        assert secret not in encoded
    assert device.fetch_count == 7
    assert db.query(FetchLog).count() == 0
    assert db.query(Device).count() == 1


@pytest.mark.parametrize("target", ["clash", "shadowrocket", "v2ray"])
def test_subscription_diagnostics_matches_delivery(diagnostics_db, target):
    import json

    db, friend, node, device = diagnostics_db
    device.device_token_hash = main_module.device_token_hash("private-device-token")
    device.identity_source = "device_link"
    db.commit()
    report = main_module.diagnose_subscription(
        friend.id, Response(), target=target, device_id=device.id, db=db, _={}
    )
    response = main_module.subscription(
        friend.token,
        Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)}),
        target=target,
        device="private-device-token",
        db=db,
    )
    assert report["subscription"]["http_status"] == response.status_code == 200
    assert report["subscription"]["rendered_count"] == 1
    assert "private-device-token" not in json.dumps(report)
    if target == "clash":
        assert len(yaml.safe_load(response.body)["proxies"]) == 1
    else:
        assert len(base64.b64decode(response.body).decode().splitlines()) == 1


@pytest.mark.parametrize(
    "state", ["blocked", "revoked", "expired", "disabled", "quota"]
)
def test_subscription_diagnostics_reports_admission(diagnostics_db, state):
    db, friend, _, device = diagnostics_db
    device.device_token_hash = main_module.device_token_hash("private-device-token")
    if state == "blocked":
        device.blocked = True
    elif state == "revoked":
        device.device_token_revoked_at = utcnow()
    elif state == "expired":
        friend.expires_at = utcnow() - timedelta(days=1)
    elif state == "disabled":
        friend.enabled = False
    else:
        friend.flow_limit_gb = 1
        db.add(
            FlowRecord(
                friend_id=friend.id,
                node_id=None,
                source="hysteria2",
                bucket=utcnow(),
                bytes_in=1024**3,
                bytes_out=0,
            )
        )
    db.commit()
    report = main_module.diagnose_subscription(
        friend.id, Response(), target="shadowrocket", device_id=device.id, db=db, _={}
    )
    with pytest.raises(HTTPException) as error:
        main_module.subscription(
            friend.token,
            Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)}),
            target="shadowrocket",
            device="private-device-token",
            db=db,
        )
    assert report["subscription"]["http_status"] == error.value.status_code


def test_subscription_diagnostics_protocol_skip_and_stale_agent(
    protocol_boundary, monkeypatch
):
    db, friend, node, _, current = protocol_boundary
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    db.add(
        NodeAgent(
            node_id=node.id,
            token_hash="not-exposed",
            status="ready",
            desired_generation="same",
            applied_generation="same",
            last_seen=utcnow() - timedelta(days=1),
        )
    )
    db.delete(current)
    db.commit()
    report = main_module.diagnose_subscription(
        friend.id, Response(), target="shadowrocket", device_id=None, db=db, _={}
    )
    assert report["subscription"]["http_status"] == 503
    assert report["nodes"][0]["code"] == "credential_unavailable"
    assert report["nodes"][0]["agent"] == {
        "state": "stale",
        "generation_matches": False,
    }


def test_subscription_diagnostics_rejects_other_users_device(diagnostics_db):
    db, friend, _, _ = diagnostics_db
    other = Friend(uid="other-diagnostics", token="other-private")
    db.add(other)
    db.flush()
    other_device = Device(friend_id=other.id, fingerprint="other-fingerprint")
    db.add(other_device)
    db.commit()
    with pytest.raises(HTTPException) as error:
        main_module.diagnose_subscription(
            friend.id,
            Response(),
            target="clash",
            device_id=other_device.id,
            db=db,
            _={},
        )
    assert error.value.status_code == 404


def test_subscription_diagnostics_requires_admin_and_no_store(diagnostics_db):
    db, friend, _, _ = diagnostics_db
    client = TestClient(app)
    endpoint = f"/api/admin/friends/{friend.id}/subscription-diagnostics"
    assert client.get(endpoint).status_code == 401
    app.dependency_overrides[main_module.require_admin] = lambda: {}
    app.dependency_overrides[main_module.get_db] = lambda: db
    try:
        result = client.get(endpoint)
        assert result.status_code == 200
        assert result.headers["cache-control"] == "private, no-store"
        assert client.get(endpoint + "?target=unsupported").status_code == 400
    finally:
        app.dependency_overrides.clear()


@pytest.fixture(params=["vless", "hysteria2"])
def protocol_boundary(request, tmp_path):
    db = make_session_factory(str(tmp_path / "protocol.db"))()
    protocol = request.param
    other = "hysteria2" if protocol == "vless" else "vless"
    friend = Friend(
        uid="protocol-boundary", token="fixture-token", per_user_credentials=True
    )
    node = Node(
        name="fixture",
        protocol=protocol,
        uri=f"{protocol}://fixture@node.invalid:443",
        adapter_kind="remote_agent",
        per_user_enabled=True,
    )
    db.add_all([friend, node])
    db.flush()
    db.add(Allocation(friend_id=friend.id, node_id=node.id))
    stale = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=other,
        credential_name="fixture-old",
        version=99,
        status="active",
    )
    current = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=protocol,
        credential_name="fixture-current",
        version=1,
        status="active",
    )
    db.add_all([stale, current])
    db.commit()
    yield db, friend, node, stale, current
    db.close()


def test_protocol_boundary_rejects_switch_without_mutating_node(protocol_boundary):
    db, _, node, stale, _ = protocol_boundary
    original = node.uri
    with pytest.raises(HTTPException) as error:
        main_module.update_node(
            node.id,
            {
                "uri": f"{stale.protocol}://fixture@other.invalid:443",
                "name": "must-not-save",
            },
            db=db,
            _={},
        )
    assert error.value.status_code == 409
    db.refresh(node)
    assert node.uri == original and node.name == "fixture"
    result = main_module.update_node(node.id, {"name": "safe rename"}, db=db, _={})
    assert result["name"] == "safe rename"


def test_protocol_boundary_filters_subscription_and_desired(
    protocol_boundary, monkeypatch
):
    from app.converter import parse_uri
    from app.credentials import render_credential_uri

    db, friend, node, stale, current = protocol_boundary
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    response = main_module.subscription(
        friend.token, request, target="shadowrocket", device=None, db=db
    )
    uri = base64.b64decode(response.body).decode()
    assert uri == render_credential_uri(node, current)
    assert parse_uri(uri)["scheme"] == node.protocol
    assert [item["credential_id"] for item in _desired_users(db, node.id)] == [
        current.id
    ]
    with pytest.raises(ValueError):
        render_credential_uri(node, stale)
    db.delete(current)
    db.commit()
    with pytest.raises(HTTPException) as error:
        main_module.subscription(
            friend.token, request, target="shadowrocket", device=None, db=db
        )
    assert error.value.status_code == 503


def test_protocol_boundary_blocks_stale_activation_and_rotation(protocol_boundary):
    db, _, node, stale, current = protocol_boundary
    result = proxy_adapters.activate_credential(db, stale)
    assert result.status == "error" and result.last_synced_at is None
    with pytest.raises(HTTPException) as error:
        main_module.rotate_credential(stale.id, db=db, _={})
    assert error.value.status_code == 409
    current.status = "pending"
    assert _mark_applied(db, node.id, "fixture-generation", "fixture-generation") == 1
    assert current.status == "active" and stale.status == "error"


def test_device_slot_conversion_preserves_history_and_survives_network_changes(
    protocol_boundary, monkeypatch
):
    db, friend, node, _, _ = protocol_boundary
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    friend.device_limit = 1

    def request(ip, ua):
        return Request(
            {
                "type": "http",
                "scheme": "https",
                "path": "/",
                "query_string": b"",
                "server": ("testserver", 443),
                "headers": [(b"user-agent", ua.encode())],
                "client": (ip, 1),
            }
        )

    first = request("192.0.2.1", "fixture-client-one")
    main_module.subscription(
        friend.token, first, target="shadowrocket", device=None, db=db
    )
    original = db.query(Device).filter_by(friend_id=friend.id).one()
    device_id, first_seen = original.id, original.first_seen
    with pytest.raises(HTTPException) as error:
        main_module.subscription(
            friend.token,
            request("192.0.2.2", "fixture-client-two"),
            target="shadowrocket",
            device=None,
            db=db,
        )
    assert error.value.status_code == 403
    converted = main_module.rotate_device_link(device_id, first, db=db, _={})
    token = parse_qs(urlsplit(converted["links"]["shadowrocket"]).query)["device"][0]
    for i in range(3):
        response = main_module.subscription(
            friend.token,
            request(f"192.0.2.{i + 10}", f"fixture-client-{i}"),
            target="shadowrocket",
            device=token,
            db=db,
        )
        assert response.status_code == 200
    db.refresh(original)
    assert original.id == device_id and original.first_seen == first_seen
    assert original.fetch_count == 4 and original.identity_source == "device_link"
    assert db.query(Device).filter_by(friend_id=friend.id).count() == 1
    assert db.query(FetchLog).filter_by(device_id=device_id).count() == 4
    original.blocked = True
    db.commit()
    main_module.rotate_device_link(device_id, first, db=db, _={})
    assert original.blocked is True


def test_protocol_boundary_rejects_revoked_history_and_allows_alias_edits(
    protocol_boundary,
):
    db, _, node, stale, current = protocol_boundary
    for row in (stale, current):
        row.revoked_at = utcnow()
        row.status = "revoked"
    db.commit()
    with pytest.raises(HTTPException) as error:
        main_module.update_node(
            node.id,
            {"uri": f"{stale.protocol}://fixture@node.invalid:443"},
            db=db,
            _={},
        )
    assert error.value.status_code == 409
    scheme = "HY2" if node.protocol == "hysteria2" else "VLESS"
    result = main_module.update_node(
        node.id, {"uri": f"{scheme}://fixture@replacement.invalid:8443"}, db=db, _={}
    )
    assert result["protocol"] == current.protocol
    assert node.server == "replacement.invalid"


def test_protocol_boundary_agent_only_and_unmanaged_controls(protocol_boundary):
    db, _, node, stale, current = protocol_boundary
    db.delete(stale)
    db.delete(current)
    db.commit()
    replacement = "hysteria2" if node.protocol == "vless" else "vless"
    payload = {"uri": f"{replacement}://fixture@node.invalid:443"}
    registration = NodeAgent(
        node_id=node.id, token_hash="fixture-hash", status="offline"
    )
    db.add(registration)
    db.commit()
    with pytest.raises(HTTPException) as error:
        main_module.update_node(node.id, payload, db=db, _={})
    assert error.value.status_code == 409
    db.delete(registration)
    db.commit()
    assert (
        main_module.update_node(node.id, payload, db=db, _={})["protocol"]
        == replacement
    )


def test_protocol_boundary_render_identity_and_uri_guards(protocol_boundary):
    from app.credentials import render_credential_uri

    db, _, node, stale, current = protocol_boundary
    original_id = current.node_id
    current.node_id = original_id + 100
    with pytest.raises(ValueError):
        render_credential_uri(node, current)
    current.node_id = original_id
    node.uri = f"{stale.protocol}://fixture@node.invalid:443"
    with pytest.raises(ValueError):
        render_credential_uri(node, current)
    db.rollback()


def test_protocol_boundary_inconsistent_uri_is_skipped_not_server_error(
    protocol_boundary, monkeypatch
):
    db, friend, node, stale, _ = protocol_boundary
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    node.uri = f"{stale.protocol}://fixture@node.invalid:443"
    db.commit()
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    with pytest.raises(HTTPException) as error:
        main_module.subscription(
            friend.token, request, target="shadowrocket", device=None, db=db
        )
    assert error.value.status_code == 503


def test_protocol_boundary_local_extra_cannot_cross_node_or_protocol(protocol_boundary):
    from types import SimpleNamespace

    db, friend, node, stale, current = protocol_boundary
    if node.protocol != "vless":
        assert proxy_adapters._live_vless_rows(db, node.id, extra=stale) == []
        return
    assert stale not in proxy_adapters._live_vless_rows(db, node.id, extra=stale)
    foreign = SimpleNamespace(
        node_id=node.id + 100, protocol="vless", revoked_at=None, friend=friend
    )
    rows = proxy_adapters._live_vless_rows(db, node.id, extra=foreign)
    assert foreign not in rows and current in rows


def test_protocol_boundary_traffic_drops_stale_rows(protocol_boundary):
    db, friend, node, stale, current = protocol_boundary
    sample = {
        "credential_key": credential_stats_id(stale),
        "sample_key": "fixture-stale-sample",
        "source": node.protocol,
        "bytes_in": 12,
        "bytes_out": 34,
    }
    inserted, ack = _record_traffic(db, node.id, [sample])
    assert inserted == 0 and ack == [sample["sample_key"]]
    sample.update(
        credential_key=credential_stats_id(current), sample_key="fixture-current-sample"
    )
    assert _record_traffic(db, node.id, [sample])[0] == 1
    assert db.query(FlowRecord).one().friend_id == friend.id


client = TestClient(app, base_url="https://testserver")


def test_bootstrap_against_control_plane_and_agent(tmp_path, monkeypatch):
    """Real routes + Agent poll; replace only transport, proxy daemon and SSH."""
    import importlib.util
    from argparse import Namespace

    from scripts import bootstrap_node as boot

    spec = importlib.util.spec_from_file_location(
        "bootstrap_real_agent", boot.ROOT / "agent/node-agent.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    admin = TestClient(app, base_url="https://testserver")
    peer = TestClient(app, base_url="https://testserver")
    assert (
        admin.post(
            "/api/admin/login", json={"password": "test-admin-password"}
        ).status_code
        == 200
    )
    a = Namespace(
        public_host="bootstrap.invalid",
        public_port=28443,
        listen_port=8443,
        sni="bootstrap.invalid",
        client=None,
        region="SG",
    )
    ctx = {}

    def api(method, path, data=None):
        if method == "GET" and path.startswith("/api/admin/agents/"):
            ctx["agent"].poll_node(ctx["spec"])
        res = admin.request(method, path, json=data)
        res.raise_for_status()
        return res.json()

    def ssh(_, action, **cfg):
        if action == "verify-owned":
            assert ctx["agent"].authenticate(ctx["spec"]["node_id"], cfg["password"])[
                "ok"
            ]
            return
        assert action == "install"
        proxy = tmp_path / "config.yaml"
        proxy.write_text("auth: {}\n")
        entry = dict(
            node_id=cfg["node_id"],
            token=cfg["token"],
            protocol="hysteria2",
            hysteria_config=str(proxy),
            backup_dir=str(tmp_path / "backups"),
            auth_port=19281,
            stats_port=19282,
        )
        agent = mod.Agent(
            dict(
                endpoint="https://testserver",
                state_path=str(tmp_path / "state.json"),
                nodes=[entry],
            )
        )

        def transport(method, path, token, payload=None):
            res = peer.request(
                method, path, headers={"X-Sub-App-Agent-Token": token}, json=payload
            )
            res.raise_for_status()
            return res.json()

        monkeypatch.setattr(agent, "request_json", transport)
        monkeypatch.setattr(agent, "_service_restart", lambda spec: True)
        monkeypatch.setattr(
            agent, "capabilities", lambda spec: {"managed_auth_modes": True}
        )
        monkeypatch.setattr(agent, "collect_traffic", lambda spec: [])
        ctx.update(agent=agent, spec=entry)

    monkeypatch.setattr(boot, "remote", ssh)
    boot.provision(a, api)
    node = next(r for r in api("GET", "/api/admin/nodes") if r["name"] == a.name)
    assert (
        node["enabled"],
        node["port"],
        node["allocated_to"],
        node["agent"]["status"],
    ) == (True, 28443, 0, "ready")
    assert not node["per_user_enabled"]
    db = Session()
    try:
        saved = db.get(Node, node["id"])
        from app.converter import parse_uri

        assert parse_uri(saved.uri)["name"] == node["name"]
    finally:
        db.close()


def test_all_subscription_formats_use_managed_node_name_without_uri_fragment():
    from urllib.parse import quote, unquote, urlsplit

    from app.converter import parse_uri

    name = "14｜🇸🇬 新加坡 Reality"
    friend = Friend(uid="canonical-label-user", token="canonical-label-token")
    node = Node(
        name=name,
        protocol="vless",
        uri="vless://00000000-0000-0000-0000-000000000042@sg.example:443?security=reality",
        server="sg.example",
    )
    db = Session()
    try:
        db.add_all([friend, node])
        db.flush()
        db.add(Allocation(friend_id=friend.id, node_id=node.id))
        db.commit()
    finally:
        db.close()

    raw = client.get(f"/sub/{friend.token}?target=raw")
    assert raw.status_code == 200
    assert urlsplit(raw.text).fragment == quote(name, safe="")
    assert unquote(urlsplit(raw.text).fragment) == name
    assert parse_uri(raw.text)["name"] == name

    clash = client.get(f"/sub/{friend.token}?target=clash")
    assert clash.status_code == 200
    assert yaml.safe_load(clash.text)["proxies"][0]["name"] == name

    for target in ("v2ray", "base64", "shadowrocket"):
        response = client.get(f"/sub/{friend.token}?target={target}")
        assert base64.b64decode(response.text).decode() == raw.text


def test_user_credential_uri_uses_managed_node_name_even_if_stale_fragment():
    from app.converter import parse_uri
    from app.credentials import render_credential_uri

    node = Node(
        name="15｜🇸🇬 新加坡 Hy2",
        protocol="hysteria2",
        uri="hysteria2://shared@example.com:8443?sni=example.com#old-name",
        server="example.com",
    )
    row = UserNodeCredential(
        friend_id=7,
        node_id=18,
        protocol="hysteria2",
        credential_name="u7n18v1",
        version=1,
        status="active",
    )
    assert parse_uri(render_credential_uri(node, row))["name"] == node.name


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
    from app.converter import parse_uri

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
    assert parse_uri(response.text)["name"] == current.name
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
            uri_with_name(node.uri, node.name),
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


def test_node_traffic_uses_user_attributed_proxy_records_not_nezha_totals(
    tmp_path: Path,
):
    factory = make_session_factory(str(tmp_path / "traffic-reporting.db"))
    db = factory()
    try:
        node = Node(
            name="traffic fixture",
            protocol="hysteria2",
            uri="hysteria2://fixture",
        )
        db.add(node)
        db.flush()
        friends = [
            Friend(uid=f"traffic-user-{index}", token=f"traffic-token-{index}")
            for index in (10, 11)
        ]
        db.add_all(friends)
        db.flush()
        now = utcnow().replace(tzinfo=None)
        db.add_all(
            [
                FlowRecord(
                    node_id=node.id,
                    friend_id=friends[0].id,
                    bucket=now - timedelta(minutes=5),
                    created_at=now,
                    source="hysteria2",
                    bytes_in=101,
                    bytes_out=202,
                ),
                FlowRecord(
                    node_id=node.id,
                    friend_id=friends[1].id,
                    bucket=now - timedelta(minutes=5),
                    created_at=now,
                    source="vless",
                    bytes_in=303,
                    bytes_out=404,
                ),
                FlowRecord(
                    node_id=node.id,
                    bucket=now - timedelta(minutes=5),
                    created_at=now,
                    source="nezha",
                    bytes_in=10**12,
                    bytes_out=10**12,
                ),
                FlowRecord(
                    node_id=node.id,
                    bucket=now - timedelta(minutes=5),
                    created_at=now,
                    source="unknown",
                    bytes_in=10**9,
                    bytes_out=10**9,
                ),
                NodeMetricSample(
                    node_id=node.id,
                    nezha_server_id=1,
                    bucket=now - timedelta(minutes=5),
                    collected_at=utcnow(),
                    delta_in=10**12,
                    delta_out=10**12,
                ),
            ]
        )
        db.commit()

        summary = main_module._node_traffic_summary(db, node.id)
        assert summary["24h"] == {
            "bytes_in": 404,
            "bytes_out": 606,
            "total": 1010,
        }
        assert summary["7d"] == summary["24h"]
        assert summary["30d"] == summary["24h"]
        detail = main_module.node_traffic(node.id, "24h", db=db, _={})
        assert detail["source"] == "proxy_agent"
        assert detail["totals"] == {"bytes_in": 404, "bytes_out": 606}
        assert len(detail["points"]) == 1
        assert detail["points"][0]["bytes_in"] == 404
        report = main_module.node_dict(node, db=db)
        assert report["traffic"]["24h"]["total"] == 1010
        assert report["traffic_source"] == "proxy_agent"
        assert report["traffic_updated_at"] is not None
    finally:
        db.close()
