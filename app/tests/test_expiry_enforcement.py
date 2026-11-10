from datetime import timedelta

from app import agent_api, proxy_adapters
from app.credentials import credential_values
from app.models import Friend, Node, UserNodeCredential, make_session_factory, utcnow


def test_expired_friend_is_removed_from_remote_and_local_proxy_auth_paths(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SUB_APP_SECRET", "test-expiry-secret")
    factory = make_session_factory(str(tmp_path / "expiry.db"))
    db = factory()
    try:
        expired_at = utcnow() - timedelta(days=1)
        remote = Node(
            name="remote hy2",
            protocol="hysteria2",
            adapter_kind="remote_agent",
            per_user_enabled=True,
            uri="hysteria2://example.test:443",
        )
        local_hy2 = Node(
            name="local hy2",
            protocol="hysteria2",
            adapter_kind="local_hy2",
            uri="hysteria2://example.test:443",
        )
        local_vless = Node(
            name="local vless",
            protocol="vless",
            adapter_kind="local_vless",
            uri="vless://uuid@example.test:443",
        )
        expired_friend = Friend(
            uid="expired",
            per_user_credentials=True,
            expires_at=expired_at,
        )
        db.add_all([remote, local_hy2, local_vless, expired_friend])
        db.flush()
        remote_row = UserNodeCredential(
            friend_id=expired_friend.id,
            node_id=remote.id,
            protocol="hysteria2",
            credential_name=f"u{expired_friend.id}n{remote.id}",
            version=1,
            status="active",
        )
        hy2_row = UserNodeCredential(
            friend_id=expired_friend.id,
            node_id=local_hy2.id,
            protocol="hysteria2",
            credential_name=f"u{expired_friend.id}n{local_hy2.id}",
            version=1,
            status="active",
        )
        vless_row = UserNodeCredential(
            friend_id=expired_friend.id,
            node_id=local_vless.id,
            protocol="vless",
            credential_name=f"u{expired_friend.id}n{local_vless.id}",
            version=1,
            status="active",
        )
        db.add_all([remote_row, hy2_row, vless_row])
        db.commit()

        assert agent_api._desired_users(db, remote.id) == []
        monkeypatch.setattr(
            proxy_adapters, "legacy_hysteria_allowed", lambda _auth: False
        )
        hy2_values = credential_values(hy2_row)
        assert (
            proxy_adapters.authenticate_hysteria(
                db, f"{hy2_values['username']}:{hy2_values['password']}"
            )
            is None
        )
        assert proxy_adapters._live_vless_rows(db, local_vless.id) == []
    finally:
        db.close()


def test_expired_node_rejects_local_legacy_hysteria_auth(tmp_path, monkeypatch):
    factory = make_session_factory(str(tmp_path / "expired-node.db"))
    db = factory()
    try:
        node = Node(
            name="expired local hy2",
            protocol="hysteria2",
            adapter_kind="local_hy2",
            uri="hysteria2://shared@example.test:443",
            expires_at=utcnow() - timedelta(days=1),
        )
        db.add(node)
        db.commit()
        monkeypatch.setattr(
            proxy_adapters, "legacy_hysteria_allowed", lambda _auth: True
        )

        assert (
            proxy_adapters.authenticate_hysteria(db, "legacy-shared-password") is None
        )
    finally:
        db.close()
