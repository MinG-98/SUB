from app.credentials import credential_stats_id
from app.models import (
    Allocation,
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
)
from app.proxy_adapters import (
    _live_vless_rows,
    authenticate_hysteria,
)
from app.quota import credential_kick_stats_ids
from scripts.reconciler import reconcile


def test_reconciler_revokes_allocated_credential_when_node_is_disabled(tmp_path):
    factory = make_session_factory(str(tmp_path / "disabled-node.db"))
    db = factory()
    try:
        node = Node(
            name="disabled remote",
            protocol="hysteria2",
            adapter_kind="remote_agent",
            uri="hysteria2://shared@example.test:443",
            enabled=False,
            per_user_enabled=True,
        )
        friend = Friend(uid="disabled-node-user", per_user_credentials=True)
        db.add_all([node, friend])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name="disabled-node-user-v1",
            version=1,
            status="active",
        )
        db.add_all([credential, Allocation(friend_id=friend.id, node_id=node.id)])
        db.commit()

        result = reconcile(db)

        db.refresh(credential)
        assert result["revoked"] == 1
        assert credential.status == "revoked"
        assert credential.revoked_at is not None
    finally:
        db.close()


def test_disabled_node_kicks_all_users_and_legacy_shared_session(tmp_path):
    factory = make_session_factory(str(tmp_path / "disabled-kicks.db"))
    db = factory()
    try:
        node = Node(
            name="disabled local HY2",
            protocol="hysteria2",
            adapter_kind="local_hy2",
            uri="hysteria2://shared@example.test:443",
            enabled=False,
        )
        friend = Friend(uid="disabled-kick-user", per_user_credentials=True)
        db.add_all([node, friend])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name="disabled-kick-user-v1",
            version=1,
            status="active",
        )
        db.add(credential)
        db.commit()

        assert credential_kick_stats_ids(db, node.id, "hysteria2") == sorted(
            [credential_stats_id(credential), "legacy-shared"]
        )
    finally:
        db.close()


def test_remote_shared_mode_kicks_old_per_user_sessions(tmp_path):
    factory = make_session_factory(str(tmp_path / "shared-mode-kicks.db"))
    db = factory()
    try:
        node = Node(
            name="remote shared HY2",
            protocol="hysteria2",
            adapter_kind="remote_agent",
            uri="hysteria2://shared@example.test:443",
            enabled=True,
            per_user_enabled=False,
        )
        friend = Friend(uid="shared-mode-user", per_user_credentials=True)
        db.add_all([node, friend])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name="shared-mode-user-v1",
            version=1,
            status="active",
        )
        db.add(credential)
        db.commit()

        assert credential_kick_stats_ids(db, node.id, "hysteria2") == [
            credential_stats_id(credential)
        ]
    finally:
        db.close()


def test_disabled_local_vless_node_never_syncs_live_user_credentials(tmp_path):
    factory = make_session_factory(str(tmp_path / "disabled-vless.db"))
    db = factory()
    try:
        node = Node(
            name="disabled local VLESS",
            protocol="vless",
            adapter_kind="local_vless",
            uri="vless://00000000-0000-4000-8000-000000000001@example.test:443",
            enabled=False,
        )
        friend = Friend(uid="disabled-vless-user", per_user_credentials=True)
        db.add_all([node, friend])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="vless",
            credential_name="disabled-vless-user-v1",
            version=1,
            status="active",
        )
        db.add(credential)
        db.commit()

        assert _live_vless_rows(db, node.id) == []
    finally:
        db.close()


def test_disabled_local_hysteria_rejects_legacy_auth(tmp_path, monkeypatch):
    from app import proxy_adapters

    factory = make_session_factory(str(tmp_path / "disabled-hysteria.db"))
    db = factory()
    try:
        node = Node(
            name="disabled local HY2",
            protocol="hysteria2",
            adapter_kind="local_hy2",
            uri="hysteria2://shared-password@example.test:443",
            enabled=False,
        )
        db.add(node)
        db.commit()
        monkeypatch.setattr(
            proxy_adapters, "legacy_hysteria_allowed", lambda _auth: True
        )

        assert authenticate_hysteria(db, "shared-password") is None
    finally:
        db.close()
