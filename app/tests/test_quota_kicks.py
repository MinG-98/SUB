from datetime import timedelta

from app.credentials import credential_stats_id
from app.models import (
    FlowRecord,
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
    utcnow,
)
from app.quota import credential_kick_stats_ids, quota_exceeded_stats_ids
from scripts import proxy_collector


def test_hysteria_stats_api_only_accepts_loopback_listeners():
    assert proxy_collector._loopback_http_base("127.0.0.1:9999") == (
        "http://127.0.0.1:9999"
    )
    assert proxy_collector._loopback_http_base("[::1]:9999") == ("http://[::1]:9999")
    assert proxy_collector._loopback_http_base("localhost:9999") == (
        "http://127.0.0.1:9999"
    )
    for unsafe in ("0.0.0.0:9999", "192.0.2.1:9999", ":9999", "localhost:0"):
        try:
            proxy_collector._loopback_http_base(unsafe)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"non-loopback listener accepted: {unsafe}")


def test_local_hysteria_quota_kicks_only_online_ids_including_old_versions(
    tmp_path, monkeypatch
):
    factory = make_session_factory(str(tmp_path / "quota-kicks.db"))
    db = factory()
    try:
        node = Node(
            name="local quota HY2",
            protocol="hysteria2",
            adapter_kind="local_hy2",
            uri="hysteria2://shared@example.test:443",
        )
        over = Friend(
            uid="over-quota",
            flow_limit_gb=1,
            per_user_credentials=True,
        )
        under = Friend(
            uid="under-quota",
            flow_limit_gb=1,
            per_user_credentials=True,
        )
        expired = Friend(
            uid="expired",
            expires_at=utcnow() - timedelta(days=1),
            per_user_credentials=True,
        )
        revoked_user = Friend(uid="revoked-user", per_user_credentials=True)
        db.add_all([node, over, under, expired, revoked_user])
        db.flush()

        old = UserNodeCredential(
            friend_id=over.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{over.id}n{node.id}",
            version=1,
            status="revoked",
            revoked_at=utcnow(),
        )
        current = UserNodeCredential(
            friend_id=over.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{over.id}n{node.id}",
            version=2,
            status="active",
        )
        below = UserNodeCredential(
            friend_id=under.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{under.id}n{node.id}",
            version=1,
            status="active",
        )
        expired_row = UserNodeCredential(
            friend_id=expired.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{expired.id}n{node.id}",
            version=1,
            status="active",
        )
        explicitly_revoked = UserNodeCredential(
            friend_id=revoked_user.id,
            node_id=node.id,
            protocol="hysteria2",
            credential_name=f"u{revoked_user.id}n{node.id}",
            version=1,
            status="revoked",
            revoked_at=utcnow(),
        )
        db.add_all([old, current, below, expired_row, explicitly_revoked])
        db.add(
            FlowRecord(
                friend_id=over.id,
                node_id=node.id,
                source="hysteria2",
                sample_key="over-quota-sample",
                bytes_in=1024**3,
                bytes_out=0,
                bucket=utcnow(),
            )
        )
        db.commit()

        old_id = credential_stats_id(old)
        current_id = credential_stats_id(current)
        below_id = credential_stats_id(below)
        expired_id = credential_stats_id(expired_row)
        revoked_id = credential_stats_id(explicitly_revoked)
        assert quota_exceeded_stats_ids(db, node.id, "hysteria2") == [
            old_id,
            current_id,
        ]
        assert credential_kick_stats_ids(db, node.id, "hysteria2") == sorted(
            [expired_id, old_id, revoked_id, current_id]
        )

        kicked = []
        monkeypatch.setattr(
            proxy_collector,
            "_hysteria_online",
            lambda: {old_id, below_id, expired_id, revoked_id},
        )
        monkeypatch.setattr(
            proxy_collector, "_hysteria_kick", lambda ids: kicked.extend(ids)
        )

        result = proxy_collector.kick_overquota_hysteria_sessions(db)

        assert result == {"candidates": 4, "online": 3, "kicked": 3}
        assert kicked == sorted([expired_id, old_id, revoked_id])
    finally:
        db.close()
