from app.agent_api import _record_traffic
from app.credentials import credential_stats_id
from app.models import (
    FlowRecord,
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
)
from app.proxy_adapters import adapter_info


def test_agent_traffic_ack_is_per_sample_and_idempotent(tmp_path):
    factory = make_session_factory(str(tmp_path / "traffic-ack.db"))
    db = factory()
    try:
        node = Node(
            name="remote VLESS",
            protocol="vless",
            adapter_kind="remote_agent",
            uri="vless://00000000-0000-4000-8000-000000000001@example.test:443",
        )
        friend = Friend(uid="traffic-user", per_user_credentials=True)
        db.add_all([node, friend])
        db.flush()
        credential = UserNodeCredential(
            friend_id=friend.id,
            node_id=node.id,
            protocol="vless",
            credential_name="traffic-user-node-v1",
            version=1,
            status="active",
        )
        db.add(credential)
        db.commit()

        source = adapter_info(node)["source"]
        key = credential_stats_id(credential)
        payload = [
            {
                "credential_key": key,
                "sample_key": "accepted-sample",
                "source": source,
                "bytes_in": 100,
                "bytes_out": 200,
            },
            {
                "credential_key": "deleted-or-revoked-credential",
                "sample_key": "discarded-sample",
                "source": source,
                "bytes_in": 300,
                "bytes_out": 400,
            },
        ]

        inserted, acknowledged = _record_traffic(db, node.id, payload)
        db.commit()
        assert inserted == 1
        assert acknowledged == ["accepted-sample", "discarded-sample"]
        assert db.query(FlowRecord).count() == 1

        # If the HTTP response was lost, the retry is still acknowledged even
        # though INSERT OR IGNORE reports no newly inserted rows.
        inserted, retry_ack = _record_traffic(db, node.id, payload)
        assert inserted == 0
        assert retry_ack == acknowledged
        assert db.query(FlowRecord).count() == 1
    finally:
        db.close()
