"""The latency probe must only measure the path real subscribers are
actually on — never a healthier one.

Found while auditing #6: the probe fetched a TEST user's per-user
credential whenever one existed in the database, without checking whether
the per-user-credentials feature was even turned on globally. On a node
where it wasn't, real subscribers were still receiving the shared/base URI
(the one the agent's 24h legacy window drops), while the probe dialed the
TEST user's still-installed credential and reported the node healthy — the
dashboard could stay green through the exact class of outage #4 fixed on
the agent side.

These tests seed a real SQLite DB and call run_probes() end to end, then
read the credential selection back out of the written status file, rather
than re-implementing the query in the test.
"""

import importlib

import pytest

from app.models import (
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
    new_token,
    utcnow,
)


@pytest.fixture
def latency_env(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    monkeypatch.setenv("SUB_APP_DB", str(db_path))
    monkeypatch.setenv("SUB_APP_LATENCY_STATUS", str(tmp_path / "status.json"))
    monkeypatch.setenv("SUB_APP_LATENCY_LOCK", str(tmp_path / "lock"))
    monkeypatch.setenv("SUB_APP_LATENCY_TMP", str(tmp_path / "tmp"))
    import app.latency as latency

    importlib.reload(latency)  # module-level constants read the env at import
    return latency, db_path


def _seed(db_path, *, credential_status="active", credential_protocol="hysteria2"):
    factory = make_session_factory(str(db_path))
    db = factory()
    node = Node(
        name="n1",
        uri="hysteria2://sharedpass@node1.example.test:8443",
        protocol="hysteria2",
        enabled=True,
        sort_order=1,
    )
    db.add(node)
    db.commit()
    db.refresh(node)

    friend = Friend(
        uid="TEST", token=new_token(), enabled=True, per_user_credentials=True
    )
    db.add(friend)
    db.commit()
    db.refresh(friend)

    cred = UserNodeCredential(
        friend_id=friend.id,
        node_id=node.id,
        protocol=credential_protocol,
        version=1,
        status=credential_status,
        credential_name="test-n1-v1",
        created_at=utcnow(),
    )
    db.add(cred)
    db.commit()
    db.close()
    return node.id


def test_feature_flag_off_falls_back_to_base_uri(latency_env, monkeypatch):
    latency, db_path = latency_env
    monkeypatch.setenv("SUB_APP_SECRET", "s")
    monkeypatch.delenv("SUB_APP_PER_USER_CREDENTIALS", raising=False)
    _seed(db_path)

    latency.run_probes()
    status = latency.read_status()
    assert status["nodes"][0]["credential_source"] == "base", (
        "a credential row existing in the DB is not enough — the global "
        "feature flag being off must still fall back to the base URI, "
        "matching what real subscribers receive"
    )


def test_feature_flag_on_uses_per_user_credential(latency_env, monkeypatch):
    latency, db_path = latency_env
    monkeypatch.setenv("SUB_APP_SECRET", "s")
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    _seed(db_path)

    latency.run_probes()
    status = latency.read_status()
    assert status["nodes"][0]["credential_source"] == "user:TEST"


def test_missing_secret_degrades_this_node_not_the_whole_run(latency_env, monkeypatch):
    latency, db_path = latency_env
    monkeypatch.delenv("SUB_APP_SECRET", raising=False)
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    _seed(db_path)

    latency.run_probes()
    status = latency.read_status()
    assert status["status"] != "error", "a missing secret must not blank the dashboard"
    assert (
        len(status["nodes"]) == 1
    ), "the node must still be measured, via the base URI"
    assert status["nodes"][0]["credential_source"] == "base"


def test_grace_credential_is_not_probed(latency_env, monkeypatch):
    latency, db_path = latency_env
    monkeypatch.setenv("SUB_APP_SECRET", "s")
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    _seed(db_path, credential_status="grace")

    latency.run_probes()
    status = latency.read_status()
    assert status["nodes"][0]["credential_source"] == "base", (
        "grace is a rotation courtesy for existing clients, not something "
        "a fresh dial is entitled to — the real subscription endpoint "
        "only ever serves 'active'"
    )


def test_wrong_protocol_credential_is_not_selected(latency_env, monkeypatch):
    latency, db_path = latency_env
    monkeypatch.setenv("SUB_APP_SECRET", "s")
    monkeypatch.setenv("SUB_APP_PER_USER_CREDENTIALS", "1")
    # A stale vless-protocol row for a node that is now hysteria2 — e.g. the
    # node's protocol was repointed and the old credential never revoked.
    _seed(db_path, credential_protocol="vless")

    latency.run_probes()
    status = latency.read_status()
    assert status["nodes"][0]["credential_source"] == "base", (
        "a credential for a different protocol must never be rendered "
        "onto this node's URI"
    )
