import hashlib
import io
import json
import os
from argparse import Namespace
from datetime import datetime, timedelta, timezone

import pytest

from deploy import bootstrap_worker as worker
from scripts import bootstrap_node as boot


def test_canary_failure_quarantines_only_the_new_node(monkeypatch):
    a = args()
    a.client = "/mock/hy2"
    calls, stops = [], []
    old = dict(name="existing", server="old.invalid", port=443, protocol="vless")
    rows = [old]

    def api(method, path, data=None):
        calls.append((method, path, data))
        if method == "GET":
            return rows
        if method == "POST" and path.endswith("/nodes"):
            rows.append(
                dict(
                    name=data["name"],
                    id=902,
                    server=a.public_host,
                    port=a.public_port,
                    protocol="hysteria2",
                    allocated_to=0,
                )
            )
            return {"created": [data["name"]]}
        if method == "POST":
            return {"token": "fake"}
        assert path.endswith("/902")

    monkeypatch.setattr(
        boot, "remote", lambda _, action, **kw: stops.append((action, kw["owner"]))
    )
    monkeypatch.setattr(boot, "wait_ready", lambda *a, **kw: "first")

    def failed(*_):
        raise RuntimeError("test canary failure")

    monkeypatch.setattr(boot, "canary", failed)
    with pytest.raises(RuntimeError, match="test canary"):
        boot.provision(a, api)
    assert calls[-1] == ("PATCH", "/api/admin/nodes/902", {"enabled": False})
    assert stops[-1] == ("stop-owned", stops[0][1])


def test_install_writes_only_managed_units_and_private_config(monkeypatch, tmp_path):
    units, base = tmp_path / "units", tmp_path / "owned"
    units.mkdir()
    monkeypatch.setattr(worker, "BASE", base)
    monkeypatch.setattr(worker, "UNITS", units)
    monkeypatch.setattr(worker.platform, "machine", lambda: "x86_64")
    monkeypatch.setitem(
        worker.ARTIFACTS, "x86_64", ("amd64", hashlib.sha256(b"example").hexdigest())
    )
    monkeypatch.setattr(
        worker.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"example")
    )
    monkeypatch.setattr(worker, "run", lambda *a, **kw: b"")
    old = os.umask(0o077)
    try:
        worker.install(
            dict(
                owner="one",
                source="# stub",
                token="test-only",
                node_id=12,
                center=boot.CENTER,
                listen_port=8443,
                cert="/etc/test.crt",
                key="/etc/test.key",
            )
        )
    finally:
        os.umask(old)
    assert (base / "agent.json").stat().st_mode & 0o777 == 0o600
    assert (base / "installation-id").read_text() == "one"
    assert {p.name for p in units.iterdir()} == {worker.AGENT, worker.PROXY}
    assert all("test-only" not in p.read_text() for p in units.iterdir())


def args():
    return Namespace(
        name="test-hy2",
        public_host="test.invalid",
        public_port=28443,
        listen_port=8443,
        sni="test.invalid",
        client=None,
    )


def test_existing_endpoint_never_mutated():
    def api(method, path):
        assert method == "GET"
        return [
            dict(name="other", server="test.invalid", port=28443, protocol="hysteria2")
        ]

    with pytest.raises(RuntimeError, match="不.*接管"):
        boot.provision(args(), api)


@pytest.mark.parametrize(
    "age,applied,previous", [(300, "g", None), (1, "old", None), (1, "g", "g")]
)
def test_does_not_accept_stale_or_previous_generation(
    monkeypatch, age, applied, previous
):
    times = iter((0, 0, 100))
    monkeypatch.setattr(boot.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(boot.time, "sleep", lambda _: None)
    row = dict(
        last_seen=(datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat(),
        status="ready",
        desired_generation="g",
        applied_generation=applied,
    )
    with pytest.raises(RuntimeError, match="心跳"):
        boot.wait_ready(lambda *_: row, 1, previous)


def test_digest_mismatch_never_executes_binary_or_installs_units(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "BASE", tmp_path / "owned")
    monkeypatch.setattr(worker, "UNITS", tmp_path / "units")
    monkeypatch.setattr(worker.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        worker.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"bad artifact")
    )
    monkeypatch.setattr(
        worker, "run", lambda *a, **kw: pytest.fail("unexpected subprocess")
    )
    old = os.umask(0o077)
    try:
        with pytest.raises(ValueError, match="摘要"):
            worker.install({})
        with pytest.raises(FileExistsError):
            worker.install({})
    finally:
        os.umask(old)


def test_secrets_in_stdin_not_ssh_argv(monkeypatch):
    a = args()
    a.cert, a.key, a.acme_email = "/etc/c", "/etc/k", None
    a.identity, a.ssh_port, a.ssh_host = "/local/key", 2222, "test.invalid"

    def fake(cmd, **kw):
        assert "StrictHostKeyChecking=yes" in cmd
        assert "only-example-token" not in str(cmd)
        assert json.loads(kw["input"])["token"] == "only-example-token"

    monkeypatch.setattr(boot.subprocess, "run", fake)
    boot.remote(a, "install", token="only-example-token")
