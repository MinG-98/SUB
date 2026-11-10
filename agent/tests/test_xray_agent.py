"""Drive native Xray applies against temporary live, backup, and Agent state files."""

import importlib.util
import json
import socket
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)

LEGACY_ID = "00000000-0000-4000-8000-000000000001"
ALICE = {
    "protocol": "vless",
    "uuid": "00000000-0000-4000-8000-000000000002",
    "stats_id": "f1n17v1",
}
BOB = {
    "protocol": "vless",
    "uuid": "00000000-0000-4000-8000-000000000003",
    "stats_id": "f2n17v1",
}
LOOPBACK_API = "127.0.0.1:10085"


def _reality(tag="front", port=443, listen="127.0.0.1"):
    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {"decryption": "none", "clients": [{"id": LEGACY_ID}]},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": "fixture.invalid:443",
                "serverNames": ["fixture.invalid"],
                "privateKey": "A" * 42 + "E",  # synthetic, never used by a service
                "shortIds": ["0123456789abcdef"],
            },
        },
    }


class LocalNode:
    def __init__(self, root):
        self.path = root / "xray.json"
        self.spec = {
            "node_id": 17,
            "protocol": "vless",
            "engine": "xray",
            "xray_config": str(self.path),
            "xray_binary": str(root / "fixture-xray"),
            "service": "fixture-xray.service",
            "inbound_port": 443,
            "v2ray_api_listen": LOOPBACK_API,
            "backup_dir": str(root / "backups"),
        }
        self.agent_config = {
            "endpoint": "https://control.invalid",
            "state_path": str(root / "agent-state.json"),
            "nodes": [self.spec],
        }
        self.agent = agent_mod.Agent(self.agent_config)
        self.check = Mock(return_value=True)
        self.restart = Mock(return_value=True)
        self.write(
            {
                "inbounds": [_reality()],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            }
        )

    def write(self, config):
        self.path.write_text(json.dumps(config) + "\n", encoding="utf-8")

    def read(self):
        return json.loads(self.path.read_bytes())

    def apply(self, *users, mode="per_user"):
        self.agent.apply_xray(
            self.spec,
            {"protocol": "vless", "mode": mode, "users": [dict(u) for u in users]},
        )


@pytest.fixture
def node(tmp_path, monkeypatch):
    node = LocalNode(tmp_path)
    monkeypatch.setattr(agent_mod, "command_ok", node.check)
    monkeypatch.setattr(agent_mod.Agent, "_service_restart", node.restart)

    def no_external_io(*_args, **_kwargs):
        pytest.fail("unit tests must not start processes or connect to hosts")

    monkeypatch.setattr(agent_mod.subprocess, "Popen", no_external_io)
    monkeypatch.setattr(socket, "create_connection", no_external_io)
    return node


def _clients(config):
    (front,) = [i for i in config["inbounds"] if i.get("tag") == "front"]
    return front["settings"]["clients"]


def _assert_clients(config, *managed, legacy=False):
    clients = _clients(config)
    expected_ids = [u["uuid"] for u in managed] + ([LEGACY_ID] if legacy else [])
    assert sorted(c["id"] for c in clients) == sorted(expected_ids)
    emails = {c["id"]: c.get("email") for c in clients}
    for user in managed:
        assert emails[user["uuid"]] == user["stats_id"]
    assert all(not c.get("flow") for c in clients), "unexpected flow on native clients"


def test_only_the_selected_reality_inbound_changes_and_reapply_is_a_noop(node):
    plain = _reality("plain", listen="127.0.0.2")
    plain["streamSettings"] = {"network": "tcp", "security": "none"}
    trojan = _reality("other-protocol", listen="127.0.0.3")
    trojan.update(protocol="trojan", settings={"clients": [{"password": "fixture"}]})
    decoys = [plain, trojan, _reality("other-port", port=8443)]
    original = node.read()
    original["inbounds"][:0] = decoys  # The correct inbound is deliberately last.
    node.write(original)

    node.apply(ALICE, BOB)
    live = node.read()
    _assert_clients(live, ALICE, BOB, legacy=True)
    for decoy in decoys:
        assert decoy in live["inbounds"]
    expected_front = _reality()
    expected_front["settings"]["clients"] = _clients(live)
    assert expected_front in live["inbounds"], "preserve Reality and transport settings"
    assert live["outbounds"] == original["outbounds"]
    node.restart.assert_called_once()

    first = node.path.read_bytes()
    node.apply(ALICE, BOB)
    assert node.path.read_bytes() == first
    node.restart.assert_called_once()


@pytest.mark.parametrize("matches", [0, 2], ids=["no-match", "ambiguous"])
def test_apply_does_not_guess_a_reality_inbound(node, matches):
    config = node.read()
    config["inbounds"] = [_reality("other-port", port=8443)] + [
        _reality(f"edge-{i}", listen=f"127.0.0.{i + 1}") for i in range(matches)
    ]
    node.write(config)
    before = node.path.read_bytes()
    with pytest.raises((RuntimeError, ValueError)):
        node.apply(ALICE)
    assert node.path.read_bytes() == before
    node.restart.assert_not_called()


def test_original_credential_expires_24h_from_first_apply_even_across_reload(
    node, monkeypatch
):
    start = datetime(2030, 1, 1, tzinfo=timezone.utc)
    now = start
    monkeypatch.setattr(agent_mod, "utcnow", lambda: now)
    node.apply(ALICE)
    _assert_clients(node.read(), ALICE, legacy=True)

    now = start + timedelta(hours=24, seconds=-1)
    node.agent = agent_mod.Agent(node.agent_config)
    node.apply(BOB)
    _assert_clients(node.read(), BOB, legacy=True)

    now = start + timedelta(hours=24, seconds=1)
    node.agent = agent_mod.Agent(node.agent_config)
    node.apply(BOB)
    _assert_clients(node.read(), BOB)


@pytest.mark.parametrize("mode", ["shared", "disabled"])
@pytest.mark.parametrize("adopted", [False, True], ids=["first-apply", "during-grace"])
def test_shared_and_disabled_revoke_prior_credentials(node, mode, adopted):
    if adopted:
        node.apply(ALICE)
        _assert_clients(node.read(), ALICE, legacy=True)
    if mode == "shared":
        shared = {**BOB, "stats_id": "legacy-shared"}
        node.apply(shared, mode=mode)
        _assert_clients(node.read(), shared)
    else:
        node.apply(mode=mode)
        # Deny-all can use an empty list or a private sentinel; neither old
        # credential may be usable. Do not pin a generated ID or its name.
        live_ids = {c["id"] for c in _clients(node.read())}
        assert {LEGACY_ID, ALICE["uuid"]}.isdisjoint(live_ids)


def test_non_vless_desired_credential_is_never_authorized(node):
    before = node.path.read_bytes()
    try:
        node.apply(ALICE, {**BOB, "protocol": "hysteria2"})
    except (RuntimeError, ValueError):
        assert node.path.read_bytes() == before
        node.restart.assert_not_called()
    else:  # Filtering the foreign record is safe too.
        _assert_clients(node.read(), ALICE, legacy=True)


def _validation_path(node, argv):
    binary, *options = map(str, argv)
    assert binary == node.spec["xray_binary"]
    assert any(opt.lstrip("-") == "test" for opt in options)
    for i, option in enumerate(options):
        flag, equals, value = option.partition("=")
        if flag.lstrip("-") in {"c", "config"}:
            return Path(value if equals else options[i + 1])
    pytest.fail("Xray validation was not given a config file")


def test_failed_validation_checks_a_separate_candidate_and_never_swaps_live(node):
    before = node.path.read_bytes()
    inode = node.path.stat().st_ino
    rejected = []

    def reject(argv, *_args, **_kwargs):
        candidate = _validation_path(node, argv)
        assert not candidate.samefile(node.path)
        assert node.path.read_bytes() == before, "validation must precede replacement"
        rejected.append(candidate.read_bytes())
        return False

    node.check.side_effect = reject
    with pytest.raises((RuntimeError, ValueError)):
        node.apply(ALICE)
    assert rejected, "the validator must see the candidate before apply fails"
    for body in rejected:
        _assert_clients(json.loads(body), ALICE, legacy=True)
    assert node.path.read_bytes() == before
    assert node.path.stat().st_ino == inode
    node.restart.assert_not_called()


def test_failed_restart_restores_and_restarts_the_original_config(node):
    original = node.path.read_bytes()
    validated = []
    attempts = []

    def accept(argv, *_args, **_kwargs):
        validated.append(json.loads(_validation_path(node, argv).read_bytes()))
        return True

    def restart(spec):
        assert spec["service"] == node.spec["service"]
        live = node.path.read_bytes()
        if not attempts:
            assert json.loads(live) in validated, "service must get the checked config"
        attempts.append(live)
        return live == original  # Only the known-good config can start.

    node.check.side_effect = accept
    node.restart.side_effect = restart
    with pytest.raises((RuntimeError, ValueError)):
        node.apply(ALICE)
    assert attempts, "the candidate must actually reach the service"
    _assert_clients(json.loads(attempts[0]), ALICE, legacy=True)
    assert node.path.read_bytes() == original
    assert attempts[-1] == original, "the restored config must reach the service too"


def _stats_endpoints(config):
    """Read Xray's direct API listener or the inbound(s) routed to its API tag."""
    api = config["api"]
    assert "StatsService" in api["services"]
    endpoints = []
    if api.get("listen"):
        host, port = api["listen"].rsplit(":", 1)
        endpoints.append((host.strip("[]"), int(port)))
    tags = {
        tag
        for rule in config.get("routing", {}).get("rules", [])
        if api.get("tag") and rule.get("outboundTag") == api["tag"]
        for tag in rule.get("inboundTag", [])
    }
    for inbound in config["inbounds"]:
        if inbound.get("tag") in tags:
            endpoints.append((inbound.get("listen", "0.0.0.0"), int(inbound["port"])))
    return endpoints


@pytest.mark.parametrize(
    ("listen", "existing"),
    [
        (LOOPBACK_API, None),
        ("0.0.0.0:10085", None),
        ("[::]:10085", None),
        ("192.0.2.17:10085", None),
        (LOOPBACK_API, "0.0.0.0:10085"),
    ],
)
def test_stats_api_is_only_exposed_on_loopback(node, listen, existing):
    node.spec["v2ray_api_listen"] = listen
    if existing:
        config = node.read()
        config["api"] = {"tag": "api", "listen": existing, "services": ["StatsService"]}
        node.write(config)
    before = node.path.read_bytes()
    try:
        node.apply(ALICE)
    except (RuntimeError, ValueError):
        if listen == LOOPBACK_API and not existing:
            raise
        assert node.path.read_bytes() == before
        node.restart.assert_not_called()
        return

    live = node.read()
    endpoints = _stats_endpoints(live)
    assert endpoints and all(ip_address(host).is_loopback for host, _ in endpoints)
    if listen == LOOPBACK_API:
        assert ("127.0.0.1", 10085) in endpoints
    assert isinstance(live["stats"], dict)
    alice = next(c for c in _clients(live) if c["id"] == ALICE["uuid"])
    level = live["policy"]["levels"][str(alice.get("level", 0))]
    assert level["statsUserUplink"] is True
    assert level["statsUserDownlink"] is True
