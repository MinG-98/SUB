"""Reject mixed-protocol desired state before touching proxy config or Agent state."""

import importlib.util
import json
import threading
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "protocol_agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


@pytest.mark.parametrize(
    "method,protocol,wrong",
    [
        (
            "apply_singbox_hysteria2",
            "hysteria2",
            {"protocol": "vless", "uuid": "fixture"},
        ),
        ("apply_hysteria", "hysteria2", {"protocol": "vless", "uuid": "fixture"}),
        (
            "apply_vless",
            "vless",
            {"protocol": "hysteria2", "username": "fixture", "password": "fixture"},
        ),
        (
            "apply_xray",
            "vless",
            {"protocol": "hysteria2", "username": "fixture", "password": "fixture"},
        ),
    ],
)
@pytest.mark.parametrize("mode", ["per_user", "shared"])
def test_reject_mixed_protocol_before_any_config_access(method, protocol, wrong, mode):
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    with pytest.raises(ValueError, match="desired"):
        getattr(agent, method)(
            {},
            {
                "protocol": protocol,
                "mode": mode,
                "users": [{"stats_id": "fixture", **wrong}],
            },
        )


@pytest.mark.parametrize(
    "user",
    [
        {"protocol": "hysteria2"},
        {"username": "", "password": ""},
        {"username": "fixture", "password": None},
    ],
)
def test_reject_empty_hy2_material_instead_of_colon_password(user):
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    with pytest.raises(ValueError, match="desired"):
        agent.apply_singbox_hysteria2({}, {"users": [{"stats_id": "fixture", **user}]})


def test_poll_rejects_mixed_batch_before_publishing_auth_cache():
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    previous = {"protocol": "hysteria2", "users": []}
    agent.desired = {1: previous}
    agent.lock = threading.RLock()
    posts = []
    valid = {
        "protocol": "hysteria2",
        "stats_id": "fixture-good",
        "username": "fixture",
        "password": "fixture-pass",
    }
    invalid = {"protocol": "vless", "stats_id": "fixture-bad", "uuid": "fixture"}

    def transport(method, path, token, payload=None):
        if method == "GET":
            return {"protocol": "hysteria2", "apply": True, "users": [valid, invalid]}
        posts.append(payload)
        return {"ok": True}

    agent.request_json = transport
    agent.capabilities = lambda _: {}
    agent.poll_node({"node_id": 1, "protocol": "hysteria2", "token": "fixture-token"})
    assert agent.desired[1] is previous
    assert len(posts) == 1 and posts[0]["status"] == "error"
    assert posts[0]["error"] == "ValueError"


@pytest.mark.parametrize(
    "protocol,user,mode",
    [
        ("hysteria2", {"username": "fixture", "password": "fixture-pass"}, "per_user"),
        ("hysteria2", {"auth": "single-shared-token"}, "shared"),
        ("vless", {"uuid": "00000000-0000-4000-8000-000000000001"}, "per_user"),
    ],
)
def test_valid_legacy_field_shapes_remain_supported(protocol, user, mode):
    agent_mod.Agent.validate_desired_users(
        {"mode": mode, "users": [{"stats_id": "fixture", **user}]}, protocol
    )


@pytest.mark.parametrize("suffix", [".json", ".yaml"])
def test_explicit_empty_hy2_legacy_is_not_recaptured_during_adoption(
    tmp_path, monkeypatch, suffix
):
    path = tmp_path / ("hy2" + suffix)
    path.write_text(
        json.dumps(
            {
                "auth": {
                    "type": "userpass",
                    "userpass": {"managed": "private-test-password"},
                }
            }
        )
    )
    spec = {
        "node_id": 6,
        "protocol": "hysteria2",
        "hysteria_config": str(path),
        "auth_port": 19281,
        "stats_port": 19282,
        "backup_dir": str(tmp_path / "backups"),
    }
    config = {
        "endpoint": "https://control.invalid",
        "state_path": str(tmp_path / "state.json"),
        "nodes": [spec],
    }
    agent = agent_mod.Agent(config)
    agent.state = {
        "nodes": {"6": {"legacy_auth": [], "legacy_until": "2099-01-01T00:00:00+00:00"}}
    }
    monkeypatch.setattr(agent_mod.Agent, "_service_restart", lambda *_: True)
    desired = {"protocol": "hysteria2", "mode": "per_user", "users": []}
    agent.apply_hysteria(spec, desired)
    if suffix == ".json":
        assert json.loads(path.read_text())["auth"]["type"] == "http"
    first = path.read_bytes()
    monkeypatch.setattr(
        agent_mod.Agent,
        "_service_restart",
        lambda *_: pytest.fail("unchanged config must not restart the service"),
    )
    agent.apply_hysteria(spec, desired)
    assert path.read_bytes() == first
    reloaded = agent_mod.Agent(config)
    reloaded.desired[6] = desired
    assert reloaded.node_state(6)["legacy_auth"] == []
    assert reloaded.authenticate(6, "managed:private-test-password") == {"ok": False}
