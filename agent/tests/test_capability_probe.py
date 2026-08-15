"""Regression tests for the agent's bounded sing-box capability probes."""

import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent.parent / "node-agent.py"
if not MODULE_PATH.is_file():
    MODULE_PATH = Path(__file__).with_name("node-agent.py")
spec = importlib.util.spec_from_file_location("agent", MODULE_PATH)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


def _agent(tmp_path):
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    agent.state = {"nodes": {}}
    agent.state_path = tmp_path / "state.json"
    agent.config_meta = {}
    return agent


def _spec(config_path):
    return {
        "node_id": 13,
        "protocol": "vless",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(config_path),
        "v2ray_api_listen": "127.0.0.1:10085",
    }


def _write_config(path, users):
    config = {
        "inbounds": [
            {"tag": "reality-in", "type": "vless", "users": users},
        ],
        "experimental": {
            "v2ray_api": {
                "listen": "127.0.0.1:10085",
                "stats": {
                    "enabled": True,
                    "inbounds": ["reality-in"],
                    "users": [u["name"] for u in users if u.get("name")],
                },
            }
        },
    }
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def test_configured_api_avoids_repeated_cli_probe(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    _write_config(config_path, [{"name": "f1n13v1", "uuid": "u1"}])
    agent = _agent(tmp_path)
    node_spec = _spec(config_path)

    def fail_probe(*_args, **_kwargs):
        raise AssertionError("version must not run when config declares the API")

    monkeypatch.setattr(agent_mod, "command_output", fail_probe)

    assert agent._singbox_has_v2ray_api(node_spec) is True
    assert agent.capabilities(node_spec)["vless_v2ray_api"] is True


def test_unchanged_vless_config_skips_probe_and_restart(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    _write_config(config_path, [{"name": "f1n13v1", "uuid": "u1"}])
    agent = _agent(tmp_path)
    agent.state["nodes"]["13"] = {
        "legacy_users": [],
        "legacy_until": "2000-01-01T00:00:00+00:00",
    }
    node_spec = _spec(config_path)

    def fail_probe(*_args, **_kwargs):
        raise AssertionError("unchanged config must not probe the binary")

    monkeypatch.setattr(agent_mod, "command_output", fail_probe)
    monkeypatch.setattr(
        agent_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unchanged config must not run sing-box check")
        ),
    )
    monkeypatch.setattr(
        agent_mod.Agent,
        "_service_restart",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unchanged config must not restart sing-box")
        ),
    )

    agent.apply_vless(
        node_spec, {"users": [{"stats_id": "f1n13v1", "uuid": "u1"}]}
    )


def test_failed_traffic_helper_is_backed_off(tmp_path, monkeypatch):
    helper = tmp_path / "stats-helper"
    helper.write_text("placeholder", encoding="utf-8")
    agent = _agent(tmp_path)
    node_spec = _spec(tmp_path / "missing.json")
    node_spec["vless_stats_binary"] = str(helper)
    calls = []

    def empty_helper(*_args, **_kwargs):
        calls.append(1)
        return ""

    monkeypatch.setattr(agent_mod, "command_output", empty_helper)

    assert agent.collect_vless_traffic(node_spec) == []
    assert agent.collect_vless_traffic(node_spec) == []
    assert len(calls) == 1
