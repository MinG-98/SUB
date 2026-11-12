"""Exercise Agent data-plane safeguards against real temporary config/state files."""

import importlib.util
import json
import threading
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


class _Completed:
    returncode = 0


def _agent(tmp_path, state=None):
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    agent.state_path = tmp_path / "state.json"
    agent.state = state if state is not None else {"nodes": {}}
    agent.config_meta = {}
    agent.desired = {}
    agent.lock = threading.RLock()
    return agent


def _patch_singbox(monkeypatch, restart_calls):
    monkeypatch.setattr(
        agent_mod, "command_output", lambda _argv, timeout=8: "with_v2ray_api"
    )
    monkeypatch.setattr(
        agent_mod.subprocess, "run", lambda *_args, **_kwargs: _Completed()
    )

    def restart(_self, _spec):
        restart_calls.append(1)
        return True

    monkeypatch.setattr(agent_mod.Agent, "_service_restart", restart)


def test_empty_remote_users_apply_stable_unadvertised_deny_all_users(
    tmp_path, monkeypatch
):
    restart_calls = []
    _patch_singbox(monkeypatch, restart_calls)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "inbounds": [{"tag": "hy2-in", "type": "hysteria2", "users": []}],
                "experimental": {},
            }
        ),
        encoding="utf-8",
    )
    state = {
        "nodes": {
            "42": {
                "legacy_users": [],
                "legacy_until": "2000-01-01T00:00:00+00:00",
            }
        }
    }
    agent = _agent(tmp_path, state)
    spec = {
        "node_id": 42,
        "inbound_tag": "hy2-in",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
        "service": "sing-box.service",
    }

    agent.apply_singbox_hysteria2(spec, {"users": []})
    applied = json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert len(applied) == 1
    assert applied[0]["name"].startswith("sub-app-disabled-")
    assert applied[0]["password"]
    saved = agent_mod.read_json(agent.state_path, {})
    sentinel = saved["nodes"]["42"]["deny_all_users"]["hysteria2"]
    assert sentinel == applied[0]

    restarted_agent = _agent(tmp_path, saved)
    restarted_agent.apply_singbox_hysteria2(spec, {"users": []})
    assert restart_calls == [1], "the same persisted deny-all config must be idempotent"
    assert (
        json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"][0]
        == sentinel
    )


def test_persisted_malformed_managed_hy2_legacy_user_is_not_reinstalled(
    tmp_path, monkeypatch
):
    _patch_singbox(monkeypatch, [])
    bad = {"name": "f1n42v1", "password": ":"}
    shared = {"name": "shared", "password": "fixture-shared"}
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"tag": "hy2-in", "type": "hysteria2", "users": [bad, shared]}
                ]
            }
        )
    )
    agent = _agent(
        tmp_path,
        {
            "nodes": {
                "42": {
                    "legacy_users": [bad, shared],
                    "legacy_until": "2999-01-01T00:00:00+00:00",
                }
            }
        },
    )
    spec = {
        "node_id": 42,
        "inbound_tag": "hy2-in",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
    }
    agent.apply_singbox_hysteria2(spec, {"users": []})
    assert json.loads(path.read_text())["inbounds"][0]["users"] == [shared]


def test_vless_empty_users_apply_stable_unadvertised_deny_all_user(
    tmp_path, monkeypatch
):
    restart_calls = []
    _patch_singbox(monkeypatch, restart_calls)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "inbounds": [{"tag": "vless-in", "type": "vless", "users": []}],
                "experimental": {},
            }
        ),
        encoding="utf-8",
    )
    state = {
        "nodes": {
            "43": {
                "legacy_users": [],
                "legacy_until": "2000-01-01T00:00:00+00:00",
            }
        }
    }
    agent = _agent(tmp_path, state)
    spec = {
        "node_id": 43,
        "inbound_tag": "vless-in",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
        "service": "sing-box.service",
    }

    agent.apply_vless(spec, {"users": []})
    applied = json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert len(applied) == 1
    assert applied[0]["name"].startswith("sub-app-disabled-")
    assert applied[0]["uuid"]
    saved = agent_mod.read_json(agent.state_path, {})
    sentinel = saved["nodes"]["43"]["deny_all_users"]["vless"]
    assert sentinel == applied[0]

    restarted_agent = _agent(tmp_path, saved)
    restarted_agent.apply_vless(spec, {"users": []})
    assert restart_calls == [1]
    assert (
        json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"][0]
        == sentinel
    )


def test_vless_shared_mode_restores_original_user_after_legacy_window(
    tmp_path, monkeypatch
):
    _patch_singbox(monkeypatch, [])
    path = tmp_path / "config.json"
    shared = {"uuid": "00000000-0000-4000-8000-000000000001"}
    path.write_text(
        json.dumps(
            {
                "inbounds": [{"tag": "vless-in", "type": "vless", "users": [shared]}],
                "experimental": {},
            }
        ),
        encoding="utf-8",
    )
    agent = _agent(
        tmp_path,
        {
            "nodes": {
                "46": {
                    "legacy_users": [shared],
                    "legacy_until": "2000-01-01T00:00:00+00:00",
                }
            }
        },
    )
    spec = {
        "node_id": 46,
        "inbound_tag": "vless-in",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
        "service": "sing-box.service",
    }

    agent.apply_vless(
        spec,
        {
            "mode": "shared",
            "users": [
                {
                    "protocol": "vless",
                    "stats_id": "legacy-shared",
                    "uuid": shared["uuid"],
                }
            ],
        },
    )

    applied = json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert applied == [{"name": "legacy-shared", "uuid": shared["uuid"]}]


def test_disabled_vless_apply_removes_legacy_users_even_during_grace(
    tmp_path, monkeypatch
):
    _patch_singbox(monkeypatch, [])
    path = tmp_path / "config.json"
    shared = {"uuid": "00000000-0000-4000-8000-000000000001"}
    path.write_text(
        json.dumps(
            {
                "inbounds": [{"tag": "vless-in", "type": "vless", "users": [shared]}],
                "experimental": {},
            }
        ),
        encoding="utf-8",
    )
    agent = _agent(
        tmp_path,
        {
            "nodes": {
                "48": {
                    "legacy_users": [shared],
                    "legacy_until": "2999-01-01T00:00:00+00:00",
                }
            }
        },
    )
    spec = {
        "node_id": 48,
        "inbound_tag": "vless-in",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
        "service": "sing-box.service",
    }

    agent.apply_vless(spec, {"mode": "disabled", "users": []})

    applied = json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert len(applied) == 1
    assert applied[0]["name"].startswith("sub-app-disabled-")
    assert applied[0]["uuid"] != shared["uuid"]


def test_disabled_singbox_hysteria_apply_removes_legacy_users(tmp_path, monkeypatch):
    _patch_singbox(monkeypatch, [])
    path = tmp_path / "config.json"
    shared = {"name": "shared", "password": "shared-password"}
    path.write_text(
        json.dumps(
            {
                "inbounds": [{"tag": "hy2-in", "type": "hysteria2", "users": [shared]}],
                "experimental": {},
            }
        ),
        encoding="utf-8",
    )
    agent = _agent(
        tmp_path,
        {
            "nodes": {
                "49": {
                    "legacy_users": [shared],
                    "legacy_until": "2999-01-01T00:00:00+00:00",
                }
            }
        },
    )
    spec = {
        "node_id": 49,
        "inbound_tag": "hy2-in",
        "sing_box_binary": "sing-box",
        "sing_box_config": str(path),
        "backup_dir": str(tmp_path / "backups"),
        "service": "sing-box.service",
    }

    agent.apply_singbox_hysteria2(spec, {"mode": "disabled", "users": []})

    applied = json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert len(applied) == 1
    assert applied[0]["name"].startswith("sub-app-disabled-")
    assert applied[0]["password"] != shared["password"]


def test_hysteria_auth_modes_enforce_legacy_expiry_and_reject_disabled_access(
    tmp_path,
):
    agent = _agent(
        tmp_path,
        {
            "nodes": {
                "47": {
                    "legacy_auth": ["shared-password"],
                    "legacy_until": "2000-01-01T00:00:00+00:00",
                }
            }
        },
    )
    agent.desired = {
        47: {
            "enabled": True,
            "mode": "shared",
            "users": [
                {
                    "protocol": "hysteria2",
                    "auth": "current-shared-password",
                    "stats_id": "current-shared",
                }
            ],
        }
    }
    assert agent.authenticate(47, "current-shared-password") == {
        "ok": True,
        "id": "current-shared",
    }
    assert agent.authenticate(47, "shared-password") == {"ok": False}

    agent.state["nodes"]["47"]["legacy_until"] = "2999-01-01T00:00:00+00:00"
    assert agent.authenticate(47, "shared-password") == {
        "ok": True,
        "id": "legacy-shared",
    }
    agent.state["nodes"]["47"]["legacy_until"] = "not-a-valid-timestamp"
    assert agent.authenticate(47, "shared-password") == {"ok": False}

    agent.desired[47] = {
        "enabled": False,
        "mode": "disabled",
        "users": [
            {
                "protocol": "hysteria2",
                "username": "user",
                "password": "credential",
                "stats_id": "user-node-v1",
            }
        ],
    }
    assert agent.authenticate(47, "shared-password") == {"ok": False}
    assert agent.authenticate(47, "current-shared-password") == {"ok": False}
    assert agent.authenticate(47, "user:credential") == {"ok": False}


def test_traffic_outbox_retries_samples_after_failed_heartbeat(tmp_path):
    agent = _agent(tmp_path)
    agent.capabilities = lambda _spec: {}
    agent.collect_traffic = lambda _spec: next(samples)
    samples = iter(
        [
            [
                {
                    "source": "vless",
                    "credential_key": "f1n2v1",
                    "sample_key": "sample-1",
                    "bytes_in": 100,
                    "bytes_out": 200,
                }
            ],
            [],
        ]
    )
    desired = {
        "apply": False,
        "protocol": "vless",
        "generation": "generation-1",
        "users": [],
    }
    posts = []

    def request_json(method, _path, _token, payload=None):
        if method == "GET":
            return desired
        posts.append(payload)
        if len(posts) == 1:
            raise OSError("temporary control-plane outage")
        return {
            "ok": True,
            "kick_stats_ids": [],
            "traffic_ack": ["sample-1"],
        }

    agent.request_json = request_json
    spec = {"node_id": 44, "token": "test-token", "protocol": "vless"}

    agent.poll_node(spec)
    persisted = agent_mod.read_json(agent.state_path, {})
    assert persisted["nodes"]["44"]["pending_traffic"][0]["sample_key"] == "sample-1"
    assert posts[0]["traffic"][0]["sample_key"] == "sample-1"
    assert "traffic" not in posts[1], "error heartbeat must not clear the outbox"

    agent.poll_node(spec)
    assert posts[2]["traffic"][0]["sample_key"] == "sample-1"
    persisted = agent_mod.read_json(agent.state_path, {})
    assert persisted["nodes"]["44"]["pending_traffic"] == []


def test_traffic_outbox_removes_only_server_acknowledged_samples(tmp_path):
    agent = _agent(tmp_path)
    agent.capabilities = lambda _spec: {}
    agent.collect_traffic = lambda _spec: [
        {
            "source": "vless",
            "credential_key": "credential-1",
            "sample_key": "accepted-sample",
            "bytes_in": 1,
            "bytes_out": 2,
        },
        {
            "source": "vless",
            "credential_key": "credential-2",
            "sample_key": "rejected-sample",
            "bytes_in": 3,
            "bytes_out": 4,
        },
    ]
    desired = {
        "apply": False,
        "protocol": "vless",
        "generation": "generation-1",
        "users": [],
    }
    posts = []

    def request_json(method, _path, _token, payload=None):
        if method == "GET":
            return desired
        posts.append(payload)
        return {"ok": True, "traffic_ack": ["accepted-sample"]}

    agent.request_json = request_json
    agent.poll_node({"node_id": 45, "token": "test-token", "protocol": "vless"})

    persisted = agent_mod.read_json(agent.state_path, {})
    pending = persisted["nodes"]["45"]["pending_traffic"]
    assert [item["sample_key"] for item in pending] == ["rejected-sample"]
    assert [item["sample_key"] for item in posts[0]["traffic"]] == [
        "accepted-sample",
        "rejected-sample",
    ]


def test_saturated_traffic_outbox_pauses_collection_and_sends_bounded_batches(
    tmp_path,
):
    existing = [
        {
            "source": "vless",
            "credential_key": f"credential-{index}",
            "sample_key": f"queued-{index}",
            "bytes_in": index + 1,
            "bytes_out": index + 2,
        }
        for index in range(agent_mod.MAX_PENDING_TRAFFIC_RECORDS + 1)
    ]
    agent = _agent(
        tmp_path,
        {"nodes": {"46": {"pending_traffic": existing}}},
    )
    agent.capabilities = lambda _spec: {}
    collection_calls = []

    def collect(_spec):
        collection_calls.append(1)
        return [
            {
                "source": "vless",
                "credential_key": "fresh-credential",
                "sample_key": "fresh-sample",
                "bytes_in": 1,
                "bytes_out": 1,
            }
        ]

    agent.collect_traffic = collect
    posts = []

    def request_json(method, _path, _token, payload=None):
        if method == "GET":
            return {
                "apply": False,
                "protocol": "vless",
                "generation": "generation-1",
                "users": [],
            }
        sent = payload["traffic"]
        posts.append(sent)
        return {
            "ok": True,
            "traffic_ack": [item["sample_key"] for item in sent],
        }

    agent.request_json = request_json
    spec = {"node_id": 46, "token": "test-token", "protocol": "vless"}

    agent.poll_node(spec)
    assert collection_calls == []
    assert len(posts[0]) == agent_mod.MAX_TRAFFIC_BATCH_RECORDS
    persisted = agent_mod.read_json(agent.state_path, {})
    assert len(persisted["nodes"]["46"]["pending_traffic"]) < (
        agent_mod.MAX_PENDING_TRAFFIC_RECORDS
    )
    assert persisted["nodes"]["46"].get("traffic_backpressure") is not True

    agent.poll_node(spec)
    assert collection_calls == [1]
    assert len(posts[1]) == agent_mod.MAX_TRAFFIC_BATCH_RECORDS
