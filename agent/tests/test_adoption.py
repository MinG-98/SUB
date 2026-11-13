"""Native adoption plans are exact, read-only, and never start a real service."""

import builtins
import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

AGENT_DIR = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "adoption_under_test", AGENT_DIR / "adopt.py"
)
adopt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopt)
spec = importlib.util.spec_from_file_location(
    "adoption_test_agent", AGENT_DIR / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)

NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)
UNTIL = NOW + timedelta(hours=1)
FLOW = "xtls-rprx-vision"
UUIDS = [f"00000000-0000-4000-8000-{n:012d}" for n in range(1, 5)]
SERVICE = "legacy-node-agent.service"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign_desired(desired):
    # Independent of adopt.digest/encoded: match the control-plane wire contract.
    payload = {
        key: desired[key]
        for key in ("node_id", "protocol", "enabled", "mode", "apply", "users")
    }
    desired["generation"] = sha256(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    )


def forbidden(*args, **kwargs):
    pytest.fail("adoption must not perform unexpected process/network/write I/O")


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    monkeypatch.setattr(adopt.subprocess, "Popen", forbidden)
    monkeypatch.setattr(adopt.subprocess, "run", forbidden)
    monkeypatch.setattr(adopt.subprocess, "check_output", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(agent_mod.Agent, "request_json", forbidden)
    monkeypatch.setattr(agent_mod.Agent, "__init__", forbidden)


@pytest.fixture
def case(tmp_path):
    # macOS /var is a symlink; preparation intentionally rejects symlink parents.
    root = tmp_path.resolve()
    paths = {17: root / "xray.json", 18: root / "hysteria.yaml"}
    configs = {
        17: {
            "inbounds": [
                {
                    "tag": "native-reality",
                    "port": 443,
                    "protocol": "vless",
                    "streamSettings": {"security": "reality"},
                    "settings": {
                        "clients": [
                            {"id": UUIDS[0], "email": "f1n17v1", "flow": FLOW},
                            {"id": UUIDS[1], "email": "f2n17v1", "flow": FLOW},
                            {"id": UUIDS[2], "email": "shared", "flow": FLOW},
                        ]
                    },
                }
            ]
        },
        18: {
            "listen": ":8443",
            "auth": {
                "type": "userpass",
                "userpass": {
                    "f1n18v1": "managed-one",
                    "f2n18v1": "managed-two",
                    "shared": "shared-password",
                },
            },
        },
    }
    desired = {
        17: {
            "node_id": 17,
            "protocol": "vless",
            "enabled": True,
            "mode": "per_user",
            "apply": True,
            "users": [
                {"protocol": "vless", "stats_id": f"f{n}n17v1", "uuid": UUIDS[n - 1]}
                for n in (1, 2)
            ],
        },
        18: {
            "node_id": 18,
            "protocol": "hysteria2",
            "enabled": True,
            "mode": "per_user",
            "apply": True,
            "users": [
                {
                    "protocol": "hysteria2",
                    "stats_id": f"f{n}n18v1",
                    "username": f"f{n}n18v1",
                    "password": password,
                }
                for n, password in ((1, "managed-one"), (2, "managed-two"))
            ],
        },
    }
    for payload in desired.values():
        sign_desired(payload)
    manifest = {
        "legacy_deadline": UNTIL.isoformat(),
        "legacy_service": SERVICE,
        "shared_sha256": {
            "17": [sha256(UUIDS[2].encode())],
            "18": [sha256(b"shared:shared-password")],
        },
        "agent_config": {
            "endpoint": "https://control.example.invalid",
            "state_path": str(root / "private" / "state.json"),
            "nodes": [
                {
                    "node_id": 17,
                    "protocol": "vless",
                    "engine": "xray",
                    "inbound_tag": "native-reality",
                    "inbound_port": 443,
                    "xray_config": str(paths[17]),
                },
                {
                    "node_id": 18,
                    "protocol": "hysteria2",
                    "hysteria_config": str(paths[18]),
                },
            ],
        },
    }
    result = SimpleNamespace(
        root=root, paths=paths, configs=configs, desired=desired, manifest=manifest
    )
    write_configs(result)
    return result


def write_configs(case):
    case.paths[17].write_text(json.dumps(case.configs[17]), encoding="utf-8")
    case.paths[18].write_text(yaml.safe_dump(case.configs[18]), encoding="utf-8")


def test_revoke_only_explicit_node_without_recapturing_managed_users(case):
    case.manifest["shared_action"] = {"18": "revoke"}
    state, report, _ = adopt.build_plan(case.manifest, agent_mod, case.desired, NOW)
    assert state["nodes"]["18"]["legacy_auth"] == []
    assert len(state["nodes"]["17"]["xray_legacy"]) == 1
    assert report["nodes"][1]["revoked_shared_users"] == 1
    assert report["nodes"][1]["shared_users"] == 0


def test_revocation_still_requires_exact_shared_fingerprint(case):
    case.manifest["shared_action"] = {"18": "revoke"}
    case.manifest["shared_sha256"]["18"] = []
    with pytest.raises(adopt.AdoptionError, match="unapproved"):
        adopt.build_plan(case.manifest, agent_mod, case.desired, NOW)


@pytest.mark.parametrize("actions", [{"99": "revoke"}, {"18": "forever"}, []])
def test_invalid_revocation_policy_refused(case, actions):
    case.manifest["shared_action"] = actions
    with pytest.raises(adopt.AdoptionError, match="action"):
        adopt.build_plan(case.manifest, agent_mod, case.desired, NOW)


def clients(case):
    return case.configs[17]["inbounds"][0]["settings"]["clients"]


def tree_snapshot(root):
    return {
        str(path.relative_to(root)): (
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in root.rglob("*")
    }


def plan(case, monkeypatch):
    """Check purity on every success AND refusal, including transient writes."""
    before = tree_snapshot(case.root)
    inputs = copy.deepcopy((case.manifest, case.desired))

    def readonly_open(original):
        def checked(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in "wax+"):
                forbidden()
            return original(file, mode, *args, **kwargs)

        return checked

    original_os_open = os.open

    def readonly_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            forbidden()
        return original_os_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as guard:
            guard.setattr(builtins, "open", readonly_open(builtins.open))
            guard.setattr(io, "open", readonly_open(io.open))
            guard.setattr(os, "open", readonly_os_open)
            for name in ("mkdir", "unlink", "remove", "rename", "replace", "chmod"):
                guard.setattr(os, name, forbidden)
            guard.setattr(adopt, "prepare_state", forbidden)
            return adopt.build_plan(case.manifest, agent_mod, case.desired, now=NOW)
    finally:
        assert tree_snapshot(case.root) == before
        assert (case.manifest, case.desired) == inputs


def test_exact_match_has_only_approved_shared_state_and_bound_hash(case, monkeypatch):
    state, report, files = plan(case, monkeypatch)
    assert state == {
        "nodes": {
            "17": {
                "xray_legacy": [clients(case)[2]],
                "xray_legacy_until": UNTIL.timestamp(),
                "xray_flow": FLOW,
            },
            "18": {
                "legacy_auth": ["shared:shared-password"],
                "legacy_until": UNTIL.isoformat(),
            },
        }
    }
    assert files == {
        str(path): sha256(path.read_bytes()) for path in case.paths.values()
    }
    binding = {
        "manifest_sha256": sha256(canonical(case.manifest)),
        "files": files,
        "generations": {str(k): v["generation"] for k, v in case.desired.items()},
        "state_sha256": sha256(canonical(state)),
    }
    assert report == {
        "ok": True,
        "plan_sha256": sha256(canonical(binding)),
        "nodes": [
            {
                "node_id": 17,
                "protocol": "vless",
                "managed_users": 2,
                "shared_users": 1,
                "shared_action": "grace",
            },
            {
                "node_id": 18,
                "protocol": "hysteria2",
                "managed_users": 2,
                "shared_users": 1,
                "shared_action": "grace",
            },
        ],
        "legacy_deadline": UNTIL.isoformat(),
        "proxy_configs_changed": False,
    }
    assert plan(case, monkeypatch) == (state, report, files)
    assert not Path(case.manifest["agent_config"]["state_path"]).parent.exists()


def test_plan_leaves_existing_state_untouched(case, monkeypatch):
    path = Path(case.manifest["agent_config"]["state_path"])
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b'{"existing":"must survive"}\n')
    plan(case, monkeypatch)


@pytest.mark.parametrize("node", [17, 18])
def test_unknown_live_credential_refused(case, monkeypatch, node):
    if node == 17:
        clients(case).append({"id": UUIDS[3], "email": "unknown", "flow": FLOW})
    else:
        case.configs[18]["auth"]["userpass"]["unknown"] = "unknown-password"
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="unapproved or missing shared"):
        plan(case, monkeypatch)


@pytest.mark.parametrize("node", [17, 18])
def test_missing_managed_credential_refused(case, monkeypatch, node):
    if node == 17:
        clients(case).pop(0)
    else:
        del case.configs[18]["auth"]["userpass"]["f1n18v1"]
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="missing control-plane credentials"):
        plan(case, monkeypatch)


@pytest.mark.parametrize("node", [17, 18])
def test_duplicate_desired_identity_refused(case, monkeypatch, node):
    desired = case.desired[node]
    desired["users"][1]["stats_id"] = desired["users"][0]["stats_id"]
    sign_desired(desired)
    with pytest.raises(adopt.AdoptionError, match="identity is ambiguous"):
        plan(case, monkeypatch)


@pytest.mark.parametrize("where", ["live", "desired"])
def test_duplicate_xray_uuid_refused(case, monkeypatch, where):
    if where == "live":
        clients(case).append(dict(clients(case)[0]))
        write_configs(case)
    else:
        case.desired[17]["users"][1]["uuid"] = UUIDS[0]
        sign_desired(case.desired[17])
    with pytest.raises(adopt.AdoptionError, match="duplicate Xray credentials"):
        plan(case, monkeypatch)


def test_duplicate_hy2_credential_refused(case, monkeypatch):
    users = case.desired[18]["users"]
    users[1].update(username=users[0]["username"], password=users[0]["password"])
    sign_desired(case.desired[18])
    with pytest.raises(adopt.AdoptionError, match="duplicate Hy2 credentials"):
        plan(case, monkeypatch)


def test_live_xray_identity_mismatch_refused(case, monkeypatch):
    clients(case)[0]["email"] = "f99n17v1"
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="identity differs"):
        plan(case, monkeypatch)


@pytest.mark.parametrize("node", [17, 18])
@pytest.mark.parametrize("field", ["node_id", "protocol", "generation"])
def test_desired_node_protocol_or_generation_mismatch_refused(
    case, monkeypatch, node, field
):
    desired = case.desired[node]
    desired[field] = {
        "node_id": 99,
        "protocol": "hysteria2" if node == 17 else "vless",
        "generation": "0" * 64,
    }[field]
    if field != "generation":
        sign_desired(desired)
    message = (
        "generation" if field == "generation" else "matching enabled per-user node"
    )
    with pytest.raises(adopt.AdoptionError, match=message):
        plan(case, monkeypatch)


@pytest.mark.parametrize("flow", ["", None])
def test_mixed_xray_flow_refused(case, monkeypatch, flow):
    if flow is None:
        del clients(case)[0]["flow"]
    else:
        clients(case)[0]["flow"] = flow
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="mixed or missing Xray flow"):
        plan(case, monkeypatch)


@pytest.mark.parametrize("index", [0, 2], ids=["managed", "shared"])
@pytest.mark.parametrize("field", ["level", "alterId"])
def test_extra_xray_client_fields_refused(case, monkeypatch, index, field):
    clients(case)[index][field] = 0
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="unsupported Xray client attributes"):
        plan(case, monkeypatch)


def test_empty_shared_allowlists_do_not_capture_managed_users(case, monkeypatch):
    clients(case).pop()
    del case.configs[18]["auth"]["userpass"]["shared"]
    case.manifest["shared_sha256"] = {"17": [], "18": []}
    write_configs(case)
    state, report, _ = plan(case, monkeypatch)
    assert state["nodes"]["17"]["xray_legacy"] == []
    assert state["nodes"]["18"]["legacy_auth"] == []
    assert state["nodes"]["17"]["xray_flow"] == FLOW
    assert [node["shared_users"] for node in report["nodes"]] == [0, 0]
    assert [node["managed_users"] for node in report["nodes"]] == [2, 2]


@pytest.mark.parametrize("node", [17, 18])
def test_allowlist_cannot_reclassify_managed_as_shared(case, monkeypatch, node):
    credential = UUIDS[0] if node == 17 else "f1n18v1:managed-one"
    case.manifest["shared_sha256"][str(node)].append(sha256(credential.encode()))
    with pytest.raises(adopt.AdoptionError, match="unapproved or missing shared"):
        plan(case, monkeypatch)


@pytest.mark.parametrize(
    "node,field,value",
    [
        (17, "stats", {}),
        (17, "stats", {"enabled": True}),
        (17, "api", {"services": ["StatsService"]}),
        (17, "policy", {"levels": {"0": {"statsUserUplink": True}}}),
        (18, "trafficStats", {"listen": "127.0.0.1:9999", "secret": "fixture"}),
    ],
    ids=["xray-empty-stats", "xray-stats", "xray-api", "xray-policy", "hy2-stats"],
)
def test_existing_stats_rejected(case, monkeypatch, node, field, value):
    case.configs[node][field] = value
    write_configs(case)
    with pytest.raises(adopt.AdoptionError, match="existing accounting"):
        plan(case, monkeypatch)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "not-a-date",
        UNTIL.replace(tzinfo=None).isoformat(),
        NOW.isoformat(),
        (NOW - timedelta(seconds=1)).isoformat(),
        (NOW + timedelta(days=1, seconds=1)).isoformat(),
    ],
    ids=["missing", "empty", "malformed", "naive", "now", "expired", "over-24h"],
)
def test_invalid_deadline_refused(case, monkeypatch, value):
    case.manifest["legacy_deadline"] = value
    with pytest.raises(adopt.AdoptionError, match="deadline"):
        plan(case, monkeypatch)


def test_deadline_exactly_24_hours_allowed(case, monkeypatch):
    case.manifest["legacy_deadline"] = (NOW + timedelta(days=1)).isoformat()
    _, report, _ = plan(case, monkeypatch)
    assert report["legacy_deadline"] == case.manifest["legacy_deadline"]


def mock_service(monkeypatch, active="inactive", uid=0):
    monkeypatch.setattr(adopt.os, "geteuid", lambda: uid)
    check = Mock(return_value=f"LoadState=loaded\nActiveState={active}\n")
    monkeypatch.setattr(adopt.subprocess, "check_output", check)
    return check


def assert_service_checked(check):
    check.assert_called_once_with(
        ["systemctl", "show", SERVICE, "-p", "LoadState", "-p", "ActiveState"],
        text=True,
        timeout=10,
    )


def test_prepare_state_rejects_running_service(case, monkeypatch):
    state, _, _ = plan(case, monkeypatch)
    check = mock_service(monkeypatch, active="active")
    before = tree_snapshot(case.root)
    with pytest.raises(adopt.AdoptionError, match="stop the identified legacy Agent"):
        adopt.prepare_state(case.manifest["agent_config"]["state_path"], state, SERVICE)
    assert_service_checked(check)
    assert tree_snapshot(case.root) == before


def test_prepare_state_rejects_existing_state(case, monkeypatch):
    state, _, _ = plan(case, monkeypatch)
    path = Path(case.manifest["agent_config"]["state_path"])
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b'{"existing":"do not overwrite"}\n')
    check = mock_service(monkeypatch)
    before = tree_snapshot(case.root)
    with pytest.raises(adopt.AdoptionError, match="refusing to overwrite"):
        adopt.prepare_state(path, state, SERVICE)
    assert_service_checked(check)
    assert tree_snapshot(case.root) == before


def test_prepare_state_requires_root_before_service_check(case, monkeypatch):
    check = mock_service(monkeypatch, uid=501)
    before = tree_snapshot(case.root)
    with pytest.raises(adopt.AdoptionError, match="requires root"):
        adopt.prepare_state(
            case.manifest["agent_config"]["state_path"], {"nodes": {}}, SERVICE
        )
    check.assert_not_called()
    assert tree_snapshot(case.root) == before


def test_prepare_state_writes_private_mode_600_with_stopped_service(case, monkeypatch):
    state, _, _ = plan(case, monkeypatch)
    path = Path(case.manifest["agent_config"]["state_path"])
    config_bytes = {node: p.read_bytes() for node, p in case.paths.items()}
    check = mock_service(monkeypatch)
    adopt.prepare_state(path, state, SERVICE)
    assert_service_checked(check)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert json.loads(path.read_bytes()) == state
    assert path.read_bytes() == canonical(state) + b"\n"
    assert {node: p.read_bytes() for node, p in case.paths.items()} == config_bytes


def test_state_merge_preserves_existing_node_counters_and_outbox():
    original = {
        "nodes": {
            "6": {
                "counters": {"f18n6v1": {"rx": 100, "tx": 250}},
                "pending_traffic": [{"sample_key": "pending"}],
            }
        }
    }
    addition = {"nodes": {"5": {"xray_legacy": [], "xray_flow": FLOW}}}
    merged = adopt.merge_agent_state(original, addition)
    assert merged["nodes"]["6"] == original["nodes"]["6"]
    assert merged["nodes"]["5"] == addition["nodes"]["5"]
    assert original["nodes"].keys() == {"6"}


def test_state_merge_refuses_overlap_instead_of_resetting_a_live_node():
    with pytest.raises(adopt.AdoptionError, match="overwrite"):
        adopt.merge_agent_state(
            {"nodes": {"6": {"pending_traffic": [{"sample_key": "keep"}]}}},
            {"nodes": {"6": {"counters": {}}}},
        )


def test_state_merge_refuses_unknown_existing_schema():
    with pytest.raises(adopt.AdoptionError, match="schema"):
        adopt.merge_agent_state({"generations": {}}, {"nodes": {"5": {}}})


def test_existing_state_merge_is_atomic_private_and_bound_to_reviewed_hash(
    tmp_path, monkeypatch
):
    parent = tmp_path.resolve() / "agent-state"
    parent.mkdir(mode=0o700)
    path = parent / "state.json"
    existing = {
        "nodes": {
            "6": {
                "counters": {"f18n6v1": {"rx": 500, "tx": 700}},
                "pending_traffic": [{"sample_key": "not-acked"}],
            }
        }
    }
    path.write_bytes(canonical(existing) + b"\n")
    path.chmod(0o600)
    previous = path.read_bytes()
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    original_stat = Path.stat

    def root_owned(candidate, *args, **kwargs):
        result = original_stat(candidate, *args, **kwargs)
        if candidate == path:
            fields = list(result)
            fields[4] = 0
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", root_owned)
    monkeypatch.setattr(adopt.os, "chown", lambda *_: None)
    checked = mock_service(monkeypatch)
    adopt.merge_existing_state(
        path,
        {"nodes": {"5": {"xray_legacy": [], "xray_flow": FLOW}}},
        SERVICE,
        sha256(previous),
    )
    assert checked.call_count == 2
    merged = json.loads(path.read_bytes())
    assert merged["nodes"]["6"] == existing["nodes"]["6"]
    assert merged["nodes"]["5"]["xray_legacy"] == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700


def test_existing_state_merge_rejects_changed_review_hash_without_writing(
    tmp_path, monkeypatch
):
    parent = tmp_path.resolve() / "agent-state"
    parent.mkdir(mode=0o700)
    path = parent / "state.json"
    path.write_bytes(b'{"nodes":{"6":{}}}\n')
    path.chmod(0o600)
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    original_stat = Path.stat

    def root_owned(candidate, *args, **kwargs):
        result = original_stat(candidate, *args, **kwargs)
        if candidate == path:
            fields = list(result)
            fields[4] = 0
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", root_owned)
    mock_service(monkeypatch)
    original_bytes = path.read_bytes()
    with pytest.raises(adopt.AdoptionError, match="changed after plan"):
        adopt.merge_existing_state(
            path,
            {"nodes": {"5": {}}},
            SERVICE,
            "0" * 64,
        )
    assert path.read_bytes() == original_bytes
    assert {p.name for p in parent.iterdir()} == {"state.json"}
