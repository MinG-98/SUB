"""VLESS `flow` must survive the legacy compatibility window closing.

Regression test.  `flow` used to be derived from the windowed user list, so
24 hours after the first apply the field vanished from every per-user entry and
sing-box rejected every client with "flow mismatch: expected none".
"""

import importlib.util
import json
from datetime import datetime, timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


def render_users(legacy_until, node_spec=None):
    """Assemble the user list the way apply_vless does, calling the real
    Agent._vless_flow for the flow value.

    This pins _vless_flow's own behaviour, but NOT whether apply_vless
    actually calls it — a mutation test proved that reverting apply_vless's
    call site back to its pre-fix inline expression leaves this file green,
    because render_users calls _vless_flow directly and never apply_vless.
    test_apply_vless_flow.py drives the real method end to end and is the
    test that would catch that regression.
    """
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    state = {
        "legacy_users": [
            {"uuid": "legacy-uuid", "flow": "xtls-rprx-vision"},
        ],
        "legacy_until": legacy_until,
    }
    desired = {"users": [{"stats_id": "f9n13v1", "uuid": "new-uuid"}]}

    users = []
    if state.get("legacy_until") and agent_mod.utcnow() < datetime.fromisoformat(
        state["legacy_until"]
    ):
        users.extend(state.get("legacy_users", []))
    flow = agent._vless_flow(state, node_spec or {})
    for item in desired["users"]:
        entry = {"name": item["stats_id"], "uuid": item["uuid"]}
        if flow:
            entry["flow"] = flow
        users.append(entry)
    return users


def test_vless_flow_sources():
    agent = agent_mod.Agent.__new__(agent_mod.Agent)

    snapshot = {"legacy_users": [{"uuid": "u", "flow": "xtls-rprx-vision"}]}
    assert agent._vless_flow(snapshot, {}) == "xtls-rprx-vision"

    # A snapshot taken from an already-flowless config cannot recover the value
    # from the node, so the per-node key is the only way back.
    flowless = {"legacy_users": [{"uuid": "u"}]}
    assert agent._vless_flow(flowless, {}) == ""
    assert (
        agent._vless_flow(flowless, {"vless_flow": "xtls-rprx-vision"})
        == "xtls-rprx-vision"
    )

    # The snapshot wins over the fallback when both are present.
    assert (
        agent._vless_flow(snapshot, {"vless_flow": "something-else"})
        == "xtls-rprx-vision"
    )

    # Hysteria2-style legacy users have no flow and must not gain one.
    assert agent._vless_flow({"legacy_users": [{"password": "x"}]}, {}) == ""


def test_flow_survives_window():
    now = agent_mod.utcnow()
    open_window = (now + timedelta(hours=1)).isoformat()
    shut_window = (now - timedelta(hours=1)).isoformat()

    inside = render_users(open_window)
    print("window open  ->", json.dumps(inside))
    assert inside[-1]["flow"] == "xtls-rprx-vision"
    assert len(inside) == 2, "legacy user should still be served inside the window"

    outside = render_users(shut_window)
    print("window shut  ->", json.dumps(outside))
    assert len(outside) == 1, "legacy user should be gone once the window closes"
    assert (
        outside[0].get("flow") == "xtls-rprx-vision"
    ), "flow was dropped after the window closed — sing-box will reject every client"
