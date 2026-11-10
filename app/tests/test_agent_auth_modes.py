import json
from types import SimpleNamespace

from app.agent_api import _desired_payload


def _node(*, enabled=True, per_user_enabled=True, protocol="vless", uri=None):
    return SimpleNamespace(
        id=17,
        protocol=protocol,
        adapter_kind="remote_agent",
        uri=uri or "vless://00000000-0000-4000-8000-000000000017@example.test:443",
        expires_at=None,
        enabled=enabled,
        per_user_enabled=per_user_enabled,
    )


def _agent(capabilities=None):
    return SimpleNamespace(
        id=99,
        capabilities=json.dumps(capabilities or {}),
        desired_generation="",
        updated_at=None,
    )


def test_disabled_remote_node_is_explicit_deny_all_even_for_old_agents():
    desired = _desired_payload(None, _node(enabled=False), _agent())

    assert desired["mode"] == "disabled"
    assert desired["enabled"] is False
    assert desired["apply"] is True
    assert desired["users"] == []


def test_shared_mode_waits_for_agent_capability_then_applies():
    node = _node(per_user_enabled=False)

    legacy = _desired_payload(None, node, _agent())
    capable = _desired_payload(None, node, _agent({"managed_auth_modes": True}))

    assert legacy["mode"] == capable["mode"] == "shared"
    assert legacy["apply"] is False
    assert capable["apply"] is True
    assert legacy["generation"] != capable["generation"]
    assert capable["users"] == [
        {
            "credential_id": 0,
            "friend_id": 0,
            "uid": "shared",
            "protocol": "vless",
            "version": 0,
            "status": "active",
            "stats_id": "legacy-shared",
            "uuid": "00000000-0000-4000-8000-000000000017",
        }
    ]


def test_shared_hysteria_user_is_rendered_as_client_auth():
    node = _node(
        per_user_enabled=False,
        protocol="hysteria2",
        uri="hysteria2://shared-password@example.test:443",
    )

    desired = _desired_payload(None, node, _agent({"managed_auth_modes": True}))

    assert desired["mode"] == "shared"
    assert desired["users"][0]["auth"] == "shared-password"
