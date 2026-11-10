import json

import pytest

from app import proxy_adapters
from app.models import Node, make_session_factory


def test_vless_sync_sends_only_bounded_desired_user_data_and_retries(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SUB_APP_SECRET", "test-vless-sync-secret")
    monkeypatch.setattr(proxy_adapters, "adapter_ready", lambda *_args: True)
    monkeypatch.setattr(
        proxy_adapters, "adapter_marker", lambda: {"VLESS_V2RAY_API": "1"}
    )
    calls = []

    def apply(payload):
        calls.append(payload)
        if len(calls) == 1:
            raise RuntimeError("temporary helper failure")
        return {"ok": True, "digest": "test-digest", "changed": True}

    monkeypatch.setattr(proxy_adapters, "_apply_vless_sync", apply)
    db = make_session_factory(str(tmp_path / "vless.db"))()
    try:
        node = Node(
            name="local reality",
            protocol="vless",
            adapter_kind="local_vless",
            uri="vless://00000000-0000-4000-8000-000000000001@example.test:443?flow=xtls-rprx-vision",
        )
        db.add(node)
        db.commit()

        with pytest.raises(RuntimeError, match="temporary helper failure"):
            proxy_adapters.sync_vless_config(db, node=node)
        proxy_adapters.sync_vless_config(db, node=node)

        assert calls[0] == calls[1]
        assert calls[0]["enabled"] is True
        assert calls[0]["users"] == []
        assert calls[0]["flow"] == "xtls-rprx-vision"
        assert json.loads(json.dumps(calls[0]))["deny_all_uuid"]
        assert set(calls[0]) == {"enabled", "users", "flow", "deny_all_uuid"}
    finally:
        db.close()


def test_vless_sync_rejects_removed_vision_flow_before_helper_call(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(proxy_adapters, "adapter_ready", lambda *_args: True)
    monkeypatch.setattr(
        proxy_adapters, "adapter_marker", lambda: {"VLESS_V2RAY_API": "1"}
    )
    called = []
    monkeypatch.setattr(
        proxy_adapters, "_apply_vless_sync", lambda payload: called.append(payload)
    )
    db = make_session_factory(str(tmp_path / "vless-invalid-flow.db"))()
    try:
        node = Node(
            name="local reality",
            protocol="vless",
            adapter_kind="local_vless",
            uri="vless://00000000-0000-4000-8000-000000000001@example.test:443?flow=xtls-r-vision",
        )
        db.add(node)
        db.commit()

        with pytest.raises(RuntimeError, match="已不支持"):
            proxy_adapters.sync_vless_config(db, node=node)
        assert called == []
    finally:
        db.close()
