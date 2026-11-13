import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    import stage_adoption
finally:
    sys.path.pop(0)
spec = importlib.util.spec_from_file_location(
    "staging_test_agent", ROOT / "node-agent.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize("valid", [True, False])
def test_candidate_validation_never_rewrites_or_restarts_live_service(
    tmp_path, monkeypatch, valid
):
    uid = "00000000-0000-4000-8000-000000000001"
    live = tmp_path / "live.json"
    live.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "port": 443,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": uid,
                                    "email": "f1n5v1",
                                    "flow": "xtls-rprx-vision",
                                }
                            ]
                        },
                        "streamSettings": {"security": "reality"},
                    }
                ]
            }
        )
    )
    original = live.read_bytes()
    desired = {
        "node_id": 5,
        "protocol": "vless",
        "mode": "per_user",
        "enabled": True,
        "apply": True,
        "users": [{"protocol": "vless", "uuid": uid, "stats_id": "f1n5v1"}],
    }
    desired["generation"] = hashlib.sha256(
        json.dumps(
            desired, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    manifest = {
        "legacy_deadline": (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat(),
        "shared_sha256": {"5": []},
        "agent_config": {
            "endpoint": "https://control.invalid",
            "state_path": str(tmp_path / "live-state.json"),
            "nodes": [
                {
                    "node_id": 5,
                    "protocol": "vless",
                    "engine": "xray",
                    "inbound_port": 443,
                    "xray_config": str(live),
                    "xray_binary": "fixture-xray",
                    "service": "production-xray.service",
                    "token": "private-fixture-token",
                }
            ],
        },
    }
    checks = []

    def validate(argv):
        assert argv[:3] == ["fixture-xray", "run", "-test"]
        candidate = Path(argv[-1])
        assert candidate.parent == tmp_path / "staged"
        assert live.read_bytes() == original
        checks.append(argv)
        return valid

    monkeypatch.setattr(module, "command_ok", validate)
    monkeypatch.setattr(
        module.Agent,
        "start_auth_server",
        lambda *_: pytest.fail("must not bind or start Agent"),
    )
    monkeypatch.setattr(
        module.Agent,
        "request_json",
        lambda *_: pytest.fail("must not contact controller"),
    )
    if valid:
        report = stage_adoption.stage(
            manifest, module, {5: desired}, tmp_path / "staged"
        )
        assert report["live_services_restarted"] is False
        assert "private-fixture-token" not in json.dumps(report)
        assert (tmp_path / "staged/agent-config.json").stat().st_mode & 0o777 == 0o600
    else:
        with pytest.raises(RuntimeError, match="validation"):
            stage_adoption.stage(manifest, module, {5: desired}, tmp_path / "staged")
    assert checks
    assert live.read_bytes() == original
    assert not (tmp_path / "live-state.json").exists()
