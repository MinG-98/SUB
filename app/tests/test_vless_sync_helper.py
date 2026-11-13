import json
import uuid

import pytest

from scripts import vless_sync_helper as helper


def _config(path, users):
    document = {
        "inbounds": [{"tag": "reality-in", "type": "vless", "users": users}],
        "experimental": {},
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path.read_text(encoding="utf-8")


class _Result:
    def __init__(self, returncode=0):
        self.returncode = returncode


def test_device_scoped_stats_identity_is_accepted(tmp_path):
    device_stats_id = "f2d19-0123456789abn4v3"
    config_path = tmp_path / "config.json"
    _config(config_path, [])

    helper.apply_vless_config(
        _request(users=[{"name": device_stats_id, "uuid": str(uuid.uuid4())}]),
        config_path=config_path,
        marker_path=tmp_path / "proxy-adapters.env",
        state_path=tmp_path / "state" / "applied.sha256",
        binary="/test/sing-box",
        service="test-sing-box.service",
        runner=lambda *_args, **_kwargs: _Result(),
    )

    applied = json.loads(config_path.read_text(encoding="utf-8"))
    assert applied["inbounds"][0]["users"][0]["name"] == device_stats_id


def _request(*, enabled=True, users=None, deny_all_uuid=None, flow=""):
    return {
        "enabled": enabled,
        "users": users or [],
        "flow": flow,
        "deny_all_uuid": deny_all_uuid or str(uuid.uuid4()),
    }


def test_helper_preserves_only_shared_legacy_user_during_compatibility_window(
    tmp_path,
):
    shared_uuid = str(uuid.uuid4())
    stale_uuid = str(uuid.uuid4())
    managed_uuid = str(uuid.uuid4())
    config_path = tmp_path / "config.json"
    _config(
        config_path,
        [
            {"uuid": shared_uuid, "flow": "xtls-rprx-vision"},
            {"name": "old-managed", "uuid": stale_uuid},
        ],
    )
    marker_path = tmp_path / "proxy-adapters.env"
    marker_path.write_text("VLESS_LEGACY_UNTIL=2999-01-01T00:00:00+00:00\n")
    commands = []

    def runner(args, **_kwargs):
        commands.append(args)
        return _Result()

    request = _request(
        users=[{"name": "f1n2v1", "uuid": managed_uuid}],
        flow="xtls-rprx-vision",
    )
    result = helper.apply_vless_config(
        request,
        config_path=config_path,
        marker_path=marker_path,
        state_path=tmp_path / "state" / "applied.sha256",
        binary="/test/sing-box",
        service="test-sing-box.service",
        runner=runner,
    )

    applied = json.loads(config_path.read_text(encoding="utf-8"))
    users = applied["inbounds"][0]["users"]
    assert [user["uuid"] for user in users] == [shared_uuid, managed_uuid]
    assert users[0] == {"uuid": shared_uuid, "flow": "xtls-rprx-vision"}
    assert users[1] == {
        "name": "f1n2v1",
        "uuid": managed_uuid,
        "flow": "xtls-rprx-vision",
    }
    assert stale_uuid not in {user["uuid"] for user in users}
    assert applied["experimental"]["v2ray_api"]["stats"]["users"] == ["f1n2v1"]
    assert result["ok"] is True
    assert result["changed"] is True
    assert commands[0][:2] == ["/test/sing-box", "check"]
    assert commands[1] == ["systemctl", "restart", "test-sing-box.service"]
    assert commands[2] == [
        "systemctl",
        "is-active",
        "--quiet",
        "test-sing-box.service",
    ]


def test_disabled_helper_removes_legacy_users_immediately(tmp_path):
    shared_uuid = str(uuid.uuid4())
    deny_uuid = str(uuid.uuid4())
    config_path = tmp_path / "config.json"
    _config(config_path, [{"uuid": shared_uuid}])
    marker_path = tmp_path / "proxy-adapters.env"
    marker_path.write_text("VLESS_LEGACY_UNTIL=2999-01-01T00:00:00+00:00\n")

    def runner(*_args, **_kwargs):
        return _Result()

    helper.apply_vless_config(
        _request(enabled=False, deny_all_uuid=deny_uuid),
        config_path=config_path,
        marker_path=marker_path,
        state_path=tmp_path / "state" / "applied.sha256",
        runner=runner,
    )

    users = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]["users"]
    assert users == [{"name": "sub-app-disabled", "uuid": deny_uuid}]


def test_helper_reconcile_is_idempotent_after_success(tmp_path):
    config_path = tmp_path / "config.json"
    _config(config_path, [])
    state_path = tmp_path / "state" / "applied.sha256"
    calls = []

    def runner(args, **_kwargs):
        calls.append(args)
        return _Result()

    request = _request(users=[{"name": "f1n2v1", "uuid": str(uuid.uuid4())}])
    first = helper.apply_vless_config(
        request,
        config_path=config_path,
        marker_path=tmp_path / "missing.env",
        state_path=state_path,
        runner=runner,
    )
    calls_after_first_apply = len(calls)
    second = helper.apply_vless_config(
        request,
        config_path=config_path,
        marker_path=tmp_path / "missing.env",
        state_path=state_path,
        runner=runner,
    )

    assert first["digest"] == second["digest"]
    assert first["changed"] is True
    assert second["changed"] is False
    assert len(calls) == calls_after_first_apply


def test_helper_rolls_back_on_restart_failure_then_allows_retry(tmp_path):
    original_users = [{"uuid": str(uuid.uuid4())}]
    config_path = tmp_path / "config.json"
    original = _config(config_path, original_users)
    state_path = tmp_path / "state" / "applied.sha256"
    request = _request(
        users=[{"name": "f1n2v1", "uuid": str(uuid.uuid4())}],
    )
    statuses = iter([0, 1, 0])

    def fail_once(args, **_kwargs):
        return _Result(next(statuses))

    with pytest.raises(helper.VlessApplyError, match="restart failed"):
        helper.apply_vless_config(
            request,
            config_path=config_path,
            marker_path=tmp_path / "missing.env",
            state_path=state_path,
            runner=fail_once,
        )
    assert config_path.read_text(encoding="utf-8") == original
    assert state_path.read_text(encoding="ascii").startswith("pending:")

    calls = []

    def succeed(args, **_kwargs):
        calls.append(args)
        return _Result()

    result = helper.apply_vless_config(
        request,
        config_path=config_path,
        marker_path=tmp_path / "missing.env",
        state_path=state_path,
        runner=succeed,
    )
    assert result["ok"] is True
    assert not state_path.read_text(encoding="ascii").startswith("pending:")
    assert len(calls) == 3


def test_helper_rejects_arbitrary_names_flows_and_users_when_disabled(tmp_path):
    config_path = tmp_path / "config.json"
    original = _config(config_path, [{"uuid": str(uuid.uuid4())}])
    base = {
        "config_path": config_path,
        "marker_path": tmp_path / "missing.env",
        "state_path": tmp_path / "state" / "applied.sha256",
        "runner": lambda *_args, **_kwargs: _Result(),
    }
    unsafe_requests = [
        _request(users=[{"name": "../../etc/passwd", "uuid": str(uuid.uuid4())}]),
        _request(
            users=[
                {
                    "name": "f1n2v1",
                    "uuid": str(uuid.uuid4()),
                    "flow": ";systemctl restart sshd",
                }
            ]
        ),
        _request(
            enabled=False,
            users=[{"name": "f1n2v1", "uuid": str(uuid.uuid4())}],
        ),
    ]
    for request in unsafe_requests:
        with pytest.raises(ValueError):
            helper.apply_vless_config(request, **base)
    assert config_path.read_text(encoding="utf-8") == original
