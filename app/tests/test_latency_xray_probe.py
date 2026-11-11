import json
import stat
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import latency
from app.converter import parse_uri


def _parsed(uri):
    parsed = parse_uri(uri)
    assert parsed is not None
    return parsed


def test_xray_reality_config_maps_vless_client_fields():
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=tcp&security=reality"
        "&sni=www.example.test&fp=chrome&pbk=public-key&sid=abcd"
        "&spx=%2Fprobe&flow=xtls-rprx-vision"
    )

    config = latency._xray_reality_config(parsed, 12345)
    inbound = config["inbounds"][0]
    outbound = config["outbounds"][0]
    user = outbound["settings"]["vnext"][0]["users"][0]
    reality = outbound["streamSettings"]["realitySettings"]

    assert inbound["listen"] == "127.0.0.1"
    assert inbound["port"] == 12345
    assert inbound["protocol"] == "socks"
    assert outbound["settings"]["vnext"][0]["address"] == "example.test"
    assert outbound["settings"]["vnext"][0]["port"] == 443
    assert user == {
        "id": "probe-user",
        "encryption": "none",
        "flow": "xtls-rprx-vision",
    }
    assert reality == {
        "serverName": "www.example.test",
        "fingerprint": "chrome",
        "password": "public-key",
        "shortId": "abcd",
        "spiderX": "/probe",
    }
    assert "publicKey" not in reality


def test_xray_reality_config_maps_grpc_transport():
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=grpc&security=reality"
        "&sni=www.example.test&pbk=public-key&sid=abcd&serviceName=probe"
    )

    config = latency._xray_reality_config(parsed, 12345)

    assert config["outbounds"][0]["streamSettings"]["network"] == "grpc"
    assert config["outbounds"][0]["streamSettings"]["grpcSettings"] == {
        "serviceName": "probe"
    }


def test_vless_reality_probe_uses_xray_when_installed(monkeypatch, tmp_path):
    binary = tmp_path / "xray"
    binary.write_bytes(b"test stub")
    monkeypatch.setattr(latency, "XRAY_PROBE_BIN", str(binary))
    calls = []
    monkeypatch.setattr(
        latency, "_xray_probe", lambda _parsed: calls.append("xray") or {"state": "ok"}
    )
    monkeypatch.setattr(
        latency,
        "_sing_box_probe",
        lambda _parsed: calls.append("sing-box") or {"state": "bad"},
    )
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=tcp&security=reality"
        "&sni=www.example.test&pbk=public-key&sid=abcd"
    )

    result = latency._vless_probe(parsed)

    assert result == {"state": "ok"}
    assert calls == ["xray"]


def test_xray_probe_keeps_config_private_and_cleans_up(monkeypatch, tmp_path):
    binary = tmp_path / "xray"
    binary.write_bytes(b"test stub")
    monkeypatch.setattr(latency, "XRAY_PROBE_BIN", str(binary))
    monkeypatch.setattr(latency, "TMP_ROOT", tmp_path / "probe-tmp")
    captured = {}

    class FakeProcess:
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            return 0

    process = FakeProcess()

    def fake_popen(args, **_kwargs):
        config_path = Path(args[-1])
        captured["path"] = config_path
        captured["mode"] = stat.S_IMODE(config_path.stat().st_mode)
        captured["config"] = json.loads(config_path.read_text(encoding="utf-8"))
        return process

    monkeypatch.setattr(latency.subprocess, "Popen", fake_popen)
    curl_calls = []

    def fake_curl(args, **_kwargs):
        curl_calls.append(args)
        return SimpleNamespace(returncode=0, stdout="204")

    monkeypatch.setattr(latency.subprocess, "run", fake_curl)
    monkeypatch.setattr(
        latency.socket, "create_connection", lambda *_args, **_kwargs: nullcontext()
    )
    parsed = _parsed(
        "vless://secret-user@example.test:443?type=tcp&security=reality"
        "&sni=www.example.test&pbk=public-key&sid=abcd"
    )

    result = latency._xray_probe(parsed)

    assert result["state"] == "ok"
    assert result["source"] == "xray"
    assert curl_calls[0][curl_calls[0].index("--noproxy") + 1] == ""
    assert captured["mode"] == 0o600
    assert (
        captured["config"]["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]
        == "secret-user"
    )
    assert not captured["path"].exists()
    assert process.terminated


def test_non_reality_vless_keeps_sing_box_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(latency, "XRAY_PROBE_BIN", str(tmp_path / "xray"))
    monkeypatch.setattr(
        latency, "_xray_probe", lambda _parsed: (_ for _ in ()).throw(AssertionError())
    )
    monkeypatch.setattr(latency, "_sing_box_probe", lambda _parsed: {"state": "ok"})
    parsed = _parsed(
        "vless://probe-user@example.test:443?security=tls&sni=www.example.test"
    )

    assert latency._vless_probe(parsed) == {"state": "ok"}


def test_unsupported_reality_transport_is_not_reported_as_failure(monkeypatch):
    monkeypatch.setattr(latency, "_sing_box_probe", lambda _parsed: {"state": "bad"})
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=xhttp&security=reality"
        "&sni=www.example.test&pbk=public-key&sid=abcd"
    )

    result = latency._vless_probe(parsed)

    assert result["state"] == "unsupported"
    assert result["source"] == "xray"


def test_xray_reality_config_rejects_missing_public_key():
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=tcp&security=reality"
        "&sni=www.example.test&sid=abcd"
    )

    try:
        latency._xray_reality_config(parsed, 12345)
    except ValueError as exc:
        assert "incomplete" in str(exc)
    else:
        raise AssertionError("missing REALITY public key must be rejected")


def test_xray_reality_config_rejects_websocket_transport():
    parsed = _parsed(
        "vless://probe-user@example.test:443?type=ws&security=reality"
        "&sni=www.example.test&pbk=public-key&sid=abcd"
    )

    with pytest.raises(ValueError, match="unsupported VLESS REALITY transport"):
        latency._xray_reality_config(parsed, 12345)
