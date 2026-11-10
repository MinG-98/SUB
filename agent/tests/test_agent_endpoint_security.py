"""Agent control-plane endpoints must keep bearer tokens on a safe URL."""

import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError

import pytest

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return b'{"ok":true}'


@pytest.mark.parametrize(
    "endpoint",
    [
        None,
        "",
        "http://control.example",
        "ftp://control.example",
        "//control.example",
        "https://",
        "https://user@control.example",
        "https://user:secret@control.example",
        "https://control.example?token=secret",
        "https://control.example?",
        "https://control.example#fragment",
        "https://control.example#",
        "https://control.example:0",
        "https://control.example:65536",
        "https://control.example:not-a-port",
        "https://[::1",
        " https://control.example",
        "https://control.example\n.evil",
        "https://control.example\\@evil.example",
    ],
)
def test_agent_rejects_unsafe_control_plane_endpoint(endpoint, tmp_path):
    with pytest.raises(ValueError, match="invalid Agent endpoint"):
        agent_mod.Agent(
            {"endpoint": endpoint, "state_path": str(tmp_path / "state.json")}
        )


@pytest.mark.parametrize(
    "endpoint, expected",
    [
        ("https://control.example", "https://control.example"),
        ("HTTPS://control.example:8443/base/", "HTTPS://control.example:8443/base"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_agent_accepts_valid_https_endpoints(endpoint, expected, tmp_path):
    agent = agent_mod.Agent(
        {"endpoint": endpoint, "state_path": str(tmp_path / "state.json")}
    )

    assert agent.endpoint == expected


def test_control_plane_requests_use_no_redirect_opener_and_keep_token(
    monkeypatch, tmp_path
):
    agent = agent_mod.Agent(
        {
            "endpoint": "https://control.example/base/",
            "state_path": str(tmp_path / "state.json"),
        }
    )
    opened = []

    class _FakeOpener:
        def open(self, request, timeout):
            opened.append((request, timeout))
            return _Response()

    def fake_build_opener(*handlers):
        assert len(handlers) == 1
        assert isinstance(handlers[0], agent_mod._NoRedirectHandler)
        return _FakeOpener()

    monkeypatch.setattr(agent_mod, "build_opener", fake_build_opener)

    result = agent.request_json("GET", "/api/agent/v1/desired/17", "node-token")

    assert result == {"ok": True}
    request, timeout = opened[0]
    assert request.full_url == "https://control.example/base/api/agent/v1/desired/17"
    assert request.get_header("X-sub-app-agent-token") == "node-token"
    assert timeout == 12


def test_no_redirect_opener_does_not_forward_token_to_redirect_target():
    forwarded_tokens = []

    class _RedirectServerHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):  # noqa: N802
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/capture")
                self.end_headers()
                return
            if self.path == "/capture":
                forwarded_tokens.append(self.headers.get("X-Sub-App-Agent-Token", ""))
            self.send_response(200)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectServerHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = agent_mod.Request(
            f"http://127.0.0.1:{server.server_port}/redirect",
            headers={"X-Sub-App-Agent-Token": "node-token"},
        )
        opener = agent_mod.build_opener(agent_mod._NoRedirectHandler())

        with pytest.raises(HTTPError):
            opener.open(request, timeout=2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert forwarded_tokens == []
