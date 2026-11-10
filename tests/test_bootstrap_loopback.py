"""Optional offline dataplane smoke test with an independently verified HY2 binary."""

import contextlib
import http.server
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import threading
import time
import urllib.request

import pytest
import yaml

from scripts.bootstrap_node import ROOT


@pytest.mark.skipif(
    not os.environ.get("TEST_HY2_BINARY"),
    reason="set TEST_HY2_BINARY to a verified Hysteria 2 binary",
)
def test_real_hy2_agent_auth_and_proxy(tmp_path):
    binary = os.environ["TEST_HY2_BINARY"]
    spec = importlib.util.spec_from_file_location(
        "smoke_agent", ROOT / "agent/node-agent.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"loopback-ok")

        def log_message(self, *_):
            pass

    def free(kind):
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=smoke.invalid",
            "-addext",
            "subjectAltName=DNS:smoke.invalid",
            "-out",
            cert,
            "-keyout",
            key,
        ],
        capture_output=True,
        check=True,
    )
    auth, stats = free(socket.SOCK_STREAM), free(socket.SOCK_STREAM)
    udp, socks = free(socket.SOCK_DGRAM), free(socket.SOCK_STREAM)
    password, stats_key = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    server = {
        "listen": f"127.0.0.1:{udp}",
        "tls": {"cert": str(cert), "key": str(key)},
        "auth": {"type": "http", "http": {"url": f"http://127.0.0.1:{auth}/auth"}},
        "trafficStats": {"listen": f"127.0.0.1:{stats}", "secret": stats_key},
    }
    client = {
        "server": f"127.0.0.1:{udp}",
        "auth": password,
        "tls": {"sni": "smoke.invalid", "ca": str(cert)},
        "socks5": {"listen": f"127.0.0.1:{socks}"},
    }
    agent = mod.Agent(
        {
            "endpoint": "https://sub.example.invalid",
            "state_path": str(tmp_path / "state.json"),
        }
    )
    agent.desired[1] = {
        "mode": "shared",
        "users": [{"protocol": "hysteria2", "auth": password, "stats_id": "test"}],
    }
    with contextlib.ExitStack() as cleanup:
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        cleanup.callback(origin.server_close)
        cleanup.callback(origin.shutdown)
        agent.start_auth_server(
            {"node_id": 1, "auth_port": auth, "protocol": "hysteria2"}
        )
        cleanup.callback(agent.auth_servers[0].server_close)
        cleanup.callback(agent.auth_servers[0].shutdown)
        for role, cfg in (("server", server), ("client", client)):
            path = tmp_path / (role + ".yaml")
            path.write_text(yaml.safe_dump(cfg))
            proc = subprocess.Popen(
                [binary, role, "-c", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            cleanup.callback(proc.wait, 5)
            cleanup.callback(proc.kill)
            time.sleep(0.3)
        for _ in range(8):
            r = subprocess.run(
                [
                    "curl",
                    "-q",
                    "-fsS",
                    "--max-time",
                    "2",
                    "--noproxy",
                    "",
                    "--proxy",
                    f"socks5h://127.0.0.1:{socks}",
                    f"http://127.0.0.1:{origin.server_port}/",
                ],
                capture_output=True,
            )
            if r.returncode == 0 and r.stdout == b"loopback-ok":
                break
            time.sleep(0.2)
        else:
            pytest.fail("real TLS/QUIC proxy request failed")
        req = urllib.request.Request(
            f"http://127.0.0.1:{stats}/online", headers={"Authorization": stats_key}
        )
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            req, timeout=2
        ) as res:
            assert isinstance(json.load(res), dict)
