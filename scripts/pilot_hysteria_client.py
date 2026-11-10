#!/usr/bin/env python3
"""Bounded live handshake check for the US Hysteria2 pilot."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlunsplit

import yaml
from sqlalchemy import select

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        os.environ[key] = value.strip().strip("'\"")

from app.credentials import credential_values  # noqa: E402
from app.models import (  # noqa: E402
    Friend,
    Node,
    UserNodeCredential,
    make_session_factory,
)


def main():
    pilot_port = int(os.environ.get("HY2_PILOT_PORT", "28080"))
    pilot_uid = os.environ["HY2_PILOT_UID"]
    pilot_node = int(os.environ.get("HY2_PILOT_NODE", "4"))
    factory = make_session_factory(str(ROOT / "data.db"))
    db = factory()
    try:
        friend = db.scalar(select(Friend).where(Friend.uid == pilot_uid))
        node = db.get(Node, pilot_node)
        row = db.scalar(
            select(UserNodeCredential)
            .where(
                UserNodeCredential.friend_id == friend.id,
                UserNodeCredential.node_id == pilot_node,
                UserNodeCredential.status == "active",
            )
            .order_by(UserNodeCredential.version.desc())
            .limit(1)
        )
        parts = urlsplit(node.uri)
        target_host = os.environ.get("HY2_PILOT_HOST", parts.hostname or "")
        if os.environ.get("HY2_PILOT_SHARED") == "1":
            auth = unquote(parts.username or "")
        else:
            values = credential_values(row)
            auth = f"{values['username']}:{values['password']}"
        query = parse_qs(parts.query)
        if os.environ.get("HY2_PILOT_EXPLICIT") == "1":
            tls = {"sni": query.get("sni", [""])[0]}
            if query.get("insecure", [""])[0].lower() in {"1", "true", "yes"}:
                tls["insecure"] = True
            client_config = {
                "server": f"{target_host}:{parts.port}",
                "auth": auth,
                "tls": tls,
                "obfs": {
                    "type": query.get("obfs", [""])[0],
                    "salamander": {"password": query.get("obfs-password", [""])[0]},
                },
                "socks5": {"listen": f"127.0.0.1:{pilot_port}"},
            }
        else:
            server = urlunsplit(
                (
                    parts.scheme,
                    f"{quote(auth, safe=':')}@{target_host}:{parts.port}",
                    parts.path,
                    parts.query,
                    "",
                )
            )
            client_config = {
                "server": server,
                "socks5": {"listen": f"127.0.0.1:{pilot_port}"},
            }
    finally:
        db.close()

    fd, name = tempfile.mkstemp(prefix="hy2-pilot.", suffix=".yaml", dir="/tmp")
    os.close(fd)
    config_path = Path(name)
    os.chmod(config_path, 0o600)
    config_path.write_text(
        yaml.safe_dump(
            client_config,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    log_fd, log_name = tempfile.mkstemp(prefix="hy2-pilot-log.", dir="/tmp")
    os.close(log_fd)
    log_path = Path(log_name)
    process = subprocess.Popen(
        ["/usr/local/bin/hysteria", "client", "-c", str(config_path)],
        stdout=log_path.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    try:
        time.sleep(4)
        if process.poll() is not None:
            log_text = log_path.read_text(encoding="utf-8", errors="replace").lower()
            tokens = {
                key: token in log_text
                for key, token in {
                    "fatal": "fatal",
                    "failed": "failed",
                    "invalid": "invalid",
                    "unsupported": "unsupported",
                    "parse": "parse",
                    "listen": "listen",
                    "server_address": "server address",
                    "mode": "mode",
                    "permission": "permission",
                }.items()
            }
            safe_words = {
                word
                for word in log_text.replace(":", " ").replace("/", " ").split()
                if word
                in {
                    "fatal",
                    "failed",
                    "invalid",
                    "unsupported",
                    "parse",
                    "listen",
                    "server",
                    "address",
                    "mode",
                    "config",
                    "configuration",
                    "url",
                    "host",
                    "port",
                    "missing",
                    "required",
                    "socks5",
                    "auth",
                    "obfs",
                    "tls",
                    "yaml",
                    "field",
                    "unknown",
                    "must",
                    "be",
                    "a",
                }
            }
            print(
                "hysteria_client_process_failed",
                "log_lines",
                len(log_text.splitlines()),
                "auth_word",
                "auth" in log_text,
                "yaml_word",
                "yaml" in log_text,
                "certificate_word",
                "certificate" in log_text,
                "unknown_field",
                "unknown field" in log_text,
                "tokens",
                tokens,
                "safe_words",
                sorted(safe_words),
            )
            return 1
        response = subprocess.run(
            [
                "curl",
                "-fsS",
                "--socks5-hostname",
                f"127.0.0.1:{pilot_port}",
                "--max-time",
                "12",
                os.environ.get("HY2_PILOT_URL", "https://www.gstatic.com/generate_204"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        log_text = log_path.read_text(encoding="utf-8", errors="replace").lower()
        flags = {
            key: token in log_text
            for key, token in {
                "auth": "auth",
                "timeout": "timeout",
                "certificate": "certificate",
                "connection": "connection",
                "error": "error",
            }.items()
        }
        classes = []
        for label, tokens in {
            "authentication": ("authentication", "auth failed", "unauthorized"),
            "handshake": ("handshake", "tls"),
            "udp_dial": ("dial udp", "udp"),
            "server": ("server", "connection refused"),
            "config": ("config", "yaml", "unknown field"),
        }.items():
            if any(token in log_text for token in tokens):
                classes.append(label)
        print(
            "hysteria_external_handshake_ok",
            response.returncode == 0,
            "log_flags",
            flags,
            "classes",
            classes,
        )
        return 0 if response.returncode == 0 else 1
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        config_path.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
