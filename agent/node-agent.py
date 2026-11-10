#!/usr/bin/env python3
"""One root-only control agent per proxy server.

The agent polls the US control plane for each node hosted on this machine,
reports capabilities, and stays in observe mode until the node is explicitly
enabled.  Credentials and legacy authentication values never enter logs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

VERSION = "0.4.0"
MAX_PENDING_TRAFFIC_RECORDS = 2048
MAX_TRAFFIC_BATCH_RECORDS = 128

# "user>>>f3n12v1>>>traffic>>>uplink" as emitted by the V2Ray stats API.
VLESS_STAT_RE = re.compile(r"^user>>>(.+)>>>traffic>>>(uplink|downlink)$")
LOG = logging.getLogger("sub-app-node-agent")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_bucket() -> str:
    now = utcnow().replace(second=0, microsecond=0)
    return now.replace(minute=(now.minute // 5) * 5).isoformat()


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return copy.deepcopy(default)


def write_json(path: Path, value, mode=0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def command_output(argv: list[str], timeout=8) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (result.stdout + "\n" + result.stderr)[:4096]
    except (OSError, subprocess.SubprocessError):
        return ""


def command_ok(argv: list[str], timeout=20) -> bool:
    try:
        return (
            subprocess.run(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


class AuthHandler(BaseHTTPRequestHandler):
    server_version = "sub-app-node-agent"

    def log_message(self, *_args):
        return

    def do_POST(self):  # noqa: N802
        if self.path != "/auth":
            self.send_error(404)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 65536)
            body = json.loads(self.rfile.read(length) or b"{}")
            auth = str(body.get("auth", ""))
        except (ValueError, TypeError, json.JSONDecodeError):
            auth = ""
        result = self.server.agent.authenticate(self.server.node_id, auth)
        encoded = json.dumps(result, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward the Agent bearer token to any redirect destination."""

    def redirect_request(self, *_args, **_kwargs):
        return None


class Agent:
    def __init__(self, config: dict):
        self.config = config
        self.endpoint = self._validate_endpoint(config.get("endpoint"))
        self.interval = max(10, int(config.get("poll_seconds", 30)))
        self.state_path = Path(
            config.get("state_path", "/var/lib/sub-app-node-agent/state.json")
        )
        self.state = read_json(self.state_path, {"nodes": {}})
        self.state.setdefault("nodes", {})
        self.nodes = [
            item for item in config.get("nodes", []) if isinstance(item, dict)
        ]
        self.desired: dict[int, dict] = {}
        self.lock = threading.RLock()
        self.auth_servers = []
        # Ownership/mode of each managed config, captured before the first
        # replacement so a rollback can put it back exactly as the proxy core
        # expects it.
        self.config_meta: dict[str, tuple[int, int, int]] = {}

    @staticmethod
    def _validate_endpoint(value) -> str:
        """Validate the control-plane URL before any bearer token is sent."""
        if not isinstance(value, str) or not value:
            raise ValueError("invalid Agent endpoint: HTTPS URL required")
        if any(
            character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            or character == "\\"
            for character in value
        ):
            raise ValueError("invalid Agent endpoint: unsafe URL characters")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid Agent endpoint: malformed HTTPS URL") from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("invalid Agent endpoint: HTTPS URL with a host required")
        return value.rstrip("/")

    def node_state(self, node_id: int) -> dict:
        return self.state["nodes"].setdefault(str(node_id), {})

    def save_state(self):
        write_json(self.state_path, self.state)

    def _deny_all_user(self, state: dict, protocol: str) -> dict:
        """Keep a stable, private credential so an empty managed list denies access."""
        stored = state.setdefault("deny_all_users", {})
        if not isinstance(stored, dict):
            stored = state["deny_all_users"] = {}
        user = stored.get(protocol)
        if not isinstance(user, dict) or not user.get("name"):
            name = f"sub-app-disabled-{secrets.token_hex(8)}"
            if protocol == "vless":
                user = {"name": name, "uuid": str(uuid.uuid4())}
            elif protocol == "hysteria2":
                user = {"name": name, "password": secrets.token_urlsafe(32)}
            else:
                raise ValueError("unsupported deny-all protocol")
            stored[protocol] = user
        required = "uuid" if protocol == "vless" else "password"
        if not user.get(required):
            raise ValueError("incomplete deny-all credential state")
        return copy.deepcopy(user)

    def _enqueue_traffic(self, node_id: int, samples) -> list[dict]:
        state = self.node_state(node_id)
        pending = state.setdefault("pending_traffic", [])
        if not isinstance(pending, list):
            pending = state["pending_traffic"] = []
        known = {
            str(item.get("sample_key", ""))
            for item in pending
            if isinstance(item, dict) and item.get("sample_key")
        }
        for sample in samples if isinstance(samples, list) else []:
            if not isinstance(sample, dict):
                continue
            item = copy.deepcopy(sample)
            key = str(item.get("sample_key", ""))[:128]
            if not key:
                canonical = json.dumps(
                    item, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                )
                key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                item["sample_key"] = key
            if key not in known:
                pending.append(item)
                known.add(key)
        return copy.deepcopy(pending)

    def _ack_traffic(self, node_id: int, sample_keys: list[str]) -> None:
        state = self.node_state(node_id)
        pending = state.get("pending_traffic", [])
        acknowledged = {
            str(key)[:128] for key in sample_keys if isinstance(key, str) and key
        }
        if isinstance(pending, list):
            state["pending_traffic"] = [
                item
                for item in pending
                if not isinstance(item, dict)
                or str(item.get("sample_key", "")) not in acknowledged
            ]

    def _config_path(self, spec: dict, key: str, candidates: list[str]) -> Path | None:
        configured = str(spec.get(key, ""))
        if configured and Path(configured).is_file():
            return Path(configured)
        for pattern in candidates:
            for path in Path("/").glob(pattern.lstrip("/")):
                if path.is_file():
                    return path
        return None

    def capabilities(self, spec: dict) -> dict:
        sing_box = str(spec.get("sing_box_binary", "sing-box"))
        hysteria = str(spec.get("hysteria_binary", "hysteria"))
        sing_version = command_output([sing_box, "version"])
        hysteria_present = bool(shutil.which(hysteria))
        yaml_available = False
        try:
            import yaml  # type: ignore

            yaml_available = bool(yaml)
        except Exception:
            pass
        return {
            "agent_version": VERSION,
            "managed_auth_modes": True,
            "os": os.uname().sysname if hasattr(os, "uname") else "unknown",
            "machine": os.uname().machine if hasattr(os, "uname") else "unknown",
            "hysteria_binary": hysteria_present,
            "hysteria_yaml_adapter": yaml_available,
            "sing_box_binary": bool(shutil.which(sing_box)),
            "vless_v2ray_api": "with_v2ray_api" in sing_version,
            "hysteria_config": bool(
                self._config_path(
                    spec,
                    "hysteria_config",
                    [
                        "/etc/hysteria*/config.yaml",
                    ],
                )
            ),
            "sing_box_config": bool(
                self._config_path(
                    spec,
                    "sing_box_config",
                    [
                        "/etc/sing-box*/config.json",
                    ],
                )
            ),
            "vless_stats_helper": os.path.exists(
                str(
                    spec.get(
                        "vless_stats_binary", "/usr/local/libexec/sub-app-vless-stats"
                    )
                )
            ),
            # True when this node's Hysteria2 is an inbound inside sing-box
            # rather than a standalone hysteria server.
            "singbox_engine": self._singbox_engine(spec),
            "systemd": bool(shutil.which("systemctl")),
            "openrc": bool(shutil.which("rc-service")),
        }

    def request_json(self, method: str, path: str, token: str, payload=None):
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "sub-app-node-agent/" + VERSION,
            "X-Sub-App-Agent-Token": token,
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            self.endpoint + path, data=data, headers=headers, method=method
        )
        opener = build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=12) as response:
            return json.loads(response.read(1024 * 1024).decode("utf-8"))

    def authenticate(self, node_id: int, auth: str) -> dict:
        with self.lock:
            desired = self.desired.get(node_id, {})
            mode = desired.get("mode", "per_user")
            if mode == "disabled" or desired.get("enabled") is False:
                return {"ok": False}
            users = desired.get("users", [])
            state = self.node_state(node_id)
            for item in users:
                if item.get("protocol") != "hysteria2":
                    continue
                expected_auth = item.get("auth") or (
                    f"{item.get('username', '')}:{item.get('password', '')}"
                )
                if expected_auth == auth:
                    return {"ok": True, "id": item.get("stats_id", "")}
            legacy_until = state.get("legacy_until", "")
            try:
                legacy_deadline = datetime.fromisoformat(legacy_until)
            except (TypeError, ValueError):
                legacy_deadline = None
            if legacy_deadline is not None:
                if legacy_deadline.tzinfo is None:
                    legacy_deadline = legacy_deadline.replace(tzinfo=timezone.utc)
                if utcnow() < legacy_deadline and auth in state.get("legacy_auth", []):
                    return {"ok": True, "id": "legacy-shared"}
            return {"ok": False}

    def start_auth_server(self, spec: dict):
        if spec.get("protocol") != "hysteria2":
            return
        port = int(spec.get("auth_port", 0) or 0)
        if not port:
            return
        node_id = int(spec["node_id"])
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), AuthHandler)
            server.agent = self
            server.node_id = node_id
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.auth_servers.append(server)
        except OSError:
            LOG.error("auth backend failed to listen for node %s", node_id)

    def _service_restart(self, spec: dict) -> bool:
        service = str(spec.get("service", ""))
        if not service:
            return False
        if shutil.which("systemctl"):
            return command_ok(["systemctl", "restart", service]) and command_ok(
                ["systemctl", "is-active", "--quiet", service]
            )
        if shutil.which("rc-service"):
            return command_ok(["rc-service", service, "restart"]) and command_ok(
                ["rc-service", service, "status"]
            )
        return False

    def _backup_and_replace(self, path: Path, content: str, spec: dict) -> Path:
        backup_dir = Path(spec.get("backup_dir", "/var/lib/sub-app-node-agent/backups"))
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / (
            path.name + "." + utcnow().strftime("%Y%m%dT%H%M%SZ") + ".bak"
        )
        shutil.copy2(path, backup)
        info = path.stat()
        mode = stat.S_IMODE(info.st_mode)
        self.config_meta.setdefault(str(path), (info.st_uid, info.st_gid, mode))
        fd, name = tempfile.mkstemp(prefix=".config.", dir=str(path.parent))
        temp = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(temp, mode)
            # mkstemp creates the file as root.  Proxy cores that drop
            # privileges (OpenRC command_user / systemd User=) cannot read
            # their own config unless ownership survives the replacement.
            os.chown(temp, info.st_uid, info.st_gid)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        return backup

    def _restore(self, path: Path, backup: Path, spec: dict):
        shutil.copy2(backup, path)
        # copy2 writes into the existing inode and keeps whatever ownership it
        # currently has, so reapply the values captured before the first swap.
        owner = self.config_meta.get(str(path))
        if owner:
            uid, gid, mode = owner
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        self._service_restart(spec)

    def apply_hysteria(self, spec: dict, desired: dict) -> None:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError("PyYAML unavailable") from exc
        path = self._config_path(
            spec, "hysteria_config", ["/etc/hysteria*/config.yaml"]
        )
        if path is None:
            raise RuntimeError("Hysteria config not found")
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        node_id = int(spec["node_id"])
        state = self.node_state(node_id)
        old_auth = config.get("auth") or {}
        if not state.get("legacy_auth") and isinstance(old_auth, dict):
            if old_auth.get("type") == "password" and old_auth.get("password"):
                state["legacy_auth"] = [str(old_auth["password"])]
            elif old_auth.get("type") == "userpass":
                state["legacy_auth"] = [
                    f"{u}:{p}" for u, p in (old_auth.get("userpass") or {}).items()
                ]
        if not state.get("legacy_until") and state.get("legacy_auth"):
            state["legacy_until"] = utcnow().timestamp() + 24 * 3600
            state["legacy_until"] = datetime.fromtimestamp(
                state["legacy_until"], timezone.utc
            ).isoformat()
        auth_port = int(spec.get("auth_port", 0) or 0)
        stats_port = int(spec.get("stats_port", 0) or 0)
        if not auth_port or not stats_port:
            raise RuntimeError("HY2 auth/stats ports missing")
        config["auth"] = {
            "type": "http",
            "http": {"url": f"http://127.0.0.1:{auth_port}/auth"},
        }
        traffic = config.get("trafficStats") or {}
        traffic["listen"] = f"127.0.0.1:{stats_port}"
        if not traffic.get("secret"):
            traffic["secret"] = state.setdefault(
                "traffic_secret", secrets.token_urlsafe(32)
            )
        else:
            state["traffic_secret"] = str(traffic["secret"])
        config["trafficStats"] = traffic
        content = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
        # poll_node calls apply on every cycle.  Without this guard the proxy
        # core would be rewritten and restarted every poll interval, dropping
        # every live connection on a loop.
        if path.read_text(encoding="utf-8") == content:
            self.save_state()
            return
        backup = self._backup_and_replace(path, content, spec)
        if not self._service_restart(spec):
            self._restore(path, backup, spec)
            raise RuntimeError("Hysteria service failed after config apply")
        self.save_state()

    def _singbox_engine(self, spec: dict) -> bool:
        return str(spec.get("engine", "")).lower() in {"sing-box", "singbox"}

    def _singbox_stats_section(self, config: dict, spec: dict) -> None:
        """Rebuild the V2Ray API block from every named user in the file.

        Korea and Malaysia run a single sing-box that fronts both a VLESS and
        a Hysteria2 node.  Each node is applied on its own poll, so the stats
        block has to be derived from the whole config; deriving it from just
        the inbound being applied would make the two nodes wipe each other's
        users and restart the core on every cycle.
        """
        tags: list[str] = []
        names: list[str] = []
        for inbound in config.get("inbounds", []):
            named = [u.get("name") for u in inbound.get("users", []) if u.get("name")]
            if not named:
                continue
            tag = inbound.get("tag", "")
            if tag and tag not in tags:
                tags.append(tag)
            names.extend(named)
        experimental = config.setdefault("experimental", {})
        experimental["v2ray_api"] = {
            "listen": str(spec.get("v2ray_api_listen", "127.0.0.1:10085")),
            "stats": {"enabled": True, "inbounds": tags, "users": names},
        }

    def apply_singbox_hysteria2(self, spec: dict, desired: dict) -> None:
        """Per-user auth for a Hysteria2 inbound hosted inside sing-box.

        Unlike a standalone Hysteria server, which delegates to an HTTP auth
        backend, sing-box matches the client's auth string against each user's
        `password` field directly.
        """
        binary = str(spec.get("sing_box_binary", "sing-box"))
        if "with_v2ray_api" not in command_output([binary, "version"]):
            raise RuntimeError("sing-box lacks with_v2ray_api")
        path = self._config_path(
            spec, "sing_box_config", ["/etc/sing-box*/config.json"]
        )
        if path is None:
            raise RuntimeError("sing-box config not found")
        config = json.loads(path.read_text(encoding="utf-8"))
        wanted_tag = spec.get("inbound_tag")
        inbound = next(
            (
                item
                for item in config.get("inbounds", [])
                if (
                    item.get("tag") == wanted_tag
                    if wanted_tag
                    else item.get("type") == "hysteria2"
                )
            ),
            None,
        )
        if not inbound:
            raise RuntimeError("hysteria2 inbound not found")
        node_id = int(spec["node_id"])
        state = self.node_state(node_id)
        if "legacy_users" not in state:
            state["legacy_users"] = copy.deepcopy(inbound.get("users", []))
            state["legacy_until"] = datetime.fromtimestamp(
                utcnow().timestamp() + 24 * 3600, timezone.utc
            ).isoformat()
        mode = desired.get("mode", "per_user")
        if mode == "shared":
            users = [
                {
                    "name": item.get("stats_id", ""),
                    "password": item.get("auth")
                    or f"{item.get('username', '')}:{item.get('password', '')}",
                }
                for item in desired.get("users", [])
            ]
        else:
            users = []
            if (
                mode != "disabled"
                and state.get("legacy_until")
                and utcnow() < datetime.fromisoformat(state["legacy_until"])
            ):
                users.extend(state.get("legacy_users", []))
            if mode != "disabled":
                for item in desired.get("users", []):
                    # Subscriptions render hysteria2://user:pass@host and clients
                    # send that whole userinfo as the auth string.
                    users.append(
                        {
                            "name": item["stats_id"],
                            "password": f"{item.get('username', '')}:{item.get('password', '')}",
                        }
                    )
        if not users:
            users.append(self._deny_all_user(state, "hysteria2"))
        inbound["users"] = users
        self._singbox_stats_section(config, spec)
        content = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        if path.read_text(encoding="utf-8") == content:
            self.save_state()
            return
        backup = self._backup_and_replace(path, content, spec)
        check = subprocess.run(
            [binary, "check", "-c", str(path)],
            capture_output=True,
            timeout=20,
            check=False,
        )
        if check.returncode or not self._service_restart(spec):
            self._restore(path, backup, spec)
            raise RuntimeError("sing-box service failed after hysteria2 apply")
        self.save_state()

    def _vless_flow(self, state: dict, spec: dict) -> str:
        """Resolve the flow value written onto each per-user VLESS entry.

        It has to come from the persisted legacy snapshot, which is captured
        once and outlives the 24h compatibility window.  Reading it from the
        windowed user list instead dropped the field from every entry the
        moment the window closed — a day after the first apply — and sing-box
        then rejected every client with "flow mismatch: expected none".
        """
        flow = next(
            (
                item.get("flow")
                for item in state.get("legacy_users", [])
                if item.get("flow")
            ),
            "",
        )
        # Last resort if the state file was ever lost: the snapshot would be
        # retaken from an already-flowless config and the value could not be
        # recovered from the node itself.
        return flow or str(spec.get("vless_flow", "") or "")

    def apply_vless(self, spec: dict, desired: dict) -> None:
        binary = str(spec.get("sing_box_binary", "sing-box"))
        version = command_output([binary, "version"])
        if "with_v2ray_api" not in version:
            raise RuntimeError("sing-box lacks with_v2ray_api")
        path = self._config_path(
            spec, "sing_box_config", ["/etc/sing-box*/config.json"]
        )
        if path is None:
            raise RuntimeError("sing-box config not found")
        config = json.loads(path.read_text(encoding="utf-8"))
        inbound = next(
            (
                item
                for item in config.get("inbounds", [])
                if item.get("type") == "vless"
                or item.get("tag") == spec.get("inbound_tag")
            ),
            None,
        )
        if not inbound:
            raise RuntimeError("VLESS inbound not found")
        node_id = int(spec["node_id"])
        state = self.node_state(node_id)
        if "legacy_users" not in state:
            state["legacy_users"] = copy.deepcopy(inbound.get("users", []))
            state["legacy_until"] = utcnow().timestamp() + 24 * 3600
            state["legacy_until"] = datetime.fromtimestamp(
                state["legacy_until"], timezone.utc
            ).isoformat()
        mode = desired.get("mode", "per_user")
        if mode == "shared":
            users = []
            for item in desired.get("users", []):
                entry = {
                    "name": item.get("stats_id", ""),
                    "uuid": item["uuid"],
                }
                if item.get("flow"):
                    entry["flow"] = item["flow"]
                users.append(entry)
        else:
            users = []
            if (
                mode != "disabled"
                and state.get("legacy_until")
                and utcnow() < datetime.fromisoformat(state["legacy_until"])
            ):
                users.extend(state.get("legacy_users", []))
            if mode != "disabled":
                flow = self._vless_flow(state, spec)
                for item in desired.get("users", []):
                    entry = {"name": item["stats_id"], "uuid": item["uuid"]}
                    if flow:
                        entry["flow"] = flow
                    users.append(entry)
        if not users:
            users.append(self._deny_all_user(state, "vless"))
        inbound["users"] = users
        self._singbox_stats_section(config, spec)
        content = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        # Same idempotency guard as the Hysteria path: never restart the core
        # when the rendered config is byte-identical to what is already live.
        if path.read_text(encoding="utf-8") == content:
            self.save_state()
            return
        backup = self._backup_and_replace(path, content, spec)
        check = subprocess.run(
            [binary, "check", "-c", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
        if check.returncode or not self._service_restart(spec):
            self._restore(path, backup, spec)
            raise RuntimeError("sing-box service failed after config apply")
        self.save_state()

    def collect_vless_traffic(self, spec: dict) -> list[dict]:
        """Read per-user counters from the loopback V2Ray API via the helper.

        Counter handling mirrors the Hysteria path: report deltas, treat a
        counter that moved backwards as a restart rather than emitting a huge
        value, and key each sample on the absolute reading so the center can
        deduplicate retries.
        """
        binary = str(
            spec.get("vless_stats_binary", "/usr/local/libexec/sub-app-vless-stats")
        )
        if not os.path.exists(binary):
            return []
        listen = str(spec.get("v2ray_api_listen", "127.0.0.1:10085"))
        raw = command_output([binary, "-addr", listen], timeout=10)
        try:
            payload = json.loads(raw.strip().splitlines()[0]) if raw.strip() else {}
        except (ValueError, IndexError):
            return []
        entries = payload.get("stats")
        if not isinstance(entries, list):
            return []

        node_id = int(spec["node_id"])
        state = self.node_state(node_id)
        counters = state.setdefault("vless_counters", {})
        # "user>>>NAME>>>traffic>>>uplink" -> uplink is client-to-server.
        totals: dict[str, dict[str, int]] = {}
        for item in entries:
            if not isinstance(item, dict):
                continue
            match = VLESS_STAT_RE.match(str(item.get("name", "")))
            if not match:
                continue
            name, direction = match.group(1), match.group(2)
            try:
                value = int(item.get("value", 0) or 0)
            except (TypeError, ValueError):
                continue
            totals.setdefault(name, {"uplink": 0, "downlink": 0})[direction] = max(
                0, value
            )

        traffic = []
        for key, value in totals.items():
            rx, tx = value["uplink"], value["downlink"]
            previous = counters.get(key, {})
            old_rx, old_tx = int(previous.get("rx", 0)), int(previous.get("tx", 0))
            delta_rx = rx - old_rx if rx >= old_rx else 0
            delta_tx = tx - old_tx if tx >= old_tx else 0
            counters[key] = {"rx": rx, "tx": tx}
            if delta_rx or delta_tx:
                traffic.append(
                    {
                        # A Hysteria2 inbound hosted by sing-box reports through
                        # the same API, so label the sample with the node's own
                        # protocol rather than assuming VLESS.
                        "source": str(spec.get("protocol", "vless")),
                        "credential_key": key,
                        "bytes_in": delta_rx,
                        "bytes_out": delta_tx,
                        "bucket": iso_bucket(),
                        "sample_key": f"{node_id}:{key}:{rx}:{tx}",
                    }
                )
        return traffic

    def collect_traffic(self, spec: dict) -> list[dict]:
        if spec.get("protocol") == "vless" or self._singbox_engine(spec):
            return self.collect_vless_traffic(spec)
        if spec.get("protocol") != "hysteria2":
            return []
        node_id = int(spec["node_id"])
        state = self.node_state(node_id)
        port = int(spec.get("stats_port", 0) or 0)
        secret = state.get("traffic_secret", "")
        if not port or not secret:
            return []
        try:
            req = Request(
                f"http://127.0.0.1:{port}/traffic",
                headers={"Authorization": secret, "Accept": "application/json"},
            )
            with urlopen(req, timeout=5) as response:
                data = json.loads(response.read(1024 * 1024).decode("utf-8"))
        except Exception:
            return []
        counters = state.setdefault("counters", {})
        traffic = []
        for key, value in data.items() if isinstance(data, dict) else []:
            if not isinstance(value, dict):
                continue
            rx, tx = int(value.get("rx", 0) or 0), int(value.get("tx", 0) or 0)
            previous = counters.get(key, {})
            old_rx, old_tx = int(previous.get("rx", 0)), int(previous.get("tx", 0))
            delta_rx = rx - old_rx if rx >= old_rx else 0
            delta_tx = tx - old_tx if tx >= old_tx else 0
            counters[key] = {"rx": rx, "tx": tx}
            if delta_rx or delta_tx:
                traffic.append(
                    {
                        "source": "hysteria2",
                        "credential_key": key,
                        "bytes_in": delta_rx,
                        "bytes_out": delta_tx,
                        "bucket": iso_bucket(),
                        "sample_key": f"{node_id}:{key}:{rx}:{tx}",
                    }
                )
        return traffic

    def kick_hysteria_sessions(self, spec: dict, stats_ids: list[str]) -> int:
        """Kick only named, over-quota clients on a native Hysteria server."""
        node_id = int(spec["node_id"])
        port = int(spec.get("stats_port", 0) or 0)
        secret = str(self.node_state(node_id).get("traffic_secret", ""))
        if not port or not secret:
            raise RuntimeError("Hysteria traffic API unavailable")

        targets = sorted(
            {
                item
                for item in stats_ids
                if isinstance(item, str) and 0 < len(item) <= 128
            }
        )
        if not targets:
            return 0

        headers = {"Authorization": secret, "Accept": "application/json"}
        try:
            request = Request(
                f"http://127.0.0.1:{port}/online", headers=headers, method="GET"
            )
            with urlopen(request, timeout=5) as response:
                online = json.loads(response.read(1024 * 1024).decode("utf-8"))
            if not isinstance(online, dict):
                raise RuntimeError("Hysteria online API returned invalid data")
            targets = [
                item
                for item in targets
                if type(online.get(item)) is int and online[item] > 0
            ]
        except HTTPError as exc:
            # /online was added after /kick. An older server can still safely
            # receive this exact, server-authorized list of credential IDs.
            if exc.code != 404:
                raise
        if not targets:
            return 0

        payload = json.dumps(targets, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"http://127.0.0.1:{port}/kick",
            data=payload,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            response.read(65536)
        return len(targets)

    def process_quota_kicks(self, spec: dict, heartbeat: dict | None) -> int:
        """Deny reconnects locally before asking Hysteria to close live sessions."""
        requested = []
        if isinstance(heartbeat, dict):
            requested = heartbeat.get(
                "kick_stats_ids", heartbeat.get("quota_kick_stats_ids", [])
            )
        if not isinstance(requested, list) or not requested:
            return 0
        node_id = int(spec["node_id"])
        if spec.get("protocol") != "hysteria2" or self._singbox_engine(spec):
            return 0
        stats_ids = sorted(
            {
                item
                for item in requested
                if isinstance(item, str) and 0 < len(item) <= 128
            }
        )
        if not stats_ids:
            return 0

        with self.lock:
            desired = self.desired.get(node_id)
            if isinstance(desired, dict):
                desired["users"] = [
                    item
                    for item in desired.get("users", [])
                    if item.get("stats_id") not in stats_ids
                ]
        try:
            return self.kick_hysteria_sessions(spec, stats_ids)
        except Exception as exc:
            # Keep the agent's desired configuration status healthy; the
            # collector/next heartbeat can retry without disclosing IDs/secrets.
            LOG.warning(
                "node %s quota session kick failed: %s", node_id, type(exc).__name__
            )
            return 0

    def poll_node(self, spec: dict):
        node_id = int(spec["node_id"])
        token = str(spec.get("token", ""))
        try:
            desired = self.request_json(
                "GET", f"/api/agent/v1/desired/{node_id}", token
            )
            with self.lock:
                self.desired[node_id] = desired
            status = "observe"
            applied = desired.get("generation", "")
            if desired.get("apply"):
                status = "ready"
                applied = ""
                protocol = desired.get("protocol")
                if protocol == "hysteria2" and self._singbox_engine(spec):
                    self.apply_singbox_hysteria2(spec, desired)
                elif protocol == "hysteria2":
                    self.apply_hysteria(spec, desired)
                elif protocol == "vless":
                    self.apply_vless(spec, desired)
                else:
                    raise RuntimeError("unsupported protocol")
                applied = desired.get("generation", "")
            node_state = self.node_state(node_id)
            existing = node_state.get("pending_traffic", [])
            if not isinstance(existing, list):
                existing = []
            if len(existing) >= MAX_PENDING_TRAFFIC_RECORDS:
                if not node_state.get("traffic_backpressure"):
                    LOG.warning(
                        "node %s traffic outbox saturated at %s records; pausing collection",
                        node_id,
                        len(existing),
                    )
                node_state["traffic_backpressure"] = True
                new_samples = []
            else:
                new_samples = self.collect_traffic(spec)
            traffic = self._enqueue_traffic(node_id, new_samples)
            if len(traffic) >= MAX_PENDING_TRAFFIC_RECORDS:
                if not node_state.get("traffic_backpressure"):
                    LOG.warning(
                        "node %s traffic outbox saturated at %s records; pausing collection",
                        node_id,
                        len(traffic),
                    )
                node_state["traffic_backpressure"] = True
            # Counter baselines and their corresponding outbox records must
            # reach durable state before the heartbeat can advance counters.
            self.save_state()
            sent_traffic = copy.deepcopy(traffic[:MAX_TRAFFIC_BATCH_RECORDS])
            heartbeat = self.request_json(
                "POST",
                f"/api/agent/v1/heartbeat/{node_id}",
                token,
                {
                    "status": status,
                    "agent_version": VERSION,
                    "capabilities": self.capabilities(spec),
                    "applied_generation": applied,
                    "traffic": sent_traffic,
                },
            )
            if not isinstance(heartbeat, dict) or heartbeat.get("ok") is not True:
                raise RuntimeError("heartbeat was not acknowledged")
            traffic_ack = heartbeat.get("traffic_ack")
            if isinstance(traffic_ack, list):
                acknowledged_keys = traffic_ack
            elif heartbeat.get("traffic_records") == len(sent_traffic):
                # Compatibility with older servers that only exposed a batch
                # count. Never clear a partially accepted batch on that API.
                acknowledged_keys = [
                    str(item.get("sample_key", ""))
                    for item in sent_traffic
                    if isinstance(item, dict) and item.get("sample_key")
                ]
            else:
                acknowledged_keys = []
            self._ack_traffic(node_id, acknowledged_keys)
            remaining = self.node_state(node_id).get("pending_traffic", [])
            if (
                isinstance(remaining, list)
                and len(remaining) < MAX_PENDING_TRAFFIC_RECORDS
                and self.node_state(node_id).pop("traffic_backpressure", False)
            ):
                LOG.info("node %s traffic collection resumed", node_id)
            self.save_state()
            self.process_quota_kicks(spec, heartbeat)
        except Exception as exc:
            error = type(exc).__name__
            try:
                heartbeat = self.request_json(
                    "POST",
                    f"/api/agent/v1/heartbeat/{node_id}",
                    token,
                    {
                        "status": "error",
                        "agent_version": VERSION,
                        "capabilities": self.capabilities(spec),
                        "applied_generation": "",
                        "error": error,
                    },
                )
                self.process_quota_kicks(spec, heartbeat)
            except Exception:
                pass
            LOG.error("node %s poll failed: %s", node_id, error)

    def run(self):
        for spec in self.nodes:
            self.start_auth_server(spec)
        while True:
            started = time.monotonic()
            for spec in self.nodes:
                self.poll_node(spec)
            self.save_state()
            time.sleep(max(1, self.interval - (time.monotonic() - started)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/sub-app/node-agent.json")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    config = read_json(Path(args.config), {})
    if not config.get("endpoint") or not config.get("nodes"):
        raise SystemExit("invalid node agent config")
    Agent(config).run()


if __name__ == "__main__":
    main()
