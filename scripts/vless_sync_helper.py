#!/usr/bin/env python3
"""Narrow root helper for applying only the local VLESS user list.

The unprivileged control plane sends a bounded JSON request over a
systemd-owned Unix socket. This process always edits one fixed config, one
fixed inbound and one fixed systemd service; request data cannot select a
path, executable, unit, command or arbitrary sing-box configuration.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

CONFIG_PATH = Path("/etc/sing-box-reality/config.json")
MARKER_PATH = Path("/etc/sub-app/proxy-adapters.env")
STATE_PATH = Path("/var/lib/sub-app-vless-sync/applied.sha256")
SING_BOX_BINARY = "/usr/local/bin/sing-box-reality"
SERVICE_NAME = "sing-box-reality.service"
INBOUND_TAG = "reality-in"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_USERS = 10000
FLOW_VALUES = {"", "xtls-rprx-vision"}
USER_NAME_RE = re.compile(
    r"^(?:f[1-9][0-9]*n[1-9][0-9]*v[1-9][0-9]*|sub-app-disabled)$"
)


class VlessApplyError(RuntimeError):
    """A generic, non-sensitive helper failure."""


def _uuid_value(value) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid UUID")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("invalid UUID") from exc


def _safe_flow(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or value not in FLOW_VALUES:
        raise ValueError("unsupported VLESS flow")
    return value


def _validate_request(payload: dict) -> tuple[bool, list[dict], str]:
    if not isinstance(payload, dict) or set(payload) != {
        "enabled",
        "users",
        "flow",
        "deny_all_uuid",
    }:
        raise ValueError("invalid request schema")
    if type(payload["enabled"]) is not bool:
        raise ValueError("invalid enabled flag")
    if not isinstance(payload["users"], list) or len(payload["users"]) > MAX_USERS:
        raise ValueError("invalid user list")
    deny_all_uuid = _uuid_value(payload["deny_all_uuid"])
    flow = _safe_flow(payload["flow"])
    users = []
    names = set()
    uuids = set()
    for item in payload["users"]:
        if not isinstance(item, dict) or set(item) - {"name", "uuid", "flow"}:
            raise ValueError("invalid user entry")
        name = item.get("name")
        if not isinstance(name, str) or not USER_NAME_RE.fullmatch(name):
            raise ValueError("invalid user name")
        user_uuid = _uuid_value(item.get("uuid"))
        user_flow = _safe_flow(item.get("flow", flow))
        if name in names or user_uuid in uuids:
            raise ValueError("duplicate user entry")
        names.add(name)
        uuids.add(user_uuid)
        user = {"name": name, "uuid": user_uuid}
        if user_flow:
            user["flow"] = user_flow
        users.append(user)
    if not payload["enabled"] and users:
        raise ValueError("disabled node cannot carry users")
    return payload["enabled"], users, deny_all_uuid


def _marker_values(path: Path) -> dict[str, str]:
    values = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _legacy_window_active(marker_path: Path) -> bool:
    value = _marker_values(marker_path).get("VLESS_LEGACY_UNTIL", "")
    if not value:
        return False
    try:
        until = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < until.astimezone(timezone.utc)


def _legacy_users(old_users: list, fallback_flow: str) -> list[dict]:
    result = []
    seen = set()
    for item in old_users:
        if not isinstance(item, dict) or item.get("name") or not item.get("uuid"):
            continue
        user_uuid = _uuid_value(item["uuid"])
        if user_uuid in seen:
            continue
        user_flow = _safe_flow(item.get("flow", fallback_flow))
        user = {"uuid": user_uuid}
        if user_flow:
            user["flow"] = user_flow
        result.append(user)
        seen.add(user_uuid)
    return result


def _atomic_text(path: Path, value: str, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def apply_vless_config(
    payload: dict,
    *,
    config_path: Path = CONFIG_PATH,
    marker_path: Path = MARKER_PATH,
    state_path: Path = STATE_PATH,
    binary: str = SING_BOX_BINARY,
    service: str = SERVICE_NAME,
    runner=subprocess.run,
) -> dict:
    enabled, managed_users, deny_all_uuid = _validate_request(payload)
    if config_path.is_symlink() or not config_path.is_file():
        raise VlessApplyError("configuration unavailable")
    try:
        original = config_path.read_text(encoding="utf-8")
        original_stat = config_path.stat()
        config = json.loads(original)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise VlessApplyError("configuration unreadable") from exc
    if not isinstance(config, dict) or not isinstance(config.get("inbounds"), list):
        raise VlessApplyError("configuration invalid")
    targets = [
        inbound
        for inbound in config["inbounds"]
        if isinstance(inbound, dict) and inbound.get("tag") == INBOUND_TAG
    ]
    if len(targets) != 1 or targets[0].get("type") != "vless":
        raise VlessApplyError("target inbound invalid")
    inbound = targets[0]
    old_users = inbound.get("users")
    if not isinstance(old_users, list):
        raise VlessApplyError("target users invalid")

    legacy = (
        _legacy_users(old_users, _safe_flow(payload["flow"]))
        if enabled and _legacy_window_active(marker_path)
        else []
    )
    users = legacy + managed_users if enabled else []
    if not users:
        users = [{"name": "sub-app-disabled", "uuid": deny_all_uuid}]
    inbound["users"] = users

    experimental = config.setdefault("experimental", {})
    if not isinstance(experimental, dict):
        raise VlessApplyError("experimental config invalid")
    experimental["v2ray_api"] = {
        "listen": "127.0.0.1:10085",
        "stats": {
            "enabled": True,
            "inbounds": [INBOUND_TAG],
            "users": [user["name"] for user in users if user.get("name")],
        },
    }
    rendered = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    try:
        applied_digest = state_path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        applied_digest = ""
    if original == rendered and applied_digest == digest:
        return {"ok": True, "digest": digest, "changed": False}

    fd, temp_name = tempfile.mkstemp(
        prefix=".vless-config.", suffix=".json", dir=str(config_path.parent)
    )
    candidate = Path(temp_name)
    replaced = False
    try:
        os.fchown(fd, original_stat.st_uid, original_stat.st_gid)
        os.fchmod(fd, stat.S_IMODE(original_stat.st_mode))
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        checked = runner(
            [binary, "check", "-c", str(candidate)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if checked.returncode:
            raise VlessApplyError("configuration validation failed")
        _atomic_text(
            state_path,
            f"pending:{digest}\n",
            0o600,
            original_stat.st_uid,
            original_stat.st_gid,
        )
        if original != rendered:
            os.replace(candidate, config_path)
            replaced = True
        restarted = runner(
            ["systemctl", "restart", service],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        active = (
            runner(
                ["systemctl", "is-active", "--quiet", service],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if restarted.returncode == 0
            else None
        )
        if restarted.returncode or active is None or active.returncode:
            raise VlessApplyError("service restart failed")
    except Exception as exc:
        if replaced:
            _atomic_text(
                config_path,
                original,
                stat.S_IMODE(original_stat.st_mode),
                original_stat.st_uid,
                original_stat.st_gid,
            )
            try:
                runner(
                    ["systemctl", "restart", service],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except Exception:
                pass
        if isinstance(exc, VlessApplyError):
            raise
        raise VlessApplyError("configuration apply failed") from exc
    finally:
        candidate.unlink(missing_ok=True)

    _atomic_text(
        state_path,
        f"{digest}\n",
        0o600,
        original_stat.st_uid,
        original_stat.st_gid,
    )
    return {"ok": True, "digest": digest, "changed": original != rendered}


def main() -> int:
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "privilege_required"}))
        return 1
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        payload = json.loads(raw.decode("utf-8"))
        result = apply_vless_config(payload)
    except Exception as exc:
        error = (
            "invalid_request"
            if isinstance(exc, (ValueError, json.JSONDecodeError))
            else "apply_failed"
        )
        print(json.dumps({"ok": False, "error": error}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
