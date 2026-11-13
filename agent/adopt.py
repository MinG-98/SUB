#!/usr/bin/env python3
"""Explicit native-service adoption: inspect first, seed state only after quiescing.

Never installs/restarts services or edits proxy configs. The private manifest
identifies exact files and the fingerprints of explicitly approved shared
credentials; unknown live credentials are refused. Desired users come from
the authenticated control plane, not a caller-supplied desired-state file.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml


class AdoptionError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def private_file(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AdoptionError("expected an absolute regular private file")
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid not in {0, os.geteuid()}:
        raise AdoptionError("private manifest ownership or permissions are unsafe")
    return path.read_bytes()


def snapshot(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AdoptionError("proxy config must be an absolute regular file")
    return path.read_bytes()


def deadline(value, now):
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError()
        seconds = (result - now).total_seconds()
    except (TypeError, ValueError):
        raise AdoptionError("legacy deadline must be explicit timezone-aware ISO time")
    if not 0 < seconds <= 86400:
        raise AdoptionError("adoption requires an unexpired deadline within 24 hours")
    return result


def validate_desired(spec, desired, agent_module):
    node_id = spec["node_id"]
    protocol = spec["protocol"]
    if (
        type(node_id) is not int
        or node_id <= 0
        or type(desired.get("node_id")) is not int
        or desired.get("node_id") != node_id
        or desired.get("protocol") != protocol
        or desired.get("mode") != "per_user"
        or desired.get("apply") is not True
        or desired.get("enabled") is not True
    ):
        raise AdoptionError("adoption requires a matching enabled per-user node")
    agent_module.Agent.validate_desired_users(desired, protocol)
    unsigned = {
        k: desired[k]
        for k in ("node_id", "protocol", "enabled", "mode", "apply", "users")
    }
    raw = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if desired.get("generation") != digest(raw):
        raise AdoptionError("desired generation does not match its payload")
    ids = [u["stats_id"] for u in desired["users"]]
    if any(u.get("protocol") != protocol for u in desired["users"]):
        raise AdoptionError("explicit protocol tags are required for adoption")
    if len(set(ids)) != len(ids) or any(
        not re.fullmatch(rf"f[1-9]\d*n{node_id}v[1-9]\d*", x) for x in ids
    ):
        raise AdoptionError(
            "desired user identity is ambiguous or belongs to another node"
        )


def approve_live_credentials(actual, wanted, approved):
    """Return only explicitly fingerprinted shared material, never managed users."""
    if (
        not isinstance(approved, list)
        or len(set(approved)) != len(approved)
        or any(
            not isinstance(x, str) or not re.fullmatch(r"[0-9a-f]{64}", x)
            for x in approved
        )
    ):
        raise AdoptionError("invalid approved shared credential fingerprints")
    if set(wanted) - set(actual):
        raise AdoptionError("live config is missing control-plane credentials")
    extra = set(actual) - set(wanted)
    if {digest(x.encode()) for x in extra} != set(approved):
        raise AdoptionError("unapproved or missing shared credential; adoption refused")
    return extra


def node_seed(spec, config, desired, approved, until):
    users = desired["users"]
    if spec["protocol"] == "vless" and spec.get("engine") == "xray":
        tag, port = spec.get("inbound_tag"), spec.get("inbound_port")
        targets = [
            i
            for i in config.get("inbounds", [])
            if (tag or port)
            and i.get("protocol") == "vless"
            and i.get("streamSettings", {}).get("security") == "reality"
            and (not tag or i.get("tag") == tag)
            and (not port or str(i.get("port")) == str(port))
        ]
        if len(targets) != 1:
            raise AdoptionError("exactly one native Reality inbound must be selected")
        settings = targets[0].get("settings", {})
        fields = [k for k in ("clients", "users") if k in settings]
        if len(fields) != 1 or not isinstance(settings[fields[0]], list):
            raise AdoptionError("ambiguous Xray user list")
        clients = settings[fields[0]]
        if any(key in config for key in ("api", "stats", "policy")):
            raise AdoptionError(
                "existing accounting requires baseline migration, not fresh adoption"
            )
        if any(set(c) - {"id", "email", "flow"} for c in clients):
            raise AdoptionError("unsupported Xray client attributes would be lost")
        actual = {str(uuid.UUID(c["id"])): c for c in clients}
        wanted = {str(uuid.UUID(u["uuid"])): u["stats_id"] for u in users}
        if len(actual) != len(clients) or len(wanted) != len(users):
            raise AdoptionError("duplicate Xray credentials")
        for value, identity in wanted.items():
            if value in actual and actual[value].get("email") != identity:
                raise AdoptionError(
                    "live Xray accounting identity differs from control plane"
                )
        extra = approve_live_credentials(actual, wanted, approved)
        flows = {c.get("flow", "") for c in clients}
        if len(flows) != 1 or any(not isinstance(f, str) for f in flows):
            raise AdoptionError(
                "mixed or missing Xray flow requires explicit migration"
            )
        seed = {
            "xray_legacy": [actual[value] for value in sorted(extra)],
            "xray_legacy_until": until.timestamp(),
            "xray_flow": next(iter(flows)),
        }
    elif spec["protocol"] == "hysteria2" and not spec.get("engine"):
        if "trafficStats" in config:
            raise AdoptionError(
                "existing accounting requires baseline migration, not fresh adoption"
            )
        auth = config.get("auth", {})
        if auth.get("type") != "userpass" or not isinstance(auth.get("userpass"), dict):
            raise AdoptionError("only native Hy2 userpass adoption is supported")
        pairs = auth["userpass"]
        if any(
            not isinstance(k, str)
            or not k
            or ":" in k
            or not isinstance(v, str)
            or not v
            for k, v in pairs.items()
        ):
            raise AdoptionError("invalid live Hy2 credentials")
        actual = {f"{k}:{v}" for k, v in pairs.items()}
        wanted = {f"{u['username']}:{u['password']}" for u in users}
        if len(wanted) != len(users):
            raise AdoptionError("duplicate Hy2 credentials")
        extra = approve_live_credentials(actual, wanted, approved)
        seed = {"legacy_auth": sorted(extra), "legacy_until": until.isoformat()}
    else:
        raise AdoptionError(
            "unsupported adoption layout; existing service left untouched"
        )
    return seed, {
        "node_id": spec["node_id"],
        "protocol": spec["protocol"],
        "managed_users": len(users),
        "shared_users": len(extra),
    }


def build_plan(manifest, agent_module, desired_by_node, now=None):
    now = now or datetime.now(timezone.utc)
    until = deadline(manifest.get("legacy_deadline"), now)
    config = manifest["agent_config"]
    agent_module.Agent._validate_endpoint(config.get("endpoint"))
    state_path = Path(config["state_path"])
    if not state_path.is_absolute():
        raise AdoptionError("state path must be explicit and absolute")
    nodes = config["nodes"]
    if not nodes or len({n["node_id"] for n in nodes}) != len(nodes):
        raise AdoptionError("empty or duplicate node specifications")
    actions = manifest.get("shared_action", {})
    if (
        not isinstance(actions, dict)
        or set(actions) - {str(n["node_id"]) for n in nodes}
        or any(a not in {"grace", "revoke"} for a in actions.values())
    ):
        raise AdoptionError("invalid explicit shared credential action")
    state = {"nodes": {}}
    summary, files, generations = [], {}, {}
    for spec in nodes:
        desired = desired_by_node[spec["node_id"]]
        validate_desired(spec, desired, agent_module)
        key = "xray_config" if spec["protocol"] == "vless" else "hysteria_config"
        path = spec[key]
        if path in files:
            raise AdoptionError(
                "multiple nodes sharing one config require a separate migration"
            )
        data = snapshot(path)
        parsed = json.loads(data) if key == "xray_config" else yaml.safe_load(data)
        seed, report = node_seed(
            spec,
            parsed,
            desired,
            manifest["shared_sha256"].get(str(spec["node_id"]), []),
            until,
        )
        action = actions.get(str(spec["node_id"]), "grace")
        if action == "revoke":
            # Still require exact approved fingerprints above. Revocation must
            # never turn unknown live credentials into implicitly approved ones.
            seed["xray_legacy" if spec["protocol"] == "vless" else "legacy_auth"] = []
            report["revoked_shared_users"] = report["shared_users"]
            report["shared_users"] = 0
        report["shared_action"] = action
        state["nodes"][str(spec["node_id"])] = seed
        files[path] = digest(data)
        generations[str(spec["node_id"])] = desired["generation"]
        summary.append(report)
    binding = {
        "manifest_sha256": digest(encoded(manifest)),
        "files": files,
        "generations": generations,
        "state_sha256": digest(encoded(state)),
    }
    return (
        state,
        {
            "ok": True,
            "plan_sha256": digest(encoded(binding)),
            "nodes": summary,
            "legacy_deadline": until.isoformat(),
            "proxy_configs_changed": False,
        },
        files,
    )


def require_stopped(legacy_service):
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", legacy_service):
        raise AdoptionError("invalid legacy service name")
    status = subprocess.check_output(
        ["systemctl", "show", legacy_service, "-p", "LoadState", "-p", "ActiveState"],
        text=True,
        timeout=10,
    )
    if set(status.splitlines()) != {"LoadState=loaded", "ActiveState=inactive"}:
        raise AdoptionError("stop the identified legacy Agent before preparing state")


def prepare_state(path, state, legacy_service):
    if os.geteuid() != 0:
        raise AdoptionError("state preparation requires root")
    require_stopped(legacy_service)
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise AdoptionError("refusing to overwrite existing Agent state")
    if any(p.is_symlink() for p in path.parents):
        raise AdoptionError("state parent must not contain symlinks")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AdoptionError("state directory must be private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(encoded(state) + b"\n")
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--agent-source", type=Path, default=Path(__file__).with_name("node-agent.py")
    )
    parser.add_argument("--prepare-state", action="store_true")
    parser.add_argument("--expected-plan")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(private_file(args.manifest))
        source = snapshot(args.agent_source)
        spec = importlib.util.spec_from_file_location(
            "adoption_agent", args.agent_source
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        config = manifest["agent_config"]
        if args.prepare_state:
            require_stopped(manifest["legacy_service"])
        client = module.Agent(config)
        desired = {
            n["node_id"]: client.request_json(
                "GET", f"/api/agent/v1/desired/{n['node_id']}", n["token"]
            )
            for n in config["nodes"]
        }
        state, report, files = build_plan(manifest, module, desired)
        report["plan_sha256"] = digest(
            encoded({"plan": report["plan_sha256"], "agent_sha256": digest(source)})
        )
        if args.prepare_state:
            if not args.expected_plan or args.expected_plan != report["plan_sha256"]:
                raise AdoptionError(
                    "plan changed or confirmation missing; inspect a fresh plan"
                )
            if any(digest(snapshot(p)) != value for p, value in files.items()):
                raise AdoptionError("proxy config changed during validation")
            prepare_state(config["state_path"], state, manifest["legacy_service"])
        report["state_prepared"] = args.prepare_state
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        # Never print response bodies, paths, URIs, tokens or parser exceptions.
        message = (
            str(exc)
            if isinstance(exc, AdoptionError)
            else "adoption validation failed; no proxy config was changed"
        )
        print(
            json.dumps({"ok": False, "error": type(exc).__name__, "message": message})
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
