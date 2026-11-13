#!/usr/bin/env python3
"""Render adoption candidates in a new private directory without service changes.

Native Xray validates its staged config with its installed binary. Native Hy2
is rendered here, but still requires a separate loopback engine/authentication
smoke test before activation. This command never claims deployment success.
"""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path

from adopt import AdoptionError, build_plan, digest, encoded, private_file, snapshot


def stage(manifest, module, desired, directory):
    state, report, files = build_plan(manifest, module, desired)
    directory = Path(directory)
    if (
        not directory.is_absolute()
        or directory.exists()
        or any(p.is_symlink() for p in directory.parents)
    ):
        raise AdoptionError(
            "staging requires a new absolute directory without symlink parents"
        )
    directory.mkdir(mode=0o700)
    config = copy.deepcopy(manifest["agent_config"])
    config["state_path"] = str(directory / "state.json")
    for spec in config["nodes"]:
        key = "xray_config" if spec["protocol"] == "vless" else "hysteria_config"
        suffix = ".json" if spec["protocol"] == "vless" else ".yaml"
        original = spec[key]
        spec[key] = str(directory / f"node-{spec['node_id']}{suffix}")
        data = snapshot(original)
        if digest(data) != files[original]:
            raise AdoptionError("config changed while staging")
        Path(spec[key]).write_bytes(data)
        os.chmod(spec[key], 0o600)
        spec["backup_dir"] = str(directory / "backups" / str(spec["node_id"]))
    agent = module.Agent(config)
    agent.state = copy.deepcopy(state)
    # Stage apply methods only. Never start the Agent, bind auth servers, poll,
    # send heartbeat, kick sessions, or restart live systemd services.
    agent._service_restart = lambda _spec: True
    for spec in config["nodes"]:
        if spec["protocol"] == "vless":
            agent.apply_xray(spec, desired[spec["node_id"]])
        else:
            agent.apply_hysteria(spec, desired[spec["node_id"]])
    if any(digest(snapshot(p)) != value for p, value in files.items()):
        raise AdoptionError("live config changed during staging; inspect a new plan")
    with (directory / "agent-config.json").open("xb") as out:
        out.write(encoded(config) + b"\n")
    os.chmod(directory / "agent-config.json", 0o600)
    report.update(
        staged=True, live_services_restarted=False, hy2_engine_test="required"
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--stage-dir", required=True, type=Path)
    parser.add_argument(
        "--agent-source", type=Path, default=Path(__file__).with_name("node-agent.py")
    )
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        manifest = json.loads(private_file(args.manifest))
        snapshot(args.agent_source)
        spec = importlib.util.spec_from_file_location(
            "staging_agent", args.agent_source
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        client = module.Agent(manifest["agent_config"])
        desired = {
            n["node_id"]: client.request_json(
                "GET", f"/api/agent/v1/desired/{n['node_id']}", n["token"]
            )
            for n in client.nodes
        }
        print(
            json.dumps(stage(manifest, module, desired, args.stage_dir), sort_keys=True)
        )
        return 0
    except Exception as exc:
        message = (
            str(exc)
            if isinstance(exc, AdoptionError)
            else "staging validation failed; live services were not restarted"
        )
        print(
            json.dumps({"ok": False, "error": type(exc).__name__, "message": message})
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
