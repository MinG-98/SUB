# Node Agent

One root-only agent per proxy server.  The center (this repo's FastAPI app) is
the single source of truth; agents pull desired state, apply it locally, and
report back.  The center never connects out to a node.

## Why an agent instead of remote scripting

Per-user credentials mean the proxy core's config has to change whenever a user
is added, rotated, or revoked.  Doing that by SSH from the center would make the
center hold root on every box and would break the moment a node is unreachable.
An agent inverts the direction: nodes poll, so a node that is down simply stops
reporting instead of failing a central job.

## Protocol

    GET  /api/agent/v1/desired/<node_id>     -> desired credentials + generation
    POST /api/agent/v1/heartbeat/<node_id>   <- status, capabilities, applied generation, and per-user byte counters

Each node has its own token; only its hash is stored at the center.

A node stays in `observe` mode until it is explicitly enabled, so an agent can
be deployed and watched before it is allowed to touch any config.

## Supported layouts

| Layout | Auth path | Notes |
| --- | --- | --- |
| Standalone Hysteria2 | Agent serves a loopback HTTP auth backend | Agent is in the auth path — supervise it |
| Hysteria2 as a sing-box inbound | sing-box validates in-process | Agent not in the auth path |
| VLESS Reality (sing-box) | sing-box validates in-process | Needs `with_v2ray_api` build — see [BUILD.md](BUILD.md) |

Prefer folding Hysteria2 into sing-box where possible: a dead agent then costs
traffic accounting, not connectivity.

## Quota and live sessions

For standalone Hysteria2, once a committed traffic sample puts a user over
quota, the center returns only that node's affected credential IDs. The Agent
first removes those IDs from its loopback authentication cache, then uses the
loopback Hysteria Traffic Stats API (`/online` and `/kick`) to disconnect only
those clients. Keep the API bound to loopback and configured with a secret; the
authentication check is what prevents Hysteria clients from reconnecting after
a kick.

Hysteria2 inside sing-box has no targeted live-session kick path in this Agent.
The V2Ray API integration is for traffic counters; changing the sing-box user
list follows the normal config-apply path, which restarts the shared core and
can interrupt unrelated users. Treat zero-impact, immediate per-user quota
enforcement on this layout as unsupported until a targeted control mechanism
is implemented and verified. Do not mistake this limitation for a successful
selective kick.

## Traffic accounting

sing-box exposes per-user counters over the V2Ray gRPC API.  The agent does not
speak gRPC; `vless-stats.go` builds a small helper that queries the loopback API
and prints JSON.  **The API must stay on 127.0.0.1** — it is unauthenticated.

sing-box registers the stats service under the upstream V2Ray name on some
builds and under its own package name on others, so the helper tries both.

Build instructions for the helper, and for a sing-box that actually exposes that
API, are in [BUILD.md](BUILD.md) — stock sing-box releases omit
`with_v2ray_api`, so counters are unavailable without a rebuild.

Traffic samples remain in a per-node on-disk retry queue until the control plane
acknowledges their sample keys. Heartbeats send at most 128 queued records; when
the backlog reaches 2,048 records, the agent pauses further counter collection
until acknowledgements bring it below that threshold. A single collection pass
can cross the threshold, but an extended control-plane outage no longer causes
the agent to keep collecting and growing the queue indefinitely.

## Constraints learned the hard way

**Preserve config ownership.**  Proxy cores drop privileges (`command_user`,
systemd `User=`).  `mkstemp` creates files as root, so a config swap that only
restores the mode leaves the core unable to read its own config.  Ownership is
captured before the first swap and reapplied on both write and rollback.

**Do not rewrite an unchanged config.**  The apply path compares the rendered
output against what is on disk and returns early when equal.  Without this the
agent restarts the proxy on every poll.

**Rebuild the stats union from the whole config.**  When one sing-box hosts two
nodes, each node's apply must union every named user in the file.  Rebuilding
from only the current inbound makes the two nodes overwrite each other and
restart the core forever.  `tests/test_stats_union.py` pins this.

**Read VLESS `flow` from the persisted snapshot, not the windowed user list.**
The 24h legacy-compatibility list (`legacy_users`) empties once the window
closes, so deriving `flow` from it silently dropped the field from every
per-user entry a day after the first apply — sing-box then rejects every
client with `flow mismatch: expected none, but got xtls-rprx-vision`, while
the agent itself reports healthy (online, generation matched, config passes
`sing-box check`).  `flow` is read from the snapshot instead, which is
captured once and outlives the window.  If a node's snapshot was ever taken
from an already-flowless config, set `vless_flow` in that node's entry below
as a fallback.  `tests/test_flow_survives_window.py` pins this.

## Deploy

For an **empty Debian/Ubuntu VPS**, use the [one-command HY2 bootstrap](../deploy/NEW-NODE.md)
from the management computer. Existing proxies, Xray migration, and OpenRC hosts
are deliberately outside that installer's scope. For other layouts, continue below.

    install -m 0755 node-agent.py /usr/local/libexec/sub-app-node-agent.py
    install -m 0600 <config>      /etc/sub-app/node-agent.json

Then install the matching unit from `init/`.  Always run under a supervisor:
systemd `Restart=always`, or OpenRC `supervise-daemon`.

Config shape (one entry per node on this machine):

```json
{
  "endpoint": "https://<center>",
  "poll_seconds": 30,
  "nodes": [
    {
      "node_id": 17,
      "protocol": "vless",
      "service": "sing-box.service",
      "sing_box_binary": "/usr/local/bin/sing-box",
      "sing_box_config": "/etc/sing-box/config.json",
      "v2ray_api_listen": "127.0.0.1:10085",
      "token": "<per-node token>"
    },
    {
      "node_id": 18,
      "protocol": "hysteria2",
      "engine": "sing-box",
      "inbound_tag": "hy2-in",
      "service": "sing-box.service",
      "sing_box_config": "/etc/sing-box/config.json",
      "v2ray_api_listen": "127.0.0.1:10085",
      "token": "<per-node token>"
    }
  ]
}
```

Omit `engine` for a standalone Hysteria2 process and give `hysteria_config`,
`auth_port` and `stats_port` instead.

For an existing native **Xray VLESS/Reality** service, use `"engine": "xray"`,
`"xray_binary": "/usr/local/bin/xray"`, its actual `xray_config` and systemd
`service`, and select the inbound with its **internal** `inbound_port` and/or
`inbound_tag`. Set `v2ray_api_listen` to a free IPv4 loopback port. No sing-box
or stats helper is required. This adapter adopts at most one pre-existing client,
keeps it for the first 24 hours of per-user mode, validates a complete candidate
with `xray run -test` before swapping, and leaves Reality keys and transport
settings in place. An ambiguous inbound, a conflicting API, or an existing
multi-user list is a stop condition; don't remove existing users to bypass it.
Keep the Agent state and backup directories root-only.

Deliberately left out of the example above: `"vless_flow": "xtls-rprx-vision"`
is a fallback for the one case in "Constraints learned the hard way" below
where the persisted snapshot itself has no flow to recover.  It is not a
normal field and should not be copied into every VLESS node's config —
setting it on a node that legitimately has no flow makes every client on
that node fail the same handshake this fallback exists to prevent, just in
the opposite direction (`flow mismatch: expected xtls-rprx-vision, but got
none`).  Only add it if a node is dark and the snapshot recovery below
didn't fix it.

## Rollout

Deploy in `observe` first and confirm the heartbeat and reported capabilities.
Enable one node, verify an external dial and that per-user traffic lands at the
center, then widen.  Every config write is backed up under
`/var/lib/sub-app-node-agent/backups` and restored automatically if the proxy
fails to come back.
