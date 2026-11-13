# Verified adoption of existing native services

This is a separate workflow from `bootstrap_node.py`, which remains new-machine
only. Never run a normal Agent over an existing multi-user configuration without
an inventory and validated state migration. `observe` is not a read-only dry run.

The current adoption planner supports native Xray Reality and native Hysteria2
`userpass` configurations managed by a legacy controller without traffic
accounting. It refuses unknown credentials, missing managed credentials,
ambiguous inbounds, mixed Xray flows, unsupported client attributes, duplicate
identities, and existing accounting requiring baseline/outbox migration.
Existing standard-Agent installations should keep their current state and use
an ordinary backed-up source upgrade instead.

## Private manifest

Create an absolute-path, owner-only JSON file (0600). It contains:

- `legacy_service`: the exact old Agent systemd service name;
- `legacy_deadline`: a fixed timezone-aware ISO timestamp, in the next 24 hours;
- `shared_sha256`: mapping node ID strings to explicitly approved shared-auth
  SHA-256 fingerprints. For VLESS hash the canonical lowercase UUID; for Hy2
  hash the exact `username:password` auth string. Obtain these from the trusted
  control-plane node configuration, not by approving every unknown live user;
- `agent_config`: the ordinary new Agent configuration with HTTPS `endpoint`,
  an explicit new absolute `state_path`, and exact native node specs/tokens.
- Optional `shared_action`: node ID string to `grace` (default) or `revoke`.
  Revocation requires explicit operator approval and the same exact fingerprint
  validation; it seeds an empty legacy list, without recapturing managed users.
  If control-plane shared metadata differs from the live credential, stop and
  obtain operator approval for the identified live shared credential first.
  Never infer approval for other nodes. For a partial migration, remove only
  the adopted node from the stopped old controller's private node/token list
  before resuming that controller for the remaining nodes.

Each native Xray spec must select one Reality inbound by `inbound_port` and/or
`inbound_tag`, provide `engine: xray`, absolute `xray_config`, installed
`xray_binary`, service and loopback stats API address. Each Hy2 spec provides
absolute `hysteria_config`, installed binary, service and free loopback
`auth_port` / `stats_port`. Do not print manifests or resulting state: they
contain credentials. Never put them in Git.

## Inspect and stage

```sh
python3 agent/adopt.py --manifest /private/adoption.json
python3 agent/stage_adoption.py --manifest /private/adoption.json \
  --stage-dir /private/new-candidate-directory
```

The first command retrieves authenticated desired state and reads exact live
files. It returns only counts, deadline and a plan digest. No state is saved,
no listener is bound, and no live proxy or service is changed. Repeating it
with unchanged inputs yields the same digest; a changed desired generation,
configuration or candidate Agent source invalidates confirmation.

Staging renders configurations and state into a **new private directory**.
It uses the actual installed Xray binary's config validation but does not start
the normal Agent or restart any service. Hy2 requires a separate isolated
loopback engine/client test: candidate HTTP auth, real TLS/QUIC handshake,
allowed and rejected credentials, and an actual proxy request. A rendered YAML
file is not proof of a working Hy2 server. Inspect staged transport/TLS/listener
settings and compare all unrelated fields with the originals.
Keep the original filename suffix during both staging and activation: native
Hysteria uses the suffix to select JSON or YAML parsing. Agent 0.5.3 preserves
JSON serialization for `.json` configurations; a YAML-only smoke test cannot
validate a JSON production configuration.

## Activation and rollback gates

1. Back up old Agent source, unit/enabled state, credentials, controller state,
   native configs, and file ownership/modes; keep a verified off-host copy.
2. Ensure reserved loopback ports are free. Finish candidate syntax and native
   smoke tests before stopping the old controller. Proxy services continue to
   run while their controller is stopped.
3. Stop only the old controller and inspect a fresh plan. Confirm the digest:

   ```sh
   python3 agent/adopt.py --manifest /private/adoption.json \
     --prepare-state --expected-plan <reviewed-plan-sha256>
   ```

   Preparation refuses a running/missing old service, any changed plan, or an
   existing state file. It creates a private fsynced state file exclusively.
   It does not install/start services. Managed users are **not** legacy users;
   only fingerprint-approved shared credentials enter the fixed grace window.
   Xray flow is retained independently even when no shared credential exists.
4. Install the reviewed source, private Agent config and service; start the new
   controller. Its first native apply can restart the proxy cores, so treat
   this as a bounded cutover, not a zero-interruption update. Before disabling
   the old controller at boot, require fresh ready heartbeats, matching
   generations, working loopback auth/stats and external proxy verification.
5. If acceptance fails: stop the new controller first; restore exact proxy
   configs with ownership/modes and restart those services; restart/re-enable
   the old controller. Do not run both controllers concurrently. Preserve the
   failed candidate/state for diagnosis; do not blindly restore a whole
   control-plane database or replay stale credential state after unrelated
   administrator changes. Verify rollback using the same external probes.

Already-prepared state is never overwritten to make a retry pass. After a failed
cutover, retain its private evidence, establish a new plan and state destination,
and reevaluate the current control-plane users. Do not extend the original
shared-credential deadline merely by retrying. A successful migration needs a
second poll/reload check and later grace-expiry verification, not just an active
systemd unit.
