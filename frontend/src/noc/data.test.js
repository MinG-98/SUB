import test from "node:test";
import assert from "node:assert/strict";
import { healthRows, isRealNode, nodeStatus, probeState, summarizeProbe } from "./data.js";

test("probe summary uses its own checked denominators", () => {
  const now = Date.parse("2026-11-10T00:00:00Z");
  const result = summarizeProbe(
    {
      status: "partial",
      finished_at: new Date(now - 60_000).toISOString(),
      summary: {
        nodes_total: 3,
        entry_total: 3,
        entry_ok: 2,
        proxy_total: 2,
        proxy_ok: 1,
      },
    },
    now,
  );

  assert.equal(result.fresh, true);
  assert.equal(result.nodesTotal, 3);
  assert.equal(result.entryOk, 2);
  assert.equal(result.entryTotal, 3);
  assert.equal(result.proxyOk, 1);
  assert.equal(result.proxyTotal, 2);
});

test("missing, running, failed, stale, and future probe results stay unknown", () => {
  const now = Date.parse("2026-11-10T00:00:00Z");
  const validSummary = {
    nodes_total: 1,
    entry_total: 1,
    entry_ok: 1,
    proxy_total: 1,
    proxy_ok: 1,
  };
  const cases = [
    {},
    { status: "running", summary: validSummary },
    { status: "error", finished_at: new Date(now).toISOString(), summary: validSummary },
    { status: "success", finished_at: new Date(now - 16 * 60_000).toISOString(), summary: validSummary },
    { status: "success", finished_at: new Date(now + 1_000).toISOString(), summary: validSummary },
  ];

  for (const value of cases) {
    const result = summarizeProbe(value, now);
    assert.equal(result.fresh, false);
    assert.equal(result.entryOk, null);
    assert.equal(result.proxyOk, null);
  }
});

test("unsupported probes are not rendered as network failures", () => {
  const node = {
    enabled: true,
    probe: {
      entry: { state: "unsupported" },
      proxy: { state: "unsupported" },
    },
  };

  assert.equal(nodeStatus(node).key, "probe_unavailable");
  assert.equal(probeState({ entry: { state: "ok" }, proxy: { state: "unsupported" } }).key, "unsupported");
});

test("nodes waiting for an Agent are not mislabeled as unreachable", () => {
  const node = {
    enabled: true,
    probe: { entry: { state: "waiting_agent" }, proxy: { state: "waiting_agent" } },
  };

  assert.equal(nodeStatus(node).key, "waiting_agent");
  assert.equal(probeState(node.probe).key, "waiting");
});

test("real loopback endpoints are not guessed to be announcements", () => {
  assert.equal(
    isRealNode({ is_announcement: false, server: "127.0.0.1", port: 1 }),
    true,
  );
  assert.equal(
    isRealNode({ is_announcement: true, server: "example.com", port: 443 }),
    false,
  );
});

test("collector and reconciler jobs show stale states instead of persistent green", () => {
  const rows = healthRows({
    collector: {
      status: "success",
      stale: true,
      age_seconds: 16 * 60,
      finished_at: "2026-11-10T00:00:00Z",
      nodes_total: 14,
      samples_written: 14,
      proxy: { status: "success", stale: true, age_seconds: 30 * 60 },
      reconciler: { status: "success", stale: false, age_seconds: 60 },
    },
    latency: { nodes: [] },
  });

  assert.equal(rows.find((row) => row.name === "哪吒采集").tone, "is-warn");
  assert.equal(rows.find((row) => row.name === "代理统计").text, "陈旧");
  assert.equal(rows.find((row) => row.name === "凭据协调器").tone, "is-ok");
});

test("database health asks for verification on pre-fix SQLite versions", () => {
  const rows = healthRows({
    collector: {
      status: "success",
      stale: false,
      sqlite_version: "3.50.6",
      sqlite_wal_reset_fix: "verify_backport",
    },
    latency: { nodes: [] },
  });
  const database = rows.find((row) => row.name === "数据库");

  assert.equal(database.tone, "is-warn");
  assert.equal(database.text, "需核实版本");
  assert.match(database.detail, /WAL 修复回补/);
});
