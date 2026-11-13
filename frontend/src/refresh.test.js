import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { nextTick, watch } from "vue";
import { dataRefreshVersion, requestDataRefresh } from "./store.js";

const root = new URL("./", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("manual refresh increments the shared page refresh signal", async () => {
  const seen = [];
  const stop = watch(dataRefreshVersion, (value) => seen.push(value), { flush: "sync" });
  const before = dataRefreshVersion.value;
  requestDataRefresh();
  requestDataRefresh();
  await nextTick();
  stop();
  assert.equal(dataRefreshVersion.value, before + 2);
  assert.deepEqual(seen, [before + 1, before + 2]);
});

test("shell refresh reaches mounted admin data views without resetting their form state", () => {
  const shell = read("components/AppShell.vue");
  assert.match(shell, /requestDataRefresh\(\)/);
  assert.match(shell, /setInterval\(\(\) => refreshSignal\(\), 30000\)/);
  assert.match(shell, /refreshSignal\(false\)/);
  assert.match(shell, /aria-label="刷新面板数据"/);
  for (const view of ["OverviewView.vue", "NodesView.vue", "UsersView.vue", "DevicesView.vue"]) {
    const source = read(`views/${view}`);
    assert.match(source, /watch\(dataRefreshVersion, \(\) => load\(\)\)/, `${view} subscribes to shared refresh`);
    assert.match(source, /onMounted\(load\)/, `${view} retains initial load`);
  }
  const users = read("views/UsersView.vue");
  assert.match(users, /form\.value\s*=\s*\{/);
  assert.match(users, /watch\(dataRefreshVersion, \(\) => load\(\)\)/);
});
