import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { compileScript, compileTemplate, parse } from "@vue/compiler-sfc";
import { transformSync } from "esbuild";
import * as vue from "vue";

const source = readFileSync(new URL("./DevicesView.vue", import.meta.url), "utf8");
const { descriptor } = parse(source);
const script = compileScript(descriptor, { id: "devices-test" });
const compiled = transformSync(script.content, { format: "cjs" }).code;
const require = createRequire(import.meta.url);

function setupDevices() {
  const day = 24 * 60 * 60 * 1000;
  const rows = [
    { id: 1, friend_id: 10, friend_uid: "Ada", label: "手机", user_agent: "iPhone", last_ip: "192.0.2.1", last_seen: new Date(Date.now() - day).toISOString(), fetch_count: 4, blocked: false },
    { id: 2, friend_id: 10, friend_uid: "Ada", label: "旧设备", user_agent: "Safari", last_seen: new Date(Date.now() - 80 * day).toISOString(), fetch_count: 7, blocked: true },
    { id: 3, friend_id: 20, friend_uid: "Bob", label: "电脑", user_agent: "Chrome", last_seen: new Date(Date.now() - 10 * day).toISOString(), fetch_count: 501, blocked: false },
    { id: 4, friend_id: 20, friend_uid: "Bob", label: "备用设备", user_agent: "Edge", last_seen: new Date(Date.now() - 40 * day).toISOString(), fetch_count: 2, blocked: false },
  ];
  const mockApi = { devices: async () => rows, friends: async () => [] };
  const module = { exports: {} };
  const scopedRequire = (id) => {
    if (id === "vue") return { ...vue, onMounted() {} };
    if (id === "../api.js") return { api: mockApi };
    if (id === "../format.js") return { timeAgo: () => "刚刚" };
    if (id === "../store.js") return { dataRefreshVersion: vue.ref(0), pushToast() {} };
    if (id.endsWith(".vue")) return { default: {} };
    return require(id);
  };
  new Function("require", "module", "exports", compiled)(scopedRequire, module, module.exports);
  const state = module.exports.default.setup({}, { expose() {} });
  return { state, rows };
}

test("device view defaults to recent records and groups the visible list by user", async () => {
  const { state } = setupDevices();
  await state.load();

  assert.equal(state.filter.value, "recent");
  assert.deepEqual(state.summary.value, { total: 4, recent: 2, attention: 1, blocked: 1 });
  assert.equal(state.filtered.value.length, 2);
  assert.deepEqual(state.groupedDevices.value.map((group) => [group.uid, group.devices.length]), [["Bob", 1], ["Ada", 1]]);
  assert.equal(state.isGroupExpanded(state.groupedDevices.value[0]), false);

  state.filter.value = "all";
  await vue.nextTick();
  assert.equal(state.filtered.value.length, 4);
  assert.equal(state.groupedDevices.value.find((group) => group.uid === "Ada").blockedCount, 1);
  state.toggleAllGroups();
  await vue.nextTick();
  assert.equal(state.allGroupsExpanded.value, true);

  state.search.value = "iPhone";
  await vue.nextTick();
  assert.equal(state.filtered.value.length, 1);
  assert.equal(state.isGroupExpanded(state.groupedDevices.value[0]), true);
});

test("device template compiles and keeps verbose audit fields behind the details fold", () => {
  const result = compileTemplate({ source: descriptor.template.content, filename: "DevicesView.vue", id: "devices-test", compilerOptions: { bindingMetadata: script.bindings } });
  assert.deepEqual(result.errors, []);
  assert.match(descriptor.template.content, /近 30 天活跃/);
  assert.match(descriptor.template.content, /访问与客户端数据/);
  assert.match(descriptor.template.content, /完整 User-Agent/);
  assert.match(descriptor.template.content, /展开当前结果/);
});
