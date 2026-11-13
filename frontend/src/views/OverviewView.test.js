import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { compileScript, compileTemplate, parse } from "@vue/compiler-sfc";
import { transformSync } from "esbuild";
import * as vue from "vue";

const source = readFileSync(new URL("./OverviewView.vue", import.meta.url), "utf8");
const { descriptor } = parse(source);
const script = compileScript(descriptor, { id: "overview-test" });
const compiled = transformSync(script.content, { format: "cjs" }).code;
const require = createRequire(import.meta.url);

function setupOverview() {
  const calls = [];
  const announcement = { id: 7, name: "维护提醒", enabled: true, allocated_to: 3 };
  const mockApi = {
    stats: async () => ({}),
    nodes: async () => [{ id: 40, name: "真实代理节点", enabled: true, is_announcement: false, collector: { online: true }, traffic: {} }],
    announcements: async () => [announcement],
    latencyStatus: async () => ({ summary: {}, nodes: [] }),
    devices: async () => [],
    collectorStatus: async () => ({}),
    createAnnouncement: async (payload) => calls.push(["createAnnouncement", payload]),
    updateAnnouncement: async (id, payload) => calls.push(["updateAnnouncement", id, payload]),
    deleteAnnouncement: async (id) => calls.push(["deleteAnnouncement", id]),
    createNodes: async (payload) => calls.push(["createNodes", payload]),
    updateNode: async (id, payload) => calls.push(["updateNode", id, payload]),
    deleteNode: async (id) => calls.push(["deleteNode", id]),
  };
  const module = { exports: {} };
  const scopedRequire = (id) => {
    if (id === "vue") return { ...vue, onMounted() {} };
    if (id === "vue-router") return { useRouter: () => ({ push() {} }) };
    if (id === "../api.js") return { api: mockApi };
    if (id === "../format.js") return { formatBytes: () => "0 B", formatLatency: () => "—", formatPercent: () => "0%", timeAgo: () => "—" };
    if (id === "../store.js") return { dataRefreshVersion: vue.ref(0), pushToast() {} };
    if (id === "../noc/data.js") return { activityByUser: () => [], healthRows: () => [], isRealNode: (node) => !node.is_announcement, probeState: () => ({ key: "untested", text: "未探测" }) };
    if (id.endsWith(".vue")) return { default: {} };
    return require(id);
  };
  new Function("require", "module", "exports", compiled)(scopedRequire, module, module.exports);
  const state = module.exports.default.setup({}, { expose() {} });
  return { state, calls, announcement };
}

test("overview loads announcements independently from proxy nodes and uses announcement CRUD", async () => {
  const { state, calls, announcement } = setupOverview();
  await state.load();
  assert.deepEqual(state.announcements.value, [announcement]);

  state.openAnnouncement();
  state.announcementForm.value = { name: "新提醒", enabled: false };
  await state.saveAnnouncement();
  state.openAnnouncement(announcement);
  state.announcementForm.value = { name: "更新提醒", enabled: true };
  await state.saveAnnouncement();
  await state.toggleAnnouncement(announcement);

  assert.deepEqual(calls, [
    ["createAnnouncement", { name: "新提醒", enabled: false }],
    ["updateAnnouncement", 7, { name: "更新提醒", enabled: true }],
    ["updateAnnouncement", 7, { enabled: false }],
  ]);
  assert.equal(calls.some(([method]) => ["createNodes", "updateNode", "deleteNode"].includes(method)), false);
});

test("overview template compiles and renders announcement assignment counts", () => {
  const result = compileTemplate({ source: descriptor.template.content, filename: "OverviewView.vue", id: "overview-test", compilerOptions: { bindingMetadata: script.bindings } });
  assert.deepEqual(result.errors, []);
  assert.match(descriptor.template.content, /已分配 \{\{ node\.allocated_to \|\| 0 \}\} 位用户/);
});
