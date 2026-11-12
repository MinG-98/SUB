import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { compileScript, compileTemplate, parse } from "@vue/compiler-sfc";
import { transformSync } from "esbuild";
import * as vue from "vue";
import { api } from "../api.js";

const source = readFileSync(new URL("./UsersView.vue", import.meta.url), "utf8");
const { descriptor } = parse(source);
const script = compileScript(descriptor, { id: "users-test" });
const compiled = transformSync(script.content, { format: "cjs" }).code;
const require = createRequire(import.meta.url);

// Exercise the real SFC setup with Vue refs, without DOM or live API calls.
function setupDiagnostics() {
  const requests = [];
  let unmount;
  const mockApi = {
    friendSubscriptionDiagnostics(...args) {
      return new Promise((resolve, reject) => requests.push({ args, resolve, reject }));
    },
  };
  const module = { exports: {} };
  const scopedRequire = (id) => {
    if (id === "vue") return { ...vue, onMounted() {}, onBeforeUnmount(fn) { unmount = fn; } };
    if (id === "../api.js") return { api: mockApi };
    if (id === "../store.js") return { pushToast() {} };
    if (id.endsWith(".vue")) return { default: {} };
    return require(id);
  };
  new Function("require", "module", "exports", compiled)(scopedRequire, module, module.exports);
  const state = module.exports.default.setup({}, { expose() {} });
  return { state, requests, unmount: () => unmount() };
}

test("diagnostics API uses GET, defaults to Shadowrocket and omits hypothetical device ID", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (path, options) => {
    calls.push({ path, options });
    return new Response(JSON.stringify({ devices: [] }));
  });
  await api.friendSubscriptionDiagnostics(7);
  await api.friendSubscriptionDiagnostics(7, "clash", 12);
  await api.friendSubscriptionDiagnostics(7, "v2ray", "");
  await api.friendSubscriptionDiagnostics(7, "shadowrocket", null);
  assert.equal(calls[0].path, "/api/admin/friends/7/subscription-diagnostics?target=shadowrocket");
  assert.equal(calls[1].path, "/api/admin/friends/7/subscription-diagnostics?target=clash&device_id=12");
  assert.equal(calls[2].path, "/api/admin/friends/7/subscription-diagnostics?target=v2ray");
  assert.equal(calls[3].path, calls[0].path);
  for (const { options } of calls) {
    assert.equal(options.method || "GET", "GET");
    assert.equal(options.body, undefined);
  }
});

test("selection refresh clears results and ignores stale success, error and loading completion", async () => {
  const { state: s, requests } = setupDiagnostics();
  const first = s.openDiagnostics({ id: 7, uid: "alice", token: "not-needed" });
  assert.deepEqual(requests[0].args, [7, "shadowrocket", ""]);
  assert.deepEqual(s.diagnosticsFriend.value, { id: 7, uid: "alice" });
  const initial = { devices: [{ id: 12, label: "phone" }] };
  requests[0].resolve(initial);
  await first;
  s.diagnosticsDeviceId.value = 12;
  const oldDevice = s.refreshDiagnostics();
  assert.equal(s.diagnostics.value, null);
  assert.deepEqual(s.diagnosticsDevices.value, initial.devices);
  s.diagnosticsTarget.value = "clash";
  const current = s.refreshDiagnostics();
  assert.deepEqual(requests[2].args, [7, "clash", 12]);
  requests[1].resolve({ devices: [], target: "shadowrocket" });
  await oldDevice;
  assert.equal(s.diagnostics.value, null);
  assert.equal(s.diagnosticsLoading.value, true);
  requests[2].resolve({ devices: initial.devices, target: "clash" });
  await current;
  assert.equal(s.diagnostics.value.target, "clash");
  const oldError = s.refreshDiagnostics();
  s.diagnosticsDeviceId.value = "";
  const newest = s.refreshDiagnostics();
  requests[4].resolve({ devices: initial.devices, target: "clash", device: { scenario: "new_device" } });
  await newest;
  requests[3].reject(new Error("sensitive old error"));
  await oldError;
  assert.equal(s.diagnosticsError.value, "");
  assert.equal(s.diagnostics.value.device.scenario, "new_device");
  assert.equal(s.diagnosticsLoading.value, false);
});

test("closing, reopening for another user and unmounting invalidate pending diagnostics", async () => {
  const { state: s, requests, unmount } = setupDiagnostics();
  const old = s.openDiagnostics({ id: 7, uid: "alice" });
  s.closeDiagnostics();
  const next = s.openDiagnostics({ id: 8, uid: "bob" });
  requests[0].resolve({ devices: [{ id: 12 }] });
  await old;
  assert.equal(s.diagnosticsFriend.value.id, 8);
  assert.equal(s.diagnostics.value, null);
  assert.deepEqual(s.diagnosticsDevices.value, []);
  assert.equal(s.diagnosticsLoading.value, true);
  unmount();
  requests[1].resolve({ devices: [{ id: 13 }] });
  await next;
  assert.equal(s.diagnosticsFriend.value, null);
  assert.equal(s.diagnostics.value, null);
  assert.equal(s.diagnosticsLoading.value, false);
});

test("request failure hides raw error details and supports retry", async () => {
  const { state: s, requests } = setupDiagnostics();
  const failed = s.openDiagnostics({ id: 7, uid: "alice" });
  requests[0].reject(new Error("raw-token-must-not-appear"));
  await failed;
  assert.equal(s.diagnosticsError.value, "订阅体检加载失败，请重试。");
  assert.equal(s.diagnosticsLoading.value, false);
  const retry = s.refreshDiagnostics();
  assert.equal(s.diagnosticsError.value, "");
  requests[1].resolve({ devices: [], nodes: [] });
  await retry;
  assert.deepEqual(s.diagnostics.value.nodes, []);
});

test("diagnostics template compiles, separates admission from eligibility, and has no token/copy binding", () => {
  const result = compileTemplate({ source: descriptor.template.content, filename: "UsersView.vue", id: "users-test", compilerOptions: { bindingMetadata: script.bindings } });
  assert.deepEqual(result.errors, []);
  const modal = source.slice(source.indexOf('<Modal v-if="diagnosticsFriend"'), source.indexOf('<Modal v-if="showForm"'));
  assert.match(source, /@click="openDiagnostics\(friend\)">订阅体检/);
  assert.equal((modal.match(/@change="refreshDiagnostics"/g) || []).length, 2);
  for (const field of ["account.allowed", "device.allowed", "subscription.eligible_count", "subscription.rendered_count", "subscription.announcement_count", "node.agent.generation_matches"]) assert.ok(modal.includes(field));
  assert.match(modal, /不执行实际网络连通性测试/);
  assert.match(modal, /选择已有设备记录不代表持有其 Token/);
  assert.doesNotMatch(modal, /copyText|clipboard|v-html|\.token|\.links|JSON\.stringify/);
  assert.equal(descriptor.styles.length, 0);
});
