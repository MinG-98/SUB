<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api.js";
import { formatBytes, timeAgo } from "../format.js";
import { pushToast } from "../store.js";
import Modal from "../components/Modal.vue";
import { isRealNode, nodeStatus } from "../noc/data.js";

const loading = ref(true);
const error = ref("");
const nodes = ref([]);
const search = ref("");
const statusFilter = ref("all");

const showBulkModal = ref(false);
const bulkText = ref("");
const bulkName = ref("");
const bulkBusy = ref(false);
const bulkError = ref("");

const editing = ref(null);
const editForm = ref({ name: "", enabled: true, nezha_server_id: "", per_user_enabled: false, adapter_kind: "shared", uri: "", expires_at: "" });
const editBusy = ref(false);
const editError = ref("");
const preparing = ref(false);
const agentBusy = ref(false);
const agentTokenOnce = ref("");

function expiryLabel(value) {
  if (!value) return "无到期日";
  const remaining = Math.ceil((new Date(value).getTime() - Date.now()) / 86400000);
  if (remaining < 0) return "已到期";
  return remaining === 0 ? "今天到期" : `${remaining} 天后到期`;
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [nodeRows, latency] = await Promise.all([api.nodes(), api.latencyStatus()]);
    const probeById = new Map((latency?.nodes || []).map((node) => [node.node_id, node]));
    nodes.value = (nodeRows || []).filter(isRealNode).map((node) => ({
      ...node,
      probe: probeById.get(node.id) || null,
    }));
  } catch (e) {
    error.value = e.message || "节点加载失败";
  } finally {
    loading.value = false;
  }
}

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  return nodes.value.filter((node) => {
    const status = nodeStatus(node);
    const statusMatch = statusFilter.value === "all"
      || (statusFilter.value === "online" && status.key === "proxy_ok")
      || (statusFilter.value === "attention" && status.key !== "proxy_ok");
    const queryMatch = !q || [node.name, node.protocol, node.server].some((value) => String(value || "").toLowerCase().includes(q));
    return statusMatch && queryMatch;
  });
});

function adapterText(node) {
  if (!node.per_user_capability?.supported) return "共享模式";
  return node.per_user_capability?.label || "等待 Agent";
}

function adapterOptions(protocol) {
  const options = [{ value: "shared", label: "共享链接（不启用用户级凭据）" }];
  if (["vless", "hysteria2"].includes(protocol)) {
    options.push({ value: "remote_agent", label: "远程节点 Agent" });
  }
  if (protocol === "vless") options.push({ value: "local_vless", label: "本机 VLESS API" });
  if (protocol === "hysteria2") options.push({ value: "local_hy2", label: "本机 Hysteria2 HTTP Auth" });
  return options;
}

function statusTone(node) {
  const tone = nodeStatus(node).tone;
  return tone === "is-ok" ? "ok" : tone === "is-warn" ? "warn" : "idle";
}

async function submitBulk() {
  if (!bulkText.value.trim()) {
    bulkError.value = "请输入至少一条节点链接";
    return;
  }
  bulkBusy.value = true;
  bulkError.value = "";
  try {
    const result = await api.createNodes({ bulk: bulkText.value, name: bulkName.value || undefined });
    pushToast(`已创建 ${result.created.length} 个节点${result.skipped.length ? `，跳过 ${result.skipped.length} 条` : ""}`, "success");
    showBulkModal.value = false;
    bulkText.value = "";
    bulkName.value = "";
    await load();
  } catch (e) {
    bulkError.value = e.message || "创建失败";
  } finally {
    bulkBusy.value = false;
  }
}

function openEdit(node) {
  editing.value = node;
  editForm.value = {
    name: node.name,
    enabled: node.enabled,
    nezha_server_id: node.nezha_server_id ?? "",
    per_user_enabled: node.per_user_enabled,
    adapter_kind: node.adapter_kind || "shared",
    uri: "",
    expires_at: node.expires_at ? node.expires_at.slice(0, 10) : "",
  };
  editError.value = "";
  agentTokenOnce.value = "";
}

function closeEdit() {
  editing.value = null;
  agentTokenOnce.value = "";
}

async function submitEdit() {
  if (!editing.value) return;
  editError.value = "";
  const node = editing.value;
  const payload = {};
  if (editForm.value.name !== node.name) payload.name = editForm.value.name;
  if (editForm.value.enabled !== node.enabled) payload.enabled = editForm.value.enabled;

  const mappingText = String(editForm.value.nezha_server_id ?? "").trim();
  const mapping = mappingText ? Number(mappingText) : null;
  if (mappingText && !Number.isInteger(mapping)) {
    editError.value = "哪吒 Server ID 必须是整数";
    return;
  }
  if (mapping !== (node.nezha_server_id ?? null)) payload.nezha_server_id = mapping;
  if (editForm.value.adapter_kind !== (node.adapter_kind || "shared")) {
    payload.adapter_kind = editForm.value.adapter_kind;
  }
  if (Boolean(editForm.value.per_user_enabled) !== Boolean(node.per_user_enabled)) {
    payload.per_user_enabled = Boolean(editForm.value.per_user_enabled);
  }
  const uri = editForm.value.uri.trim();
  if (uri) payload.uri = uri;
  const expiresAt = editForm.value.expires_at || null;
  if (expiresAt !== (node.expires_at ? node.expires_at.slice(0, 10) : null)) payload.expires_at = expiresAt;
  if (!Object.keys(payload).length) {
    pushToast("没有需要保存的更改", "success");
    return;
  }

  editBusy.value = true;
  try {
    await api.updateNode(editing.value.id, payload);
    pushToast("节点已更新", "success");
    closeEdit();
    await load();
  } catch (e) {
    editError.value = e.message || "更新失败";
  } finally {
    editBusy.value = false;
  }
}

async function registerAgent() {
  if (!editing.value || agentBusy.value) return;
  agentBusy.value = true;
  editError.value = "";
  try {
    const result = await api.registerAgent(editing.value.id);
    agentTokenOnce.value = result.token;
    await load();
    editing.value = nodes.value.find((node) => node.id === editing.value?.id) || editing.value;
  } catch (e) {
    editError.value = e.message || "Agent 注册失败";
  } finally {
    agentBusy.value = false;
  }
}

async function rotateAgentToken() {
  if (!editing.value || agentBusy.value || !window.confirm("将生成一个待验证的新 token；旧 token 在确认前保持有效。继续？")) return;
  agentBusy.value = true;
  editError.value = "";
  try {
    const result = await api.rotateAgentToken(editing.value.id);
    agentTokenOnce.value = result.token;
    await load();
    editing.value = nodes.value.find((node) => node.id === editing.value?.id) || editing.value;
  } catch (e) {
    editError.value = e.message || "Agent token 轮换失败";
  } finally {
    agentBusy.value = false;
  }
}

async function confirmAgentRotation() {
  if (!editing.value || agentBusy.value || !window.confirm("确认新 token 已写入目标节点配置，并且节点已成功上报？确认后旧 token 会立即失效。")) return;
  agentBusy.value = true;
  editError.value = "";
  try {
    await api.confirmAgentTokenRotation(editing.value.id);
    agentTokenOnce.value = "";
    await load();
    editing.value = nodes.value.find((node) => node.id === editing.value?.id) || editing.value;
    pushToast("Agent token 已切换", "success");
  } catch (e) {
    editError.value = e.message || "确认 Agent token 轮换失败";
  } finally {
    agentBusy.value = false;
  }
}

async function cancelAgentRotation() {
  if (!editing.value || agentBusy.value) return;
  agentBusy.value = true;
  editError.value = "";
  try {
    await api.cancelAgentTokenRotation(editing.value.id);
    agentTokenOnce.value = "";
    await load();
    editing.value = nodes.value.find((node) => node.id === editing.value?.id) || editing.value;
    pushToast("已取消待验证 token，旧 token 继续有效", "success");
  } catch (e) {
    editError.value = e.message || "取消轮换失败";
  } finally {
    agentBusy.value = false;
  }
}

async function prepareCredentials() {
  if (!editing.value || preparing.value) return;
  preparing.value = true;
  try {
    const result = await api.prepareNodeCredentials(editing.value.id);
    pushToast(result.activated ? "独立凭据已同步" : "同步已执行，仍有凭据待处理", result.activated ? "success" : "error");
    await load();
  } catch (e) {
    pushToast(e.message || "同步凭据失败");
  } finally {
    preparing.value = false;
  }
}

async function removeNode() {
  if (!editing.value || !window.confirm(`确定删除节点「${editing.value.name}」？将影响 ${editing.value.allocated_to || 0} 个用户的节点分配，并级联删除该节点的凭据和流量记录；此操作不可撤销。`)) return;
  editBusy.value = true;
  try {
    await api.deleteNode(editing.value.id);
    pushToast("节点已删除", "success");
    closeEdit();
    await load();
  } catch (e) {
    editError.value = e.message || "删除失败";
  } finally {
    editBusy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <header class="view-hd">
    <div class="view-copy"><span class="lbl lbl-am">节点清单</span><h2>节点管理</h2><p>查看真实节点状态、流量、分配关系与用户级适配能力。</p></div>
    <div class="view-actions">
      <label class="search"><span aria-hidden="true">/</span><span class="visually-hidden">搜索节点</span><input v-model="search" placeholder="搜索节点、协议或服务器"></label>
      <button class="b b-am" @click="showBulkModal = true">批量添加</button>
    </div>
  </header>

  <div class="filter-line p">
    <div class="seg" role="group" aria-label="节点状态筛选">
      <button :aria-pressed="statusFilter === 'all'" @click="statusFilter = 'all'">全部</button>
      <button :aria-pressed="statusFilter === 'online'" @click="statusFilter = 'online'">代理可用</button>
      <button :aria-pressed="statusFilter === 'attention'" @click="statusFilter = 'attention'">待关注</button>
    </div>
    <span class="lbl-cn">{{ filtered.length }} / {{ nodes.length }} 个真实节点</span>
  </div>

  <div v-if="loading" class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  <section v-else-if="error" class="state-wrap"><div class="st" role="alert"><b>节点加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div></section>
  <section v-else-if="!filtered.length" class="state-wrap"><div class="st"><b>没有匹配的节点</b><span>调整搜索词或筛选条件后再试。</span></div></section>

  <div v-else class="entity-grid node-grid">
    <article v-for="node in filtered" :key="node.id" class="entity" :class="{ 'is-muted': !node.enabled }">
      <header class="entity-hd">
        <div class="entity-title"><span class="mk" :class="statusTone(node)"></span><div><h3>{{ node.name }}</h3><p>{{ node.server }} · {{ node.port }}</p></div></div>
        <span class="proto">{{ node.protocol }}</span>
      </header>
      <div class="entity-summary"><span class="mk" :class="statusTone(node)">{{ nodeStatus(node).text }}</span><span v-if="node.expires_at">{{ expiryLabel(node.expires_at) }}</span><span v-if="node.collector?.last_active">{{ timeAgo(node.collector.last_active) }}</span></div>
      <div class="kv-grid">
        <div class="kv"><span class="lbl-cn">24h 流量</span><strong>{{ formatBytes(node.traffic?.['24h']?.total) }}</strong></div>
        <div class="kv"><span class="lbl-cn">已分配</span><strong>{{ node.allocated_to || 0 }} 人</strong></div>
        <div class="kv"><span class="lbl-cn">哪吒</span><strong>{{ node.collector?.mapped ? "已关联" : "未关联" }}</strong></div>
        <div class="kv"><span class="lbl-cn">适配器</span><strong>{{ adapterText(node) }}</strong></div>
      </div>
      <div class="entity-actions">
        <span class="lbl-cn">ID <span class="n">{{ node.id }}</span></span><button class="b" @click="openEdit(node)">查看与编辑</button>
      </div>
    </article>
  </div>

  <Modal v-if="showBulkModal" title="批量添加节点" @close="showBulkModal = false">
    <p v-if="bulkError" class="form-error" role="alert">{{ bulkError }}</p>
    <div class="form-row"><label for="bulk-uri">节点链接（每行一条）</label><textarea id="bulk-uri" v-model="bulkText" placeholder="vless://…&#10;hysteria2://…"></textarea></div>
    <div class="form-row"><label for="bulk-name">名称（只粘贴一条时可选）</label><input id="bulk-name" v-model="bulkName" placeholder="留空则使用链接内名称"></div>
    <div class="modal-foot"><button class="b" @click="showBulkModal = false">取消</button><button class="b b-am" :disabled="bulkBusy" @click="submitBulk">{{ bulkBusy ? "创建中…" : "创建" }}</button></div>
  </Modal>

  <Modal v-if="editing" :title="editing.name" @close="closeEdit">
    <p v-if="editError" class="form-error" role="alert">{{ editError }}</p>
    <dl class="detail-list">
      <div class="detail-item"><dt>节点 ID</dt><dd class="mono">{{ editing.id }}</dd></div>
      <div class="detail-item"><dt>协议 / 入口</dt><dd class="mono">{{ editing.protocol.toUpperCase() }} · {{ editing.server }}:{{ editing.port }}</dd></div>
      <div class="detail-item"><dt>到期时间</dt><dd>{{ editing.expires_at ? `${editing.expires_at.slice(0, 10)} · ${expiryLabel(editing.expires_at)}` : "未设置" }}</dd></div>
      <div class="detail-item"><dt>24h / 7d / 30d</dt><dd class="mono">{{ formatBytes(editing.traffic?.['24h']?.total) }} · {{ formatBytes(editing.traffic?.['7d']?.total) }} · {{ formatBytes(editing.traffic?.['30d']?.total) }}</dd></div>
      <div class="detail-item"><dt>用户级适配器</dt><dd>{{ adapterText(editing) }}</dd></div>
    </dl>
    <div class="form-row"><label for="node-name">名称</label><input id="node-name" v-model="editForm.name"></div>
    <div class="form-row"><label for="node-expiry">到期日（留空表示不设置）</label><input id="node-expiry" v-model="editForm.expires_at" type="date"></div>
    <div class="check"><input id="node-enabled" v-model="editForm.enabled" type="checkbox"><label for="node-enabled">启用节点</label></div>
    <div class="form-row"><label for="nezha-id">哪吒 Server ID（留空表示未关联）</label><input id="nezha-id" v-model="editForm.nezha_server_id" type="number" placeholder="未关联"></div>
    <div class="form-row"><label for="node-adapter">凭据适配器</label><select id="node-adapter" v-model="editForm.adapter_kind"><option v-for="option in adapterOptions(editing.protocol)" :key="option.value" :value="option.value">{{ option.label }}</option></select></div>
    <div class="check"><input id="node-peruser" v-model="editForm.per_user_enabled" type="checkbox" :disabled="!editing.per_user_capability?.ready && !editing.per_user_enabled"><label for="node-peruser">启用用户级独立凭据{{ editing.per_user_capability?.ready ? "" : editing.per_user_capability?.supported ? (editing.per_user_enabled ? "（Agent 离线，可取消）" : "（Agent 未就绪）") : "（适配器不支持）" }}</label></div>
    <p v-if="editing.per_user_capability?.supported && !editing.per_user_capability?.ready" class="form-hint">节点 Agent 最近 180 秒内未上报或尚未应用配置。不能在当前状态下启用独立凭据；可取消勾选关闭，保存节点其他字段不受影响。</p>
    <p v-else-if="editing.per_user_capability?.agent_status === 'observe'" class="form-hint">Agent 已在线但尚未应用用户配置。可以启用以发起配置应用；用户级凭据只会在 Agent 回报期望版本匹配后生效。</p>
    <section v-if="editing.adapter_kind === 'remote_agent'" class="form-row">
      <label>节点 Agent</label>
      <p class="form-hint">{{ editing.agent ? `状态：${editing.agent.status}${editing.agent.last_seen ? ` · 最近上报 ${timeAgo(editing.agent.last_seen)}` : " · 尚未上报"}` : "尚未注册；注册不会自动启用用户凭据。" }}</p>
      <div class="modal-foot-group">
        <button v-if="!editing.agent" class="b" :disabled="agentBusy" @click="registerAgent">{{ agentBusy ? "注册中…" : "注册 Agent" }}</button>
        <button v-else-if="!editing.agent.rotation_pending" class="b" :disabled="agentBusy" @click="rotateAgentToken">轮换 Token</button>
        <template v-else>
          <span class="form-hint">待验证 Token 最近上报：{{ editing.agent.pending_last_seen ? timeAgo(editing.agent.pending_last_seen) : "尚未上报" }}</span>
          <button class="b" :disabled="agentBusy || !editing.agent.pending_last_seen" @click="confirmAgentRotation">确认切换</button>
          <button class="b" :disabled="agentBusy" @click="cancelAgentRotation">取消轮换</button>
        </template>
      </div>
      <p v-if="agentTokenOnce" class="form-hint" role="status">此 token 仅显示本次，请立即写入目标节点的权限为 0600 的 Agent 配置；节点服务名、代理引擎和配置路径须按实际部署填写。关闭此窗口后不会保留。</p>
      <textarea v-if="agentTokenOnce" :value="agentTokenOnce" readonly aria-label="一次性 Agent Token"></textarea>
    </section>
    <div class="form-row"><label for="node-uri">更新节点链接（留空不改）</label><input id="node-uri" v-model="editForm.uri" autocomplete="off" placeholder="vless://… / hysteria2://…"></div>
    <div class="modal-foot between">
      <div class="modal-foot-group"><button class="b b-bad" :disabled="editBusy" @click="removeNode">删除节点</button><button v-if="['vless','hysteria2'].includes(editing.protocol)" class="b" :disabled="preparing" @click="prepareCredentials">{{ preparing ? "同步中…" : "同步独立凭据" }}</button></div>
      <div class="modal-foot-group"><button class="b" @click="closeEdit">取消</button><button class="b b-am" :disabled="editBusy" @click="submitEdit">{{ editBusy ? "保存中…" : "保存" }}</button></div>
    </div>
  </Modal>
</template>
