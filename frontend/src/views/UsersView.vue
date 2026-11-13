<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { api } from "../api.js";
import { formatBytes, timeAgo } from "../format.js";
import { dataRefreshVersion, pushToast } from "../store.js";
import Modal from "../components/Modal.vue";
import { isRealNode } from "../noc/data.js";

const loading = ref(true);
const error = ref("");
const friends = ref([]);
const nodes = ref([]);
const announcements = ref([]);
const search = ref("");
const filter = ref("all");
const sortKey = ref("uid");
const sortDir = ref("asc");

const showForm = ref(false);
const editing = ref(null);
const form = ref(emptyForm());
const busy = ref(false);
const formError = ref("");
const credentials = ref([]);
const credentialsLoading = ref(false);
const credentialBusy = ref({});

const diagnosticsFriend = ref(null);
const diagnosticsTarget = ref("shadowrocket");
const diagnosticsDeviceId = ref("");
const diagnosticsDevices = ref([]);
const diagnostics = ref(null);
const diagnosticsLoading = ref(false);
const diagnosticsError = ref("");
let diagnosticsRequest = 0;

function openDiagnostics(friend) {
  diagnosticsFriend.value = { id: friend.id, uid: friend.uid };
  diagnosticsTarget.value = "shadowrocket";
  diagnosticsDeviceId.value = "";
  diagnosticsDevices.value = [];
  return refreshDiagnostics();
}

function closeDiagnostics() {
  diagnosticsRequest += 1;
  diagnosticsFriend.value = null;
  diagnostics.value = null;
  diagnosticsDevices.value = [];
  diagnosticsError.value = "";
  diagnosticsLoading.value = false;
}

async function refreshDiagnostics() {
  if (!diagnosticsFriend.value) return;
  const requestId = ++diagnosticsRequest;
  diagnostics.value = null;
  diagnosticsError.value = "";
  diagnosticsLoading.value = true;
  try {
    const result = await api.friendSubscriptionDiagnostics(diagnosticsFriend.value.id, diagnosticsTarget.value, diagnosticsDeviceId.value);
    if (requestId !== diagnosticsRequest) return;
    diagnostics.value = result;
    diagnosticsDevices.value = result.devices || [];
  } catch (e) {
    if (requestId !== diagnosticsRequest) return;
    // Do not display arbitrary response bodies: they may contain sensitive URLs.
    diagnosticsError.value = e.status === 401 ? "登录已失效，请重新登录后重试。"
      : e.status === 404 ? "用户或设备记录不存在，或体检接口尚未部署。请重新打开体检或稍后重试。"
        : "订阅体检加载失败，请重试。";
  } finally {
    if (requestId === diagnosticsRequest) diagnosticsLoading.value = false;
  }
}

function diagnosticAgentState(state) {
  return { not_managed: "非托管", unregistered: "未注册", stale: "状态陈旧", online: "在线", error: "错误" }[state] || "未知";
}

onBeforeUnmount(closeDiagnostics);

function emptyForm() {
  return { uid: "", remark: "", flow_limit_gb: 0, device_limit: 0, per_user_credentials: false, node_ids: [], announcement_ids: [], rotate_token: false, expires_at: "" };
}

function expiryDays(value) {
  return value ? Math.ceil((new Date(value).getTime() - Date.now()) / 86400000) : null;
}

function expiryText(value) {
  const days = expiryDays(value);
  if (days === null) return "未设置到期日";
  if (days < 0) return `已到期 ${Math.abs(days)} 天`;
  return days === 0 ? "今天到期" : `${days} 天后到期`;
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [friendRows, nodeRows, announcementRows] = await Promise.all([api.friends(), api.nodes(), api.announcements()]);
    friends.value = friendRows || [];
    nodes.value = nodeRows || [];
    announcements.value = announcementRows || [];
  } catch (e) {
    error.value = e.message || "用户加载失败";
  } finally {
    loading.value = false;
  }
}

const realNodes = computed(() => nodes.value.filter(isRealNode));
const nodeById = computed(() => new Map(nodes.value.map((node) => [node.id, node])));
const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  return friends.value.filter((friend) => {
    const queryMatch = !q || [friend.uid, friend.remark].some((value) => String(value || "").toLowerCase().includes(q));
    const filterMatch = filter.value === "all"
      || (filter.value === "enabled" && friend.enabled)
      || (filter.value === "attention" && (!friend.enabled || friend.flow_alert === "over" || (expiryDays(friend.expires_at) !== null && expiryDays(friend.expires_at) <= 7) || friend.credential_status?.some((row) => ["error", "pending"].includes(row.status))));
    return queryMatch && filterMatch;
  });
});

function toggleSort(key) {
  if (sortKey.value === key) sortDir.value = sortDir.value === "asc" ? "desc" : "asc";
  else {
    sortKey.value = key;
    sortDir.value = "asc";
  }
}

function sortArrow(key) {
  return sortKey.value === key ? (sortDir.value === "asc" ? "▲" : "▼") : "";
}

function userSortValue(friend, key) {
  if (key === "nodes") return realNodeCount(friend);
  if (key === "flow") return Number(friend.flow_used_bytes || 0);
  if (key === "cred") return authState(friend).text;
  return String(friend.uid || "").toLowerCase();
}

const sortedFriends = computed(() => {
  const direction = sortDir.value === "asc" ? 1 : -1;
  return [...filtered.value].sort((a, b) => {
    const left = userSortValue(a, sortKey.value);
    const right = userSortValue(b, sortKey.value);
    if (typeof left === "number" && typeof right === "number") return (left - right) * direction;
    return String(left).localeCompare(String(right), "zh-CN") * direction;
  });
});

function realNodeCount(friend) {
  return friend.node_ids.length;
}

function authState(friend) {
  if (friend.device_credentials_mode === "required") return { tone: "ok", text: "设备凭据隔离" };
  if (friend.device_credentials_mode === "preparing") return { tone: "warn", text: "设备凭据准备中" };
  if (friend.device_credentials_mode === "restoring") return { tone: "warn", text: "兼容凭据恢复中" };
  if (!friend.per_user_credentials) return { tone: "idle", text: "共享凭据" };
  const rows = friend.credential_status || [];
  if (rows.some((row) => row.status === "error")) return { tone: "bad", text: "专属 · 有错误" };
  if (rows.some((row) => row.status === "pending")) return { tone: "warn", text: "专属 · 处理中" };
  if (rows.some((row) => row.status === "active")) return { tone: "ok", text: "专属 · 已生效" };
  if (rows.some((row) => row.status === "grace")) return { tone: "warn", text: "专属 · 宽限期" };
  return { tone: "idle", text: "专属 · 待同步" };
}

function quotaTone(friend) {
  return friend.flow_alert === "over" ? "is-over" : friend.flow_alert === "warning" ? "is-warning" : "";
}

function credentialStatus(status) {
  return {
    active: { tone: "ok", text: "已生效" },
    grace: { tone: "warn", text: "宽限中" },
    pending: { tone: "info", text: "待同步" },
    error: { tone: "bad", text: "同步失败" },
    revoked: { tone: "idle", text: "已撤销" },
  }[status] || { tone: "idle", text: status || "未知" };
}

const credentialGroups = computed(() => {
  const nodes = new Map();
  for (const row of credentials.value) {
    const nodeScopes = nodes.get(row.node_id) || new Map();
    const scope = row.device_id ? `device-${row.device_id}` : "account";
    const group = nodeScopes.get(scope) || [];
    group.push(row);
    nodeScopes.set(scope, group);
    nodes.set(row.node_id, nodeScopes);
  }
  return [...nodes.entries()].map(([nodeId, scopes]) => ({
    nodeId,
    node: nodeById.value.get(nodeId),
    scopes: [...scopes.entries()].map(([scope, rows]) => {
      rows.sort((a, b) => Number(b.version) - Number(a.version));
      const current = rows[0];
      return {
        key: `${nodeId}:${scope}`,
        scopeLabel: current.device_id ? (current.device_label || `设备 #${current.device_id}`) : "账户级",
        current,
        history: rows.slice(1),
      };
    }).sort((a, b) => Number(a.current.device_id || 0) - Number(b.current.device_id || 0)),
  })).sort((a, b) => a.nodeId - b.nodeId);
});

function credentialGroupStatus(group) {
  const statuses = group.scopes.map((scope) => scope.current.status);
  return ["error", "pending", "active", "grace"].find((status) => statuses.includes(status)) || "revoked";
}

function deviceModeLabel(friend) {
  return {
    off: "兼容模式",
    preparing: "准备中",
    required: "严格隔离",
    restoring: "恢复中",
  }[friend.device_credentials_mode || "off"] || "状态未知";
}

function deviceModeDescription(friend) {
  const mode = friend.device_credentials_mode || "off";
  const progress = friend.device_credential_progress || {};
  if (mode === "preparing") {
    return `准备阶段保留旧订阅凭据；设备凭据已应用 ${progress.active_credentials || 0}/${progress.required_credentials || 0}。全部就绪后才能启用严格隔离。`;
  }
  if (mode === "required") {
    return `严格隔离已启用：设备凭据 ${progress.active_credentials || 0}/${progress.required_credentials || 0} 正常。未登记链接不能刷新订阅。`;
  }
  if (mode === "restoring") {
    return `正在恢复兼容凭据；账户凭据已应用 ${progress.active_global_credentials || 0}/${progress.required_global_credentials || 0}。全部就绪后再次点击完成恢复。`;
  }
  return `默认兼容旧订阅。准备会先创建每台登记设备的独立代理凭据，不会立即停用旧链接。当前有 ${friend.device_count || 0} 条设备记录；准备要求至少一条有效登记链接。`;
}

function deviceModeActionLabel(friend) {
  const mode = friend.device_credentials_mode || "off";
  if (mode === "preparing") return "启用严格隔离";
  if (mode === "required") return "恢复兼容订阅";
  if (mode === "restoring") return "检查恢复进度";
  return "准备设备级凭据";
}

function deviceModeAction(friend) {
  const mode = friend.device_credentials_mode || "off";
  if (mode === "off") return "prepare";
  if (mode === "preparing") return "activate";
  return "restore";
}

async function runDeviceCredentialAction() {
  const friend = editing.value;
  if (!friend) return;
  const action = deviceModeAction(friend);
  const confirmation = action === "activate"
    ? `启用「${friend.uid}」的严格设备隔离？未登记设备的通用订阅链接会停止工作；请确认每台在用设备都已有独立链接。`
    : action === "restore"
      ? `为「${friend.uid}」恢复兼容订阅？系统会先等所有节点应用账户级凭据，再撤销设备凭据。`
      : `为「${friend.uid}」准备设备级凭据？现有通用订阅暂时保持可用。`;
  if (!window.confirm(confirmation)) return;
  busy.value = true;
  formError.value = "";
  try {
    const fn = {
      prepare: api.prepareDeviceCredentials,
      activate: api.activateDeviceCredentials,
      restore: api.restoreCompatibleCredentials,
    }[action];
    const result = await fn(friend.id);
    pushToast(result.message || `设备凭据${deviceModeLabel({ device_credentials_mode: result.mode })}`, "success");
    await load();
    editing.value = friends.value.find((item) => item.id === friend.id) || null;
    if (editing.value) credentials.value = await api.friendCredentials(friend.id);
  } catch (e) {
    formError.value = e.message || "设备凭据模式切换失败";
  } finally {
    busy.value = false;
  }
}

async function copyText(value, label) {
  try {
    await navigator.clipboard.writeText(value);
    pushToast(`${label}已复制`, "success");
  } catch {
    pushToast("浏览器未允许复制，请在地址栏授权剪贴板");
  }
}

function openCreate() {
  editing.value = null;
  form.value = emptyForm();
  formError.value = "";
  credentials.value = [];
  showForm.value = true;
}

async function openEdit(friend) {
  editing.value = friend;
  form.value = {
    uid: friend.uid,
    remark: friend.remark || "",
    flow_limit_gb: friend.flow_limit_gb,
    device_limit: friend.device_limit,
    per_user_credentials: friend.per_user_credentials,
    node_ids: [...friend.node_ids],
    announcement_ids: [...(friend.announcement_ids || [])],
    rotate_token: false,
    expires_at: friend.expires_at ? friend.expires_at.slice(0, 10) : "",
  };
  formError.value = "";
  credentials.value = friend.credential_status || [];
  showForm.value = true;
  credentialsLoading.value = true;
  try {
    credentials.value = await api.friendCredentials(friend.id);
  } catch (e) {
    pushToast(e.message || "凭据详情加载失败");
  } finally {
    credentialsLoading.value = false;
  }
}

async function submit() {
  if (busy.value) return;
  busy.value = true;
  formError.value = "";
  try {
    const payload = {
      remark: form.value.remark,
      flow_limit_gb: Number(form.value.flow_limit_gb) || 0,
      device_limit: Number(form.value.device_limit) || 0,
      per_user_credentials: form.value.per_user_credentials,
      node_ids: form.value.node_ids,
      announcement_ids: form.value.announcement_ids,
      expires_at: form.value.expires_at || null,
    };
    if (editing.value) {
      if (form.value.rotate_token) payload.rotate_token = true;
      await api.updateFriend(editing.value.id, payload);
      pushToast("用户已更新", "success");
    } else {
      if (!form.value.uid.trim()) throw new Error("UID 不能为空");
      await api.createFriend({ ...payload, uid: form.value.uid.trim() });
      pushToast("用户已创建", "success");
    }
    showForm.value = false;
    await load();
  } catch (e) {
    formError.value = e.message || "保存失败";
  } finally {
    busy.value = false;
  }
}

async function toggleEnabled(friend) {
  if (friend.enabled && !window.confirm(`确定停用用户「${friend.uid}」？其订阅将停止生成。`)) return;
  try {
    await api.updateFriend(friend.id, { enabled: !friend.enabled });
    pushToast(friend.enabled ? "用户已停用" : "用户已启用", "success");
    await load();
  } catch (e) {
    pushToast(e.message || "操作失败");
  }
}

async function removeFriend(friend) {
  if (!window.confirm(`确定删除用户「${friend.uid}」？将级联删除 ${friend.device_count || 0} 台设备、${friend.node_ids?.length || 0} 个节点分配、${friend.announcement_ids?.length || 0} 个公告分配及用户凭据/流量记录；订阅 Token 立即失效，且此操作不可撤销。`)) return;
  try {
    await api.deleteFriend(friend.id);
    pushToast("用户已删除", "success");
    await load();
  } catch (e) {
    pushToast(e.message || "删除失败");
  }
}

async function credentialAction(row, action) {
  const labels = { sync: "同步", rotate: "轮换", revoke: "撤销" };
  if (action === "revoke" && !window.confirm(`确定撤销节点「${nodeById.value.get(row.node_id)?.name || row.node_id}」的当前凭据？`)) return;
  credentialBusy.value = { ...credentialBusy.value, [row.id]: true };
  try {
    const fn = { sync: api.syncCredential, rotate: api.rotateCredential, revoke: api.revokeCredential }[action];
    await fn(row.id);
    pushToast(`凭据${labels[action]}完成`, "success");
    if (editing.value) credentials.value = await api.friendCredentials(editing.value.id);
  } catch (e) {
    pushToast(e.message || `凭据${labels[action]}失败`);
  } finally {
    const next = { ...credentialBusy.value };
    delete next[row.id];
    credentialBusy.value = next;
  }
}

watch(dataRefreshVersion, () => load());
onMounted(load);
</script>

<template>
  <header class="view-hd">
    <div class="view-copy"><span class="lbl lbl-am">用户订阅</span><h2>用户管理</h2><p>用户、配额、节点分配与订阅入口集中管理。</p></div>
    <div class="view-actions">
      <label class="search"><span aria-hidden="true">/</span><span class="visually-hidden">搜索用户</span><input v-model="search" placeholder="搜索 UID 或备注"></label>
      <button class="b b-am" @click="openCreate">新建用户</button>
    </div>
  </header>

  <div class="filter-line p">
    <div class="seg" role="group" aria-label="用户筛选">
      <button :aria-pressed="filter === 'all'" @click="filter = 'all'">全部</button>
      <button :aria-pressed="filter === 'enabled'" @click="filter = 'enabled'">启用</button>
      <button :aria-pressed="filter === 'attention'" @click="filter = 'attention'">待关注</button>
    </div>
    <span class="lbl-cn">{{ filtered.length }} / {{ friends.length }} 个用户</span>
  </div>

  <div v-if="loading" class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  <section v-else-if="error" class="state-wrap"><div class="st" role="alert"><b>用户加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div></section>
  <section v-else-if="!filtered.length" class="state-wrap"><div class="st"><b>没有匹配的用户</b><span>调整搜索词或筛选条件后再试。</span></div></section>

  <div v-else class="entity-grid user-table">
    <div class="table-head">
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'uid' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('uid')">用户 <span>{{ sortArrow('uid') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'nodes' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('nodes')">节点 / 设备 <span>{{ sortArrow('nodes') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'flow' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('flow')">用户级流量 <span>{{ sortArrow('flow') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'cred' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('cred')">凭据 <span>{{ sortArrow('cred') }}</span></button>
      <span class="table-head-label">订阅格式 / 操作</span>
    </div>
    <article v-for="friend in sortedFriends" :key="friend.id" class="entity table-row" :class="{ 'is-muted': !friend.enabled }">
      <div class="table-cell table-main">
        <span class="status-dot" :class="friend.enabled ? 'ok' : 'idle'"></span>
        <div class="table-main-copy"><h3>{{ friend.uid }}</h3><span>{{ friend.remark || "无备注" }}</span></div>
      </div>
      <div class="table-cell"><strong>{{ realNodeCount(friend) }} 个节点</strong><span>{{ friend.device_count || 0 }}{{ friend.device_limit ? ` / ${friend.device_limit}` : "" }} 台设备</span></div>
      <div class="table-cell table-flow"><strong>{{ formatBytes(friend.flow_used_bytes || 0) }} / {{ friend.flow_limit_bytes ? formatBytes(friend.flow_limit_bytes) : "不限" }}</strong><div v-if="friend.flow_limit_bytes" class="bar table-bar"><i :class="quotaTone(friend)" :style="{ '--meter': `${Math.min(100, Number(friend.flow_percent || 0))}%` }"></i></div></div>
      <div class="table-cell"><strong class="table-state" :class="authState(friend).tone">{{ authState(friend).text }}</strong><span>{{ friend.expires_at ? `到期：${friend.expires_at.slice(0, 10)} · ${expiryText(friend.expires_at)}` : `创建于 ${timeAgo(friend.created_at)}` }}</span><span v-if="friend.last_shared_fallback_nodes || friend.last_skipped_node_count || friend.last_expired_node_count" class="mk is-warn" role="status">最近订阅：{{ friend.last_shared_fallback_nodes || 0 }} 回退 · {{ friend.last_skipped_node_count || 0 }} 未同步 · {{ friend.last_expired_node_count || 0 }} 到期</span></div>
      <div class="table-actions"><button class="b" :disabled="!friend.links?.clash" @click="copyText(friend.links?.clash, 'Clash 订阅链接')">复制 Clash</button><button class="b" :disabled="!friend.links?.shadowrocket" @click="copyText(friend.links?.shadowrocket, '小火箭订阅链接')">复制小火箭</button><button class="b" :disabled="!friend.links?.v2ray" @click="copyText(friend.links?.v2ray, 'V2Ray 订阅链接')">复制 V2Ray</button><button class="b" @click="openDiagnostics(friend)">订阅体检</button><button class="b b-am" @click="openEdit(friend)">查看与编辑</button></div>
    </article>
  </div>

  <Modal v-if="diagnosticsFriend" :title="`订阅体检 · ${diagnosticsFriend.uid}`" @close="closeDiagnostics">
    <p class="form-hint">只读诊断：不会真实拉取订阅、创建设备、消耗名额或更新拉取记录，也不执行实际网络连通性测试。不展示或复制 Token；选择已有设备记录不代表持有其 Token。</p>
    <div class="form-row">
      <label for="diagnostics-target">订阅格式</label>
      <select id="diagnostics-target" v-model="diagnosticsTarget" @change="refreshDiagnostics">
        <option value="clash">Clash</option><option value="shadowrocket">Shadowrocket（小火箭）</option><option value="v2ray">V2Ray</option>
      </select>
    </div>
    <div class="form-row">
      <label for="diagnostics-device">设备场景</label>
      <select id="diagnostics-device" v-model="diagnosticsDeviceId" @change="refreshDiagnostics">
        <option value="">假设新设备（不创建设备）</option>
        <option v-for="device in diagnosticsDevices" :key="device.id" :value="device.id">{{ device.label || `设备 #${device.id}` }} · #{{ device.id }} · {{ device.identity_source }}{{ device.blocked ? ' · 已封禁' : '' }}{{ device.link_revoked ? ' · 链接已撤销' : '' }}</option>
      </select>
    </div>
    <p v-if="diagnosticsLoading" class="form-hint" role="status">正在生成只读诊断…</p>
    <p v-else-if="diagnosticsError" class="form-error" role="alert">{{ diagnosticsError }}</p>
    <div v-else-if="diagnostics" aria-live="polite">
      <p class="form-hint">用户 {{ diagnostics.uid }} · #{{ diagnostics.friend_id }} · {{ diagnostics.target }} · 生成时间 {{ diagnostics.generated_at }}</p>
      <section class="credential-group">
        <h3 class="credential-name">账户与设备准入</h3>
        <div class="credential-main"><strong>账户</strong><span class="mk" :class="diagnostics.account.allowed ? 'ok' : 'bad'">{{ diagnostics.account.allowed ? '允许' : '拒绝' }}</span></div>
        <p>{{ diagnostics.account.message }} <span class="n faint">（{{ diagnostics.account.code }}）</span></p>
        <div class="credential-main"><strong>设备 · {{ diagnostics.device.scenario === 'new_device' ? '假设新设备' : `已有记录 #${diagnostics.device.selected_id}` }}</strong><span class="mk" :class="diagnostics.device.allowed ? 'ok' : 'bad'">{{ diagnostics.device.allowed ? '允许' : '拒绝' }}</span></div>
        <p>{{ diagnostics.device.message }} <span class="n faint">（{{ diagnostics.device.code }}）</span></p>
        <p class="form-hint">设备数 {{ diagnostics.device.count }} / {{ diagnostics.device.limit === 0 ? '不限' : diagnostics.device.limit }}</p>
      </section>
      <section class="credential-group">
        <h3 class="credential-name">节点资格与订阅预期</h3>
        <p>预期 HTTP {{ diagnostics.subscription.http_status }} · {{ diagnostics.subscription.code }}</p>
        <div class="credential-meta"><span>已分配 {{ diagnostics.subscription.assigned_count }}</span><span>符合条件 {{ diagnostics.subscription.eligible_count }}</span><span>预期渲染 {{ diagnostics.subscription.rendered_count }}</span><span>公告 {{ diagnostics.subscription.announcement_count }}</span></div>
        <p class="form-hint">节点符合条件不等于账户或设备获准拉取；公告不计作可用节点。以下为配置与同步状态判断，不是节点连通性测试。</p>
      </section>
      <div class="credential-groups">
        <section v-for="node in diagnostics.nodes" :key="node.node_id" class="credential-group">
          <div class="credential-main"><h3 class="credential-name">{{ node.name }} · #{{ node.node_id }}</h3><span class="mk" :class="node.included ? 'ok' : 'warn'">{{ node.included ? '纳入' : '排除' }}</span></div>
          <p>{{ node.message }} <span class="n faint">（{{ node.code }}）</span></p>
          <div class="credential-meta"><span>{{ node.protocol }}</span><span>凭据状态：{{ credentialStatus(node.credential_status).text }}</span><span>凭据同步时间：{{ node.credential_synced_at || '尚无同步记录' }}</span></div>
          <div class="credential-meta"><span>Agent：{{ diagnosticAgentState(node.agent.state) }}</span><span>配置代次：{{ node.agent.generation_matches === true ? '匹配' : node.agent.generation_matches === false ? '不匹配' : '未知 / 不适用' }}</span></div>
        </section>
        <div v-if="!diagnostics.nodes.length" class="st"><b>无节点诊断记录</b><span>请结合账户准入与节点计数判断；这不表示网络故障。</span></div>
      </div>
      <p v-if="diagnostics.notice" class="form-hint">{{ diagnostics.notice }}</p>
    </div>
    <div class="modal-foot"><button class="b" @click="closeDiagnostics">关闭</button><button class="b b-am" :disabled="diagnosticsLoading" @click="refreshDiagnostics">{{ diagnosticsLoading ? '体检中…' : '刷新体检' }}</button></div>
  </Modal>

  <Modal v-if="showForm" :title="editing ? `编辑用户 · ${editing.uid}` : '新建用户'" @close="showForm = false">
    <p v-if="formError" class="form-error" role="alert">{{ formError }}</p>
    <div v-if="!editing" class="form-row"><label for="friend-uid">UID</label><input id="friend-uid" v-model="form.uid" placeholder="唯一标识，例如 alice"></div>
    <div class="form-row"><label for="friend-remark">备注</label><input id="friend-remark" v-model="form.remark" placeholder="可选"></div>
    <div class="form-row"><label for="friend-expiry">订阅到期日（留空表示不限期）</label><input id="friend-expiry" v-model="form.expires_at" type="date"></div>
    <div class="form-row"><label for="friend-flow">用户级可计量流量配额（GB，0 表示不限）</label><input id="friend-flow" v-model="form.flow_limit_gb" type="number" min="0"><small>达到后会阻止刷新订阅，并在下一次协调时撤销可计量的独立凭据。共享凭据节点无法按用户强制断流。</small></div>
    <div class="form-row"><label for="friend-device">设备上限（0 表示不限）</label><input id="friend-device" v-model="form.device_limit" type="number" min="0"></div>
    <div class="check"><input id="friend-peruser" v-model="form.per_user_credentials" type="checkbox" :disabled="editing && editing.device_credentials_mode !== 'off'"><label for="friend-peruser">启用用户级独立凭据；只向该用户下发同步成功的节点凭据</label></div>
    <p v-if="editing && editing.device_credentials_mode !== 'off'" class="form-hint">设备隔离切换中不能关闭用户级独立凭据；请先恢复兼容订阅。</p>

    <section v-if="editing" class="credential-group device-credential-mode">
      <div class="credential-main"><strong>设备级凭据隔离</strong><span class="mk" :class="editing.device_credentials_mode === 'required' ? 'ok' : ['preparing', 'restoring'].includes(editing.device_credentials_mode) ? 'warn' : 'idle'">{{ deviceModeLabel(editing) }}</span></div>
      <p class="form-hint">{{ deviceModeDescription(editing) }}</p>
      <p class="form-hint">这是基于已登记订阅链接的逻辑隔离，不是硬件指纹认证；链接持有人仍可复制使用。</p>
      <div class="credential-actions"><button class="b b-am" :disabled="busy || (!form.per_user_credentials && (editing.device_credentials_mode || 'off') === 'off') || ((editing.device_credentials_mode || 'off') === 'off' && (!editing.device_count || !editing.node_ids?.length)) || (editing.device_credentials_mode === 'preparing' && !editing.device_credential_progress?.ready)" @click="runDeviceCredentialAction">{{ deviceModeActionLabel(editing) }}</button></div>
    </section>

    <details class="fold">
      <summary>分配真实节点 <span class="n">{{ form.node_ids.filter((id) => realNodes.some((node) => node.id === id)).length }}/{{ realNodes.length }}</span></summary>
      <div class="fold-body check-list">
        <div v-for="node in realNodes" :key="node.id" class="check"><input :id="`friend-node-${node.id}`" v-model="form.node_ids" type="checkbox" :value="node.id"><label :for="`friend-node-${node.id}`">{{ node.name }} <span class="n faint">· {{ node.protocol }}</span></label></div>
        <div v-if="!realNodes.length" class="st"><b>暂无可分配节点</b></div>
      </div>
    </details>

    <details class="fold">
      <summary>分配订阅公告 <span class="n">{{ form.announcement_ids.length }}/{{ announcements.length }}</span></summary>
      <div class="fold-body check-list">
        <div v-for="announcement in announcements" :key="announcement.id" class="check"><input :id="`friend-announcement-${announcement.id}`" v-model="form.announcement_ids" type="checkbox" :value="announcement.id"><label :for="`friend-announcement-${announcement.id}`">{{ announcement.name }} <span class="n faint">· {{ announcement.enabled ? "已发布" : "草稿" }}</span></label></div>
        <div v-if="!announcements.length" class="st"><b>暂无公告</b></div>
      </div>
    </details>

    <div v-if="editing" class="check"><input id="friend-rotate" v-model="form.rotate_token" type="checkbox"><label for="friend-rotate">重置订阅 Token；保存后旧订阅链接立即失效</label></div>

    <details v-if="editing" class="fold">
      <summary>独立凭据详情 <span class="n">{{ credentialGroups.length }} 个节点</span></summary>
      <div class="fold-body">
        <div v-if="credentialsLoading" class="loading-lines"><div v-for="index in 3" :key="index" class="sk sk-line"></div></div>
        <div v-else-if="credentialGroups.length" class="credential-groups">
          <details v-for="group in credentialGroups" :key="group.nodeId" class="credential-group credential-node-group">
            <summary class="credential-main"><div class="credential-name">{{ group.node?.name || `节点 #${group.nodeId}` }}<span class="credential-meta">{{ group.scopes.length }} 种凭据范围</span></div><span class="mk" :class="credentialStatus(credentialGroupStatus(group)).tone">{{ credentialStatus(credentialGroupStatus(group)).text }}</span></summary>
            <section v-for="scope in group.scopes" :key="scope.key" class="credential-scope">
              <div class="credential-main"><div class="credential-name">{{ scope.scopeLabel }}</div><span class="mk" :class="credentialStatus(scope.current.status).tone">{{ credentialStatus(scope.current.status).text }}</span></div>
              <div class="credential-meta"><span>{{ String(scope.current.protocol || "—").toUpperCase() }}</span><span>版本 {{ scope.current.version }}</span><span>{{ scope.current.last_synced_at ? `同步于 ${timeAgo(scope.current.last_synced_at)}` : "尚未同步" }}</span></div>
              <div v-if="scope.current.last_error" class="form-error">{{ scope.current.last_error }}</div>
              <div v-if="scope.current.status !== 'revoked'" class="credential-actions"><button class="b" :disabled="credentialBusy[scope.current.id]" @click="credentialAction(scope.current, 'sync')">同步</button><button class="b" :disabled="credentialBusy[scope.current.id]" @click="credentialAction(scope.current, 'rotate')">轮换</button><button v-if="!scope.current.device_id" class="b b-bad" :disabled="credentialBusy[scope.current.id]" @click="credentialAction(scope.current, 'revoke')">撤销</button><span v-else class="form-hint">设备凭据请在设备页封锁或撤销</span></div>
              <details v-if="scope.history.length" class="credential-history"><summary>历史记录 {{ scope.history.length }}</summary><div v-for="row in scope.history" :key="row.id" class="credential-history-row"><span>版本 {{ row.version }} · {{ credentialStatus(row.status).text }}</span><span>{{ timeAgo(row.revoked_at || row.rotated_at || row.created_at) }}</span></div></details>
            </section>
          </details>
        </div>
        <div v-else class="st"><b>暂无用户级凭据</b><span>启用独立凭据并保存后，支持的节点会开始同步。</span></div>
      </div>
    </details>

    <div class="modal-foot"><button class="b" @click="showForm = false">取消</button><button class="b b-am" :disabled="busy" @click="submit">{{ busy ? "保存中…" : "保存" }}</button></div>
  </Modal>
</template>
