<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api.js";
import { formatBytes, timeAgo } from "../format.js";
import { pushToast } from "../store.js";
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
  const groups = new Map();
  for (const row of credentials.value) {
    const group = groups.get(row.node_id) || [];
    group.push(row);
    groups.set(row.node_id, group);
  }
  return [...groups.entries()].map(([nodeId, rows]) => {
    rows.sort((a, b) => Number(b.version) - Number(a.version));
    return { nodeId, node: nodeById.value.get(nodeId), current: rows[0], history: rows.slice(1) };
  }).sort((a, b) => a.nodeId - b.nodeId);
});

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
      <div class="table-actions"><button class="b" :disabled="!friend.links?.clash" @click="copyText(friend.links?.clash, 'Clash 订阅链接')">复制 Clash</button><button class="b" :disabled="!friend.links?.shadowrocket" @click="copyText(friend.links?.shadowrocket, '小火箭订阅链接')">复制小火箭</button><button class="b" :disabled="!friend.links?.v2ray" @click="copyText(friend.links?.v2ray, 'V2Ray 订阅链接')">复制 V2Ray</button><button class="b b-am" @click="openEdit(friend)">查看与编辑</button></div>
    </article>
  </div>

  <Modal v-if="showForm" :title="editing ? `编辑用户 · ${editing.uid}` : '新建用户'" @close="showForm = false">
    <p v-if="formError" class="form-error" role="alert">{{ formError }}</p>
    <div v-if="!editing" class="form-row"><label for="friend-uid">UID</label><input id="friend-uid" v-model="form.uid" placeholder="唯一标识，例如 alice"></div>
    <div class="form-row"><label for="friend-remark">备注</label><input id="friend-remark" v-model="form.remark" placeholder="可选"></div>
    <div class="form-row"><label for="friend-expiry">订阅到期日（留空表示不限期）</label><input id="friend-expiry" v-model="form.expires_at" type="date"></div>
    <div class="form-row"><label for="friend-flow">用户级可计量流量配额（GB，0 表示不限）</label><input id="friend-flow" v-model="form.flow_limit_gb" type="number" min="0"><small>达到后会阻止刷新订阅，并在下一次协调时撤销可计量的独立凭据。共享凭据节点无法按用户强制断流。</small></div>
    <div class="form-row"><label for="friend-device">设备上限（0 表示不限）</label><input id="friend-device" v-model="form.device_limit" type="number" min="0"></div>
    <div class="check"><input id="friend-peruser" v-model="form.per_user_credentials" type="checkbox"><label for="friend-peruser">启用用户级独立凭据；只向该用户下发同步成功的节点凭据</label></div>

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
      <summary>用户级凭据 <span class="n">{{ credentialGroups.length }} 个节点</span></summary>
      <div class="fold-body">
        <div v-if="credentialsLoading" class="loading-lines"><div v-for="index in 3" :key="index" class="sk sk-line"></div></div>
        <div v-else-if="credentialGroups.length" class="credential-groups">
          <section v-for="group in credentialGroups" :key="group.nodeId" class="credential-group">
            <div class="credential-main"><div class="credential-name">{{ group.node?.name || `节点 #${group.nodeId}` }}</div><span class="mk" :class="credentialStatus(group.current.status).tone">{{ credentialStatus(group.current.status).text }}</span></div>
            <div class="credential-meta"><span>{{ String(group.current.protocol || "—").toUpperCase() }}</span><span>版本 {{ group.current.version }}</span><span>{{ group.current.last_synced_at ? `同步于 ${timeAgo(group.current.last_synced_at)}` : "尚未同步" }}</span></div>
            <div v-if="group.current.last_error" class="form-error">{{ group.current.last_error }}</div>
            <div v-if="group.current.status !== 'revoked'" class="credential-actions"><button class="b" :disabled="credentialBusy[group.current.id]" @click="credentialAction(group.current, 'sync')">同步</button><button class="b" :disabled="credentialBusy[group.current.id]" @click="credentialAction(group.current, 'rotate')">轮换</button><button class="b b-bad" :disabled="credentialBusy[group.current.id]" @click="credentialAction(group.current, 'revoke')">撤销</button></div>
            <details v-if="group.history.length" class="credential-history"><summary>历史记录 {{ group.history.length }}</summary><div v-for="row in group.history" :key="row.id" class="credential-history-row"><span>版本 {{ row.version }} · {{ credentialStatus(row.status).text }}</span><span>{{ timeAgo(row.revoked_at || row.rotated_at || row.created_at) }}</span></div></details>
          </section>
        </div>
        <div v-else class="st"><b>暂无用户级凭据</b><span>启用独立凭据并保存后，支持的节点会开始同步。</span></div>
      </div>
    </details>

    <div class="modal-foot"><button class="b" @click="showForm = false">取消</button><button class="b b-am" :disabled="busy" @click="submit">{{ busy ? "保存中…" : "保存" }}</button></div>
  </Modal>
</template>
