<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { api } from "../api.js";
import { timeAgo } from "../format.js";
import { dataRefreshVersion, pushToast } from "../store.js";
import Modal from "../components/Modal.vue";

const ATTENTION_THRESHOLD = 500;
const loading = ref(true);
const error = ref("");
const devices = ref([]);
const friends = ref([]);
const search = ref("");
const filter = ref("all");
const sortKey = ref("label");
const sortDir = ref("asc");

const showCreate = ref(false);
const createFriendId = ref("");
const createLabel = ref("");
const createBusy = ref(false);
const createError = ref("");
const createdLinks = ref(null);

const detail = ref(null);
const detailForm = ref({ label: "", blocked: false });
const detailBusy = ref(false);
const detailLinks = ref(null);

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [deviceRows, friendRows] = await Promise.all([api.devices(), api.friends()]);
    devices.value = deviceRows || [];
    friends.value = friendRows || [];
  } catch (e) {
    error.value = e.message || "设备加载失败";
  } finally {
    loading.value = false;
  }
}

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  return devices.value.filter((device) => {
    const queryMatch = !q || [device.label, device.friend_uid, device.user_agent, device.last_ip, device.access_identifier].some((value) => String(value || "").toLowerCase().includes(q));
    const filterMatch = filter.value === "all"
      || (filter.value === "attention" && !device.blocked && device.fetch_count > ATTENTION_THRESHOLD)
      || (filter.value === "blocked" && device.blocked);
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

function deviceSortValue(device, key) {
  if (key === "fetches") return Number(device.fetch_count || 0);
  if (key === "state") return statusState(device).text;
  if (key === "uid") return String(device.friend_uid || "").toLowerCase();
  return String(device.label || `设备 #${device.id}`).toLowerCase();
}

const sortedDevices = computed(() => {
  const direction = sortDir.value === "asc" ? 1 : -1;
  return [...filtered.value].sort((a, b) => {
    const left = deviceSortValue(a, sortKey.value);
    const right = deviceSortValue(b, sortKey.value);
    if (typeof left === "number" && typeof right === "number") return (left - right) * direction;
    return String(left).localeCompare(String(right), "zh-CN") * direction;
  });
});

function identityState(device) {
  if (device.device_link_active) return { tone: "info", text: "专属订阅链接" };
  if (device.identity_source === "device_link") return { tone: "bad", text: "链接已撤销" };
  return { tone: "idle", text: "旧版 UA+IP" };
}

function statusState(device) {
  if (device.blocked) return { tone: "bad", text: "已封锁" };
  if (device.fetch_count > ATTENTION_THRESHOLD) return { tone: "warn", text: "高频拉取" };
  return { tone: "ok", text: "正常" };
}

function maskedIdentifier(device) {
  const value = String(device.access_identifier || "");
  return value ? `••••${value.slice(-8)}` : "—";
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
  createFriendId.value = friends.value[0]?.id || "";
  createLabel.value = "";
  createError.value = "";
  createdLinks.value = null;
  showCreate.value = true;
}

async function submitCreate() {
  if (!createFriendId.value) {
    createError.value = "请选择用户";
    return;
  }
  createBusy.value = true;
  createError.value = "";
  try {
    const result = await api.createDeviceLink(createFriendId.value, createLabel.value);
    createdLinks.value = result.links;
    pushToast("设备专属订阅链接已创建", "success");
    await load();
  } catch (e) {
    createError.value = e.message || "创建失败";
  } finally {
    createBusy.value = false;
  }
}

function openDetail(device) {
  detail.value = device;
  detailForm.value = { label: device.label || "", blocked: device.blocked };
  detailLinks.value = null;
}

async function saveDetail() {
  if (!detail.value || detailBusy.value) return;
  if (!detail.value.blocked && detailForm.value.blocked && !window.confirm(`确定封锁设备「${detail.value.label || `#${detail.value.id}`}」？`)) return;
  detailBusy.value = true;
  try {
    await api.updateDevice(detail.value.id, { label: detailForm.value.label, blocked: detailForm.value.blocked });
    pushToast("设备已更新", "success");
    detail.value = null;
    await load();
  } catch (e) {
    pushToast(e.message || "更新失败");
  } finally {
    detailBusy.value = false;
  }
}

async function rotateLink() {
  if (!detail.value) return;
  const converting = detail.value.identity_source !== "device_link";
  const message = converting
    ? "将这条访问记录转为设备专属链接？保留原名额和历史，不增加设备数。请将新链接导入对应客户端；普通订阅链接不会自动升级。"
    : "确定轮换该设备链接？旧的设备专属链接会立即失效。";
  if (!window.confirm(message)) return;
  detailBusy.value = true;
  try {
    const result = await api.rotateDeviceLink(detail.value.id);
    detailLinks.value = result.links;
    detail.value = { ...detail.value, ...result.device };
    pushToast(converting ? "已转换，请将专属链接导入客户端" : "链接已轮换", "success");
    await load();
  } catch (e) {
    pushToast(e.message || "轮换失败");
  } finally {
    detailBusy.value = false;
  }
}

async function revokeLink() {
  if (!detail.value || !window.confirm("确定撤销该设备专属订阅链接？")) return;
  detailBusy.value = true;
  try {
    await api.revokeDeviceLink(detail.value.id);
    pushToast("链接已撤销", "success");
    detail.value = null;
    await load();
  } catch (e) {
    pushToast(e.message || "撤销失败");
  } finally {
    detailBusy.value = false;
  }
}

async function removeDevice() {
  if (!detail.value || !window.confirm(`确定删除设备「${detail.value.label || `#${detail.value.id}`}」？此操作不可撤销。`)) return;
  detailBusy.value = true;
  try {
    await api.deleteDevice(detail.value.id);
    pushToast("设备已删除", "success");
    detail.value = null;
    await load();
  } catch (e) {
    pushToast(e.message || "删除失败");
  } finally {
    detailBusy.value = false;
  }
}

watch(dataRefreshVersion, () => load());
onMounted(load);
</script>

<template>
  <header class="view-hd">
    <div class="view-copy"><span class="lbl lbl-am">Device audit</span><h2>设备审计</h2><p>设备记录是订阅访问审计，不代表手机或电脑的硬件指纹。</p></div>
    <div class="view-actions">
      <label class="search"><span aria-hidden="true">/</span><span class="visually-hidden">搜索设备</span><input v-model="search" placeholder="搜索用户、客户端或 IP"></label>
      <button class="b b-am" @click="openCreate">创建设备链接</button>
    </div>
  </header>

  <div class="filter-line p">
    <div class="seg" role="group" aria-label="设备筛选">
      <button :aria-pressed="filter === 'all'" @click="filter = 'all'">全部</button>
      <button :aria-pressed="filter === 'attention'" @click="filter = 'attention'">待关注</button>
      <button :aria-pressed="filter === 'blocked'" @click="filter = 'blocked'">已封锁</button>
    </div>
    <span class="lbl-cn">{{ filtered.length }} / {{ devices.length }} 条访问记录</span>
  </div>

  <div v-if="loading" class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  <section v-else-if="error" class="state-wrap"><div class="st" role="alert"><b>设备加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div></section>
  <section v-else-if="!filtered.length" class="state-wrap"><div class="st"><b>没有匹配的设备</b><span>调整搜索词或筛选条件后再试。</span></div></section>

  <div v-else class="entity-grid device-table">
    <div class="table-head">
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'label' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('label')">设备 <span>{{ sortArrow('label') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'uid' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('uid')">用户 / 客户端 <span>{{ sortArrow('uid') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'fetches' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('fetches')">拉取次数 <span>{{ sortArrow('fetches') }}</span></button>
      <button class="table-head-cell" type="button" :aria-sort="sortKey === 'state' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'" @click="toggleSort('state')">状态 <span>{{ sortArrow('state') }}</span></button>
      <span class="table-head-label">操作</span>
    </div>
    <article v-for="device in sortedDevices" :key="device.id" class="entity table-row" :class="{ 'is-muted': device.blocked }">
      <div class="table-cell table-main">
        <span class="status-dot" :class="statusState(device).tone"></span>
        <div class="table-main-copy"><h3>{{ device.label || `设备 #${device.id}` }}</h3><span>ID {{ device.id }} · {{ identityState(device).text }}</span></div>
      </div>
      <div class="table-cell"><strong>{{ device.friend_uid || "—" }}</strong><span class="table-wrap-anywhere">{{ device.user_agent || "—" }}</span></div>
      <div class="table-cell"><strong>{{ Number(device.fetch_count || 0).toLocaleString("zh-CN") }} 次</strong><span>{{ maskedIdentifier(device) }}</span></div>
      <div class="table-cell"><strong class="table-state" :class="statusState(device).tone">{{ statusState(device).text }}</strong><span>{{ device.last_ip || "—" }} · {{ timeAgo(device.last_seen) }}</span></div>
      <div class="table-actions"><button class="b b-am" @click="openDetail(device)">查看详情</button></div>
    </article>
  </div>

  <Modal v-if="showCreate" title="创建设备专属订阅链接" @close="showCreate = false">
    <template v-if="createdLinks">
      <p class="form-hint">链接只在本次显示一次，数据库仅保存不可逆哈希。请现在复制给对应设备。</p>
      <div class="link-box"><code>{{ createdLinks.clash }}</code><button class="b" @click="copyText(createdLinks.clash, 'Clash 链接')">复制 Clash</button></div>
      <div class="link-box"><code>{{ createdLinks.shadowrocket }}</code><button class="b" @click="copyText(createdLinks.shadowrocket, '小火箭链接')">复制小火箭</button></div>
      <div class="link-box"><code>{{ createdLinks.v2ray }}</code><button class="b" @click="copyText(createdLinks.v2ray, 'V2Ray 链接')">复制 V2Ray</button></div>
      <div class="modal-foot"><button class="b b-am" @click="showCreate = false">完成</button></div>
    </template>
    <template v-else>
      <p v-if="createError" class="form-error" role="alert">{{ createError }}</p>
      <div class="form-row"><label for="device-owner">归属用户</label><select id="device-owner" v-model="createFriendId"><option v-for="friend in friends" :key="friend.id" :value="friend.id">{{ friend.uid }}</option></select></div>
      <div class="form-row"><label for="device-label">设备标签（可选）</label><input id="device-label" v-model="createLabel" placeholder="例如 iPhone 15"></div>
      <div class="modal-foot"><button class="b" @click="showCreate = false">取消</button><button class="b b-am" :disabled="createBusy" @click="submitCreate">{{ createBusy ? "创建中…" : "创建" }}</button></div>
    </template>
  </Modal>

  <Modal v-if="detail" :title="detail.label || `设备 #${detail.id}`" @close="detail = null">
    <template v-if="detailLinks">
      <p class="form-hint">专属链接只显示一次，请复制并导入客户端。使用它换网络不会新增名额；普通订阅链接不会自动变成专属链接。若此前有设备专属链接，旧的已失效。链接可被转发，不代表硬件身份。</p>
      <div class="link-box"><code>{{ detailLinks.clash }}</code><button class="b" @click="copyText(detailLinks.clash, 'Clash 链接')">复制 Clash</button></div>
      <div class="link-box"><code>{{ detailLinks.shadowrocket }}</code><button class="b" @click="copyText(detailLinks.shadowrocket, '小火箭链接')">复制小火箭</button></div>
      <div class="link-box"><code>{{ detailLinks.v2ray }}</code><button class="b" @click="copyText(detailLinks.v2ray, 'V2Ray 链接')">复制 V2Ray</button></div>
      <div class="modal-foot"><button class="b b-am" @click="detail = null">完成</button></div>
    </template>
    <template v-else>
      <dl class="detail-list">
        <div class="detail-item"><dt>所属用户</dt><dd>{{ detail.friend_uid }}</dd></div>
        <div class="detail-item"><dt>访问标识</dt><dd class="mono">{{ detail.access_identifier || "—" }} <button v-if="detail.access_identifier" class="b b-txt" @click="copyText(detail.access_identifier, '访问标识')">复制</button></dd></div>
        <div class="detail-item"><dt>标识来源</dt><dd><span class="mk" :class="identityState(detail).tone">{{ identityState(detail).text }}</span></dd></div>
        <div class="detail-item"><dt>完整 User-Agent</dt><dd class="mono">{{ detail.user_agent || "—" }}</dd></div>
        <div class="detail-item"><dt>最近 IP</dt><dd class="mono">{{ detail.last_ip || "—" }}</dd></div>
        <div class="detail-item"><dt>首次 / 最近访问</dt><dd>{{ timeAgo(detail.first_seen) }} / {{ timeAgo(detail.last_seen) }}</dd></div>
        <div class="detail-item"><dt>拉取次数</dt><dd class="mono">{{ Number(detail.fetch_count || 0).toLocaleString("zh-CN") }}</dd></div>
      </dl>
      <div class="form-row"><label for="detail-label">设备备注</label><input id="detail-label" v-model="detailForm.label" placeholder="未命名"></div>
      <div class="check"><input id="detail-blocked" v-model="detailForm.blocked" type="checkbox"><label for="detail-blocked">封锁该访问记录</label></div>
      <div class="modal-foot between">
        <div class="modal-foot-group"><button class="b" :disabled="detailBusy" @click="rotateLink">{{ detail.identity_source === 'device_link' ? '轮换链接' : '原名额转专属链接' }}</button><button v-if="detail.device_link_active" class="b b-bad" :disabled="detailBusy" @click="revokeLink">撤销链接</button><button class="b b-bad" :disabled="detailBusy" @click="removeDevice">删除设备</button></div>
        <div class="modal-foot-group"><button class="b" @click="detail = null">取消</button><button class="b b-am" :disabled="detailBusy" @click="saveDetail">{{ detailBusy ? "保存中…" : "保存" }}</button></div>
      </div>
    </template>
  </Modal>
</template>
