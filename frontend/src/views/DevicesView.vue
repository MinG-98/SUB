<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api.js";
import { timeAgo } from "../format.js";
import { pushToast } from "../store.js";
import Modal from "../components/Modal.vue";

const ATTENTION_THRESHOLD = 500;
const loading = ref(true);
const error = ref("");
const devices = ref([]);
const friends = ref([]);
const search = ref("");
const filter = ref("all");

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

const deviceSummary = computed(() => ({
  linked: devices.value.filter((device) => device.device_link_active).length,
  legacy: devices.value.filter((device) => device.identity_source !== "device_link").length,
}));

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
  if (!detail.value || !window.confirm("确定轮换该设备链接？旧链接会立即失效。")) return;
  detailBusy.value = true;
  try {
    const result = await api.rotateDeviceLink(detail.value.id);
    detailLinks.value = result.links;
    pushToast("链接已轮换", "success");
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

onMounted(load);
</script>

<template>
  <header class="view-hd">
    <div class="view-copy"><span class="lbl lbl-am">设备审计</span><h2>设备审计</h2><p>设备记录是订阅访问审计，不代表手机或电脑的硬件指纹。</p></div>
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
    <span class="lbl-cn">{{ filtered.length }} / {{ devices.length }} 条访问记录 · 专属 {{ deviceSummary.linked }} · 旧版 {{ deviceSummary.legacy }}</span>
  </div>

  <div v-if="loading" class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  <section v-else-if="error" class="state-wrap"><div class="st" role="alert"><b>设备加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div></section>
  <section v-else-if="!filtered.length" class="state-wrap"><div class="st"><b>没有匹配的设备</b><span>调整搜索词或筛选条件后再试。</span></div></section>

  <div v-else class="entity-grid device-grid">
    <article v-for="device in filtered" :key="device.id" class="entity" :class="{ 'is-muted': device.blocked }">
      <header class="entity-hd">
        <div class="entity-title"><span class="mk" :class="statusState(device).tone"></span><div><h3>{{ device.label || `设备 #${device.id}` }}</h3><p>{{ device.friend_uid }} · ID {{ device.id }}</p></div></div>
        <span class="mk" :class="statusState(device).tone">{{ statusState(device).text }}</span>
      </header>
      <div class="kv-grid">
        <div class="kv"><span class="lbl-cn">访问标识</span><strong>{{ maskedIdentifier(device) }}</strong></div>
        <div class="kv"><span class="lbl-cn">来源</span><strong>{{ identityState(device).text }}</strong></div>
        <div class="kv"><span class="lbl-cn">最近 IP</span><strong>{{ device.last_ip || "—" }}</strong></div>
        <div class="kv"><span class="lbl-cn">拉取次数</span><strong>{{ Number(device.fetch_count || 0).toLocaleString("zh-CN") }}</strong></div>
      </div>
      <div class="row-sub"><span>客户端：{{ device.user_agent || "—" }}</span><span>最近活跃：{{ timeAgo(device.last_seen) }}</span></div>
      <div class="entity-actions"><span class="mk" :class="identityState(device).tone">{{ identityState(device).text }}</span><button class="b b-am" @click="openDetail(device)">查看详情</button></div>
    </article>
  </div>

  <Modal v-if="showCreate" title="创建设备专属订阅链接" @close="showCreate = false">
    <template v-if="createdLinks">
      <p class="form-hint">链接只在本次显示一次，数据库仅保存不可逆哈希。请现在复制给对应设备。</p>
      <div class="link-box"><code>{{ createdLinks.clash }}</code><button class="b" @click="copyText(createdLinks.clash, 'Clash 链接')">复制</button></div>
      <div class="link-box"><code>{{ createdLinks.shadowrocket }}</code><button class="b" @click="copyText(createdLinks.shadowrocket, '小火箭链接')">复制小火箭</button></div>
      <div class="link-box"><code>{{ createdLinks.v2ray }}</code><button class="b" @click="copyText(createdLinks.v2ray, 'V2Ray 链接')">复制</button></div>
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
      <p class="form-hint">新链接只在本次显示一次，旧链接已经失效。</p>
      <div class="link-box"><code>{{ detailLinks.clash }}</code><button class="b" @click="copyText(detailLinks.clash, 'Clash 链接')">复制</button></div>
      <div class="link-box"><code>{{ detailLinks.shadowrocket }}</code><button class="b" @click="copyText(detailLinks.shadowrocket, '小火箭链接')">复制小火箭</button></div>
      <div class="link-box"><code>{{ detailLinks.v2ray }}</code><button class="b" @click="copyText(detailLinks.v2ray, 'V2Ray 链接')">复制</button></div>
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
        <div class="modal-foot-group"><button v-if="detail.identity_source === 'device_link'" class="b" :disabled="detailBusy" @click="rotateLink">轮换链接</button><button v-if="detail.device_link_active" class="b b-bad" :disabled="detailBusy" @click="revokeLink">撤销链接</button><button class="b b-bad" :disabled="detailBusy" @click="removeDevice">删除设备</button></div>
        <div class="modal-foot-group"><button class="b" @click="detail = null">取消</button><button class="b b-am" :disabled="detailBusy" @click="saveDetail">{{ detailBusy ? "保存中…" : "保存" }}</button></div>
      </div>
    </template>
  </Modal>
</template>
