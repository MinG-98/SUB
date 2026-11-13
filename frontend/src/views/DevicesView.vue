<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { api } from "../api.js";
import { timeAgo } from "../format.js";
import { dataRefreshVersion, pushToast } from "../store.js";
import Modal from "../components/Modal.vue";

const ATTENTION_THRESHOLD = 500;
const RECENT_DAYS = 30;
const loading = ref(true);
const error = ref("");
const devices = ref([]);
const friends = ref([]);
const search = ref("");
const filter = ref("recent");
const groupOpenOverrides = ref(new Map());

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

function isWithinDays(value, days) {
  const timestamp = Date.parse(value || "");
  const age = Date.now() - timestamp;
  return Number.isFinite(timestamp) && age >= 0 && age <= days * 24 * 60 * 60 * 1000;
}

const summary = computed(() => ({
  total: devices.value.length,
  recent: devices.value.filter((device) => isWithinDays(device.last_seen, RECENT_DAYS)).length,
  attention: devices.value.filter((device) => !device.blocked && device.fetch_count > ATTENTION_THRESHOLD).length,
  blocked: devices.value.filter((device) => device.blocked).length,
}));

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  return devices.value.filter((device) => {
    const queryMatch = !q || [device.label, device.friend_uid, device.user_agent, device.last_ip, device.access_identifier].some((value) => String(value || "").toLowerCase().includes(q));
    const filterMatch = filter.value === "all"
      || (filter.value === "recent" && isWithinDays(device.last_seen, RECENT_DAYS))
      || (filter.value === "attention" && !device.blocked && device.fetch_count > ATTENTION_THRESHOLD)
      || (filter.value === "blocked" && device.blocked);
    return queryMatch && filterMatch;
  });
});

const groupedDevices = computed(() => {
  const groups = new Map();
  const rows = [...filtered.value].sort((a, b) => Date.parse(b.last_seen || "") - Date.parse(a.last_seen || ""));
  for (const device of rows) {
    const key = String(device.friend_id ?? device.friend_uid ?? "unknown");
    let group = groups.get(key);
    if (!group) {
      group = { key, uid: device.friend_uid || "未知用户", devices: [], blockedCount: 0, attentionCount: 0, latestSeen: device.last_seen };
      groups.set(key, group);
    }
    group.devices.push(device);
    if (device.blocked) group.blockedCount += 1;
    else if (device.fetch_count > ATTENTION_THRESHOLD) group.attentionCount += 1;
    if (Date.parse(device.last_seen || "") > Date.parse(group.latestSeen || "")) group.latestSeen = device.last_seen;
  }
  return [...groups.values()].sort((a, b) =>
    (b.blockedCount + b.attentionCount) - (a.blockedCount + a.attentionCount)
      || Date.parse(b.latestSeen || "") - Date.parse(a.latestSeen || "")
      || a.uid.localeCompare(b.uid, "zh-CN"),
  );
});

function isGroupExpanded(group) {
  const override = groupOpenOverrides.value.get(group.key);
  if (override !== undefined) return override;
  return Boolean(search.value.trim() || filter.value === "attention" || filter.value === "blocked");
}

function setGroupExpanded(group, expanded) {
  const next = new Map(groupOpenOverrides.value);
  next.set(group.key, expanded);
  groupOpenOverrides.value = next;
}

const allGroupsExpanded = computed(() => groupedDevices.value.length > 0 && groupedDevices.value.every(isGroupExpanded));

function toggleAllGroups() {
  const expanded = !allGroupsExpanded.value;
  const next = new Map();
  for (const group of groupedDevices.value) next.set(group.key, expanded);
  groupOpenOverrides.value = next;
}

watch([search, filter], () => { groupOpenOverrides.value = new Map(); });

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
    <div class="view-copy"><span class="lbl lbl-am">DEVICE MANAGEMENT</span><h2>设备管理</h2><p>按用户收纳订阅访问记录；默认只看近 30 天。访问记录不等于真实的手机或电脑。</p></div>
    <div class="view-actions">
      <label class="search"><span aria-hidden="true">/</span><span class="visually-hidden">搜索设备</span><input v-model="search" placeholder="搜用户、设备名、客户端或 IP（当前范围）"></label>
      <button class="b b-am" @click="openCreate">新建设备链接</button>
    </div>
  </header>

  <section class="kpis device-kpis" aria-label="设备记录摘要">
    <div class="kpi"><span class="lbl-cn">近 30 天活跃</span><div class="big">{{ summary.recent }}</div><span class="sub">默认显示范围</span></div>
    <div class="kpi"><span class="lbl-cn">全部记录</span><div class="big">{{ summary.total }}</div><span class="sub">可切换查看历史</span></div>
    <div class="kpi"><span class="lbl-cn">待关注</span><div class="big">{{ summary.attention }}</div><span class="sub">单设备拉取超过 {{ ATTENTION_THRESHOLD }} 次</span></div>
    <div class="kpi"><span class="lbl-cn">已封锁</span><div class="big">{{ summary.blocked }}</div><span class="sub">不会继续通过该记录访问</span></div>
  </section>

  <div class="filter-line device-filter-line">
    <div class="seg" role="group" aria-label="设备筛选">
      <button :aria-pressed="filter === 'recent'" @click="filter = 'recent'">近 30 天 <span>{{ summary.recent }}</span></button>
      <button :aria-pressed="filter === 'all'" @click="filter = 'all'">全部 <span>{{ summary.total }}</span></button>
      <button :aria-pressed="filter === 'attention'" @click="filter = 'attention'">待关注 <span>{{ summary.attention }}</span></button>
      <button :aria-pressed="filter === 'blocked'" @click="filter = 'blocked'">已封锁 <span>{{ summary.blocked }}</span></button>
    </div>
    <div class="device-list-controls">
      <span class="lbl-cn">当前 {{ filtered.length }} 条 · {{ groupedDevices.length }} 位用户</span>
      <button v-if="groupedDevices.length" class="b" type="button" @click="toggleAllGroups">{{ allGroupsExpanded ? "收起全部" : "展开当前结果" }}</button>
    </div>
  </div>

  <div v-if="loading" class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  <section v-else-if="error" class="state-wrap"><div class="st" role="alert"><b>设备加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div></section>
  <section v-else-if="!filtered.length" class="state-wrap"><div class="st"><b>没有匹配的设备</b><span>调整搜索词或筛选条件后再试。</span></div></section>

  <div v-else class="device-groups">
    <details v-for="group in groupedDevices" :key="group.key" class="device-user-group" :open="isGroupExpanded(group)" @toggle="setGroupExpanded(group, $event.target.open)">
      <summary class="device-user-summary">
        <div class="device-user-title"><strong>{{ group.uid }}</strong><span>{{ group.devices.length }} 条记录</span></div>
        <div class="device-user-stats">
          <span v-if="group.blockedCount" class="mk bad">封锁 {{ group.blockedCount }}</span>
          <span v-if="group.attentionCount" class="mk warn">待关注 {{ group.attentionCount }}</span>
          <span class="device-user-latest">最近 {{ timeAgo(group.latestSeen) }}</span>
        </div>
      </summary>
      <div class="device-record-list">
        <article v-for="device in group.devices" :key="device.id" class="device-record" :class="{ 'is-muted': device.blocked }">
          <div class="device-record-main">
            <span class="status-dot" :class="statusState(device).tone"></span>
            <div class="device-record-title"><h3>{{ device.label || `设备 #${device.id}` }}</h3><span>{{ identityState(device).text }} · {{ timeAgo(device.last_seen) }}</span></div>
          </div>
          <div class="device-record-side">
            <div class="device-record-meta">
              <span class="mk" :class="statusState(device).tone">{{ statusState(device).text }}</span>
              <span>{{ Number(device.fetch_count || 0).toLocaleString("zh-CN") }} 次拉取</span>
              <span v-if="device.last_ip">{{ device.last_ip }}</span>
            </div>
            <button class="b" type="button" @click="openDetail(device)">详情</button>
          </div>
        </article>
      </div>
    </details>
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
      <div class="device-detail-summary"><span class="mk" :class="statusState(detail).tone">{{ statusState(detail).text }}</span><span>{{ detail.friend_uid }}</span><span>最近访问 {{ timeAgo(detail.last_seen) }}</span></div>
      <div class="form-row"><label for="detail-label">设备备注</label><input id="detail-label" v-model="detailForm.label" placeholder="未命名"></div>
      <div class="check"><input id="detail-blocked" v-model="detailForm.blocked" type="checkbox"><label for="detail-blocked">封锁该访问记录</label></div>
      <details class="fold device-detail-fold">
        <summary>访问与客户端数据</summary>
        <div class="fold-body"><dl class="detail-list">
          <div class="detail-item"><dt>记录 ID</dt><dd class="mono">{{ detail.id }}</dd></div>
          <div class="detail-item"><dt>专属链接</dt><dd><span class="mk" :class="identityState(detail).tone">{{ identityState(detail).text }}</span></dd></div>
          <div class="detail-item"><dt>访问标识</dt><dd class="mono">{{ detail.access_identifier || "—" }} <button v-if="detail.access_identifier" class="b b-txt" @click="copyText(detail.access_identifier, '访问标识')">复制</button></dd></div>
          <div class="detail-item"><dt>完整 User-Agent</dt><dd class="mono">{{ detail.user_agent || "—" }}</dd></div>
          <div class="detail-item"><dt>最近 IP</dt><dd class="mono">{{ detail.last_ip || "—" }}</dd></div>
          <div class="detail-item"><dt>首次访问</dt><dd>{{ timeAgo(detail.first_seen) }}</dd></div>
          <div class="detail-item"><dt>拉取次数</dt><dd class="mono">{{ Number(detail.fetch_count || 0).toLocaleString("zh-CN") }}</dd></div>
        </dl></div>
      </details>
      <details class="fold device-actions-fold">
        <summary>链接管理与删除</summary>
        <div class="fold-body">
          <p class="form-hint">轮换或撤销会立即影响设备专属链接；删除会移除这条访问记录。</p>
          <div class="device-admin-actions"><button class="b" :disabled="detailBusy" @click="rotateLink">{{ detail.identity_source === 'device_link' ? '轮换专属链接' : '原名额转专属链接' }}</button><button v-if="detail.device_link_active" class="b b-bad" :disabled="detailBusy" @click="revokeLink">撤销链接</button><button class="b b-bad" :disabled="detailBusy" @click="removeDevice">删除访问记录</button></div>
        </div>
      </details>
      <div class="modal-foot">
        <button class="b" @click="detail = null">取消</button><button class="b b-am" :disabled="detailBusy" @click="saveDetail">{{ detailBusy ? "保存中…" : "保存" }}</button>
      </div>
    </template>
  </Modal>
</template>
