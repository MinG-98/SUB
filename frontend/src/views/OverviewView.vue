<script setup>
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";
import { formatBytes, formatLatency, formatPercent, timeAgo } from "../format.js";
import { pushToast } from "../store.js";
import Modal from "../components/Modal.vue";
import { activityByUser, healthRows, probeState, summarizeProbe } from "../noc/data.js";

const router = useRouter();
const loading = ref(true);
const error = ref("");
const stats = ref({});
const nodes = ref([]);
const announcements = ref([]);
const latency = ref({});
const devices = ref([]);
const collector = ref({});
const range = ref("24h");
const probing = ref(false);

function probeTone(ok, total) {
  if (ok == null || total == null || total === 0) return "warn";
  if (ok === total) return "ok";
  return ok > 0 ? "warn" : "bad";
}

function probeAgeText(probe) {
  if (probe.running) return "探测正在运行";
  if (probe.stale) return "结果陈旧 · " + timeAgo(latency.value.finished_at);
  return "暂无有效探测结果";
}

const showAnnouncement = ref(false);
const editingAnnouncement = ref(null);
const announcementForm = ref({ name: "", enabled: true });
const announcementBusy = ref(false);
const announcementError = ref("");

function byteParts(value) {
  const [num, unit = "B"] = formatBytes(value).split(" ");
  return { num, unit };
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [s, n, a, l, d, c] = await Promise.all([
      api.stats(), api.nodes(), api.announcements(), api.latencyStatus(), api.devices(), api.collectorStatus(),
    ]);
    stats.value = s || {};
    nodes.value = n || [];
    announcements.value = a || [];
    latency.value = l || {};
    devices.value = d || [];
    collector.value = c || {};
  } catch (e) {
    error.value = e.message || "概览数据加载失败";
  } finally {
    loading.value = false;
  }
}

const kpis = computed(() => {
  const real = nodes.value;
  const enabled = real.filter((node) => node.enabled);
  const monitor = enabled.filter((node) => node.collector?.online === true).length;
  const stale = enabled.filter((node) => node.collector?.stale || node.collector?.online == null).length;
  const probe = summarizeProbe(latency.value);
  const traffic = byteParts(stats.value.flow_24h_bytes);
  const monitorState = monitor === enabled.length && enabled.length
    ? "ok"
    : stale || monitor
      ? "warn"
      : enabled.length
        ? "bad"
        : "";
  return [
    { label: "真实节点", value: real.length, sub: `${announcements.value.length} 条公告不计入` },
    { label: "监控在线 / 启用", value: `${monitor} / ${enabled.length}`, state: monitorState, sub: `${formatPercent(enabled.length ? (monitor / enabled.length) * 100 : 0)} · ${stale} 个陈旧/未知 · 仅代表心跳` },
    {
      label: "入口可达",
      value: probe.entryOk == null ? "—" : `${probe.entryOk}/${probe.entryTotal}`,
      state: probeTone(probe.entryOk, probe.entryTotal),
      sub: !probe.fresh ? probeAgeText(probe) : probe.entryTotal ? "协议入口探测" : "没有可测试的启用节点",
    },
    {
      label: "代理出口",
      value: probe.proxyOk == null ? "—" : `${probe.proxyOk}/${probe.proxyTotal}`,
      state: probeTone(probe.proxyOk, probe.proxyTotal),
      sub: !probe.fresh ? probeAgeText(probe) : probe.proxyTotal ? "完整代理链路" : "没有可测试的启用节点",
    },
    { label: "用户数", value: stats.value.friends || 0, sub: "订阅账户" },
    { label: "24h 流量", value: traffic.num, unit: traffic.unit, sub: "代理出网" },
    { label: "24h 拉取", value: Number(stats.value.fetch_24h || 0).toLocaleString("zh-CN"), sub: "订阅请求次数" },
  ];
});

const traffic = computed(() => {
  const key = range.value === "all" ? "30d" : range.value;
  const rows = nodes.value.map((node) => ({
    id: node.id,
    name: node.name,
    bytes: node.traffic?.[key]?.total ?? null,
    off: !node.enabled,
  })).sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
  const shown = rows.slice(0, 5);
  const max = Math.max(1, ...shown.map((row) => row.bytes || 0));
  return {
    rows,
    shown: shown.map((row) => ({ ...row, pct: Math.max(1.5, ((row.bytes || 0) / max) * 100) })),
  };
});

const activity = computed(() => {
  const rows = activityByUser(devices.value).slice(0, 5);
  const max = Math.max(1, ...rows.map((row) => row.fetches));
  return rows.map((row) => ({ ...row, pct: Math.max(1.5, (row.fetches / max) * 100) }));
});

function meter(label, ms, okCount, total, fresh = true) {
  const has = ms != null;
  return {
    label,
    ms,
    text: formatLatency(has ? ms : null),
    pct: has ? Math.min(100, (ms / 400) * 100) : 0,
    tone: !fresh || total === 0 ? "warn" : !has ? "bad" : ms < 150 ? "ok" : ms < 400 ? "warn" : "bad",
    reachability: total == null ? "" : total === 0 ? "没有可测试节点" : `可达 ${okCount || 0}/${total}`,
  };
}

const probe = computed(() => {
  const summary = latency.value.summary || {};
  const health = summarizeProbe(latency.value);
  return {
    meters: [
      meter("控制面", health.fresh && latency.value.control?.state === "ok" ? latency.value.control.ms : null, null, null, health.fresh),
      meter("节点入口", health.fresh ? summary.entry_avg_ms : null, health.entryOk, health.entryTotal, health.fresh),
      meter("代理出口", health.fresh ? summary.proxy_avg_ms : null, health.proxyOk, health.proxyTotal, health.fresh),
    ],
    nodes: (latency.value.nodes || []).map((node) => {
      const state = probeState(node);
      return {
        ...node,
        state,
        tone: { connected: "ok", exit_fail: "warn", timeout: "warn", unreachable: "bad", waiting: "info", pending: "info", unsupported: "warn", untested: "idle" }[state.key] || "idle",
        ms: node.proxy?.ms ?? node.entry?.ms,
        reason: node.proxy?.reason || node.entry?.reason || "",
      };
    }),
  };
});

const health = computed(() => healthRows({ stats: stats.value, nodes: nodes.value, latency: latency.value, devices: devices.value, collector: collector.value }));
async function runProbe() {
  if (probing.value) return;
  probing.value = true;
  try {
    await api.triggerLatencyProbe();
    pushToast("已触发延迟探测", "success");
    window.setTimeout(load, 2500);
  } catch (e) {
    pushToast(e.message || "触发探测失败");
  } finally {
    probing.value = false;
  }
}

function openAnnouncement(node = null) {
  editingAnnouncement.value = node;
  announcementForm.value = { name: node?.name || "", enabled: node?.enabled ?? true };
  announcementError.value = "";
  showAnnouncement.value = true;
}

async function saveAnnouncement() {
  const name = announcementForm.value.name.trim();
  if (!name) {
    announcementError.value = "备注内容不能为空";
    return;
  }
  announcementBusy.value = true;
  announcementError.value = "";
  try {
    if (editingAnnouncement.value) {
      await api.updateAnnouncement(editingAnnouncement.value.id, { name, enabled: announcementForm.value.enabled });
    } else {
      await api.createAnnouncement({ name, enabled: announcementForm.value.enabled });
    }
    pushToast(editingAnnouncement.value ? "备注已更新" : "备注已创建", "success");
    showAnnouncement.value = false;
    await load();
  } catch (e) {
    announcementError.value = e.message || "保存失败";
  } finally {
    announcementBusy.value = false;
  }
}

async function toggleAnnouncement(node) {
  try {
    await api.updateAnnouncement(node.id, { enabled: !node.enabled });
    pushToast(node.enabled ? "已取消发布" : "已发布", "success");
    await load();
  } catch (e) {
    pushToast(e.message || "操作失败");
  }
}

async function removeAnnouncement() {
  const node = editingAnnouncement.value;
  if (!node || !window.confirm(`确定删除公告「${node.name}」？将从 ${node.allocated_to || 0} 个用户的后续订阅中移除。`)) return;
  announcementBusy.value = true;
  try {
    await api.deleteAnnouncement(node.id);
    pushToast("公告已删除", "success");
    showAnnouncement.value = false;
    await load();
  } catch (e) {
    announcementError.value = e.message || "删除失败";
  } finally {
    announcementBusy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <template v-if="loading">
    <div class="kpis">
      <div v-for="index in 5" :key="index" class="kpi">
        <div class="sk sk-title"></div><div class="sk sk-value"></div><div class="sk sk-sub"></div>
      </div>
    </div>
    <div class="loading-lines"><div v-for="index in 8" :key="index" class="sk sk-line"></div></div>
  </template>

  <section v-else-if="error" class="state-wrap">
    <div class="st" role="alert"><b>概览数据加载失败</b><span>{{ error }}</span><button class="b b-am" @click="load">重试</button></div>
  </section>

  <template v-else>
    <div class="kpis">
      <div v-for="item in kpis" :key="item.label" class="kpi">
        <span class="lbl-cn">{{ item.label }}</span>
        <div class="big">{{ item.value }}<u v-if="item.unit">{{ item.unit }}</u></div>
        <span v-if="item.state" class="mk" :class="item.state">{{ item.sub }}</span>
        <span v-else class="sub">{{ item.sub }}</span>
      </div>
    </div>

    <div class="grid">
      <section class="p c7" aria-labelledby="h-traffic">
        <div class="p-hd">
          <h2 id="h-traffic">节点流量</h2>
          <div class="seg" role="group" aria-label="时间范围">
            <button v-for="item in ['24h','7d','30d','all']" :key="item" :aria-pressed="range === item" @click="range = item">{{ item === "all" ? "全部" : item }}</button>
          </div>
        </div>
        <div v-if="traffic.shown.length" class="rows">
          <div v-for="row in traffic.shown" :key="row.id" class="row">
            <div class="row-nm">{{ row.name }}</div><div class="row-vl">{{ row.bytes == null ? "无数据" : formatBytes(row.bytes) }}</div>
            <div class="row-bar"><div class="bar"><i :style="{ '--meter': `${row.pct}%` }"></i></div></div>
            <div v-if="row.off" class="row-sub"><span class="mk idle">已停用</span></div>
          </div>
        </div>
        <div v-else class="st"><b>暂无流量数据</b><span>还没有节点上报统计。</span></div>
        <div class="p-ft"><template v-if="range === 'all'">「全部」区间当前显示 30d 数据。</template>共 {{ traffic.rows.length }} 个节点，已显示流量最高的前 {{ traffic.shown.length }} 个 · <a href="#" @click.prevent="router.push({name:'nodes'})">查看节点 →</a></div>
      </section>

      <section class="p c5" aria-labelledby="h-activity">
        <div class="p-hd"><h2 id="h-activity">用户拉取活跃度</h2><span class="lbl">拉取次数</span></div>
        <div v-if="activity.length" class="rows">
          <div v-for="row in activity" :key="row.uid" class="row">
            <div class="row-nm">{{ row.uid }}</div><div class="row-vl">{{ row.fetches.toLocaleString("zh-CN") }} 次</div>
            <div class="row-bar"><div class="bar"><i class="info" :style="{ '--meter': `${row.pct}%` }"></i></div></div>
            <div class="row-sub"><span>{{ row.devices }} 台设备</span></div>
          </div>
        </div>
        <div v-else class="st"><b>暂无拉取记录</b><span>还没有客户端拉取过订阅。</span></div>
        <div class="p-ft">统计订阅链接被客户端拉取的次数，按设备归属用户聚合 —— 与代理流量无关。</div>
      </section>

      <section class="p c6" aria-labelledby="h-probe">
        <div class="p-hd"><h2 id="h-probe">延迟探针</h2><button class="b b-am" :disabled="probing" @click="runProbe">{{ probing ? "探测中…" : "手动探测" }}</button></div>
        <div>
          <div v-for="item in probe.meters" :key="item.label" class="mtr">
            <div class="mtr-nm">{{ item.label }}</div><div class="bar"><i :class="item.tone" :style="{ '--meter': `${item.pct}%` }"></i></div><div class="mtr-vl">{{ item.text }}</div>
            <div v-if="item.reachability" class="mtr-sub">{{ item.reachability }}</div>
          </div>
          <div class="lbl-cn">最近探测 {{ timeAgo(latency.finished_at) }}<span v-if="latency.target?.url" class="n"> · {{ latency.target.url.replace(/^https?:\/\//, "") }}</span></div>
        </div>
        <details class="probe-detail">
          <summary>逐节点结果 <span class="n">{{ probe.nodes.length }}</span></summary>
          <div class="probe-detail-body">
            <div v-for="node in probe.nodes" :key="node.node_id" class="led">
              <div class="row-nm">{{ node.name || `节点 #${node.node_id}` }}</div><span class="mk" :class="node.tone">{{ node.state.text }}</span>
              <div class="led-meta"><span class="n">{{ node.protocol || "—" }}</span><em>{{ node.ms != null ? `${node.ms}ms` : "—" }}</em><span>{{ node.credential_source?.startsWith("user:") ? `用户级 ${node.credential_source.slice(5)}` : "共享凭据" }}</span><span>{{ timeAgo(node.checked_at) }}</span><span v-if="node.reason">{{ node.reason }}</span></div>
            </div>
            <div v-if="!probe.nodes.length" class="st"><b>尚未探测</b><span>点击「手动探测」开始第一次测试。</span></div>
          </div>
        </details>
        <div class="p-ft">入口探测验证节点入口可达性（VLESS 为 TCP，Hysteria2 为协议握手）；出口探测走完整代理链路访问外部目标。两者结果可以不一致。</div>
      </section>

      <section class="p c6" aria-labelledby="h-ann">
        <div class="p-hd"><h2 id="h-ann">备注节点</h2><button class="b" @click="openAnnouncement()">新增</button></div>
        <div v-if="announcements.length">
          <div v-for="node in announcements" :key="node.id" class="ann">
            <div class="ann-ic">{{ node.enabled ? "◆" : "◇" }}</div><div class="ann-nm">{{ node.name }}</div><span class="lbl-cn">{{ node.allocated_to || 0 }} 用户</span><span class="mk" :class="node.enabled ? 'ok' : 'idle'">{{ node.enabled ? "已发布" : "草稿" }}</span>
            <div class="ann-ac"><button class="b" @click="openAnnouncement(node)">编辑</button><button class="b" @click="toggleAnnouncement(node)">{{ node.enabled ? "取消发布" : "发布" }}</button></div>
          </div>
        </div>
        <div v-else class="st"><b>还没有备注节点</b><span>备注用于给订阅客户端显示提示文字。</span><button class="b" @click="openAnnouncement()">新增备注</button></div>
        <div class="p-ft">备注节点用于向订阅客户端推送提示文字，不参与真实代理连接、节点状态与流量统计。</div>
      </section>

      <section class="p c12 health-panel" aria-labelledby="h-health">
        <div class="p-hd"><h2 id="h-health">系统健康</h2></div>
        <div class="health-list">
          <div v-for="row in health" :key="row.name" class="led">
            <div class="row-nm">{{ row.name }}</div><span class="mk" :class="row.tone === 'is-ok' ? 'ok' : row.tone === 'is-bad' ? 'bad' : 'idle'">{{ row.text }}</span>
            <div class="led-meta"><span>{{ row.detail || "—" }}</span><span>{{ timeAgo(row.at) }}</span></div>
          </div>
        </div>
      </section>

    </div>
  </template>

  <Modal v-if="showAnnouncement" :title="editingAnnouncement ? '编辑备注节点' : '新增备注节点'" @close="showAnnouncement = false">
    <p v-if="announcementError" class="form-error" role="alert">{{ announcementError }}</p>
    <div class="form-row"><label for="announcement-name">订阅中显示的提示文字</label><input id="announcement-name" v-model="announcementForm.name" maxlength="160" placeholder="例如：⚠️ 使用前请更新订阅"></div>
    <div class="check"><input id="announcement-enabled" v-model="announcementForm.enabled" type="checkbox"><label for="announcement-enabled">立即发布到已分配该备注的用户订阅</label></div>
    <div class="modal-foot between">
      <button v-if="editingAnnouncement" class="b b-bad" :disabled="announcementBusy" @click="removeAnnouncement">删除这条备注</button><span v-else></span>
      <div class="modal-foot-group"><button class="b" @click="showAnnouncement = false">取消</button><button class="b b-am" :disabled="announcementBusy" @click="saveAnnouncement">{{ announcementBusy ? "保存中…" : "保存" }}</button></div>
    </div>
  </Modal>
</template>
