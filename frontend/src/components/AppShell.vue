<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "../api.js";
import { isRealNode, summarizeProbe } from "../noc/data.js";
import { auth } from "../store.js";

const route = useRoute();
const router = useRouter();
const navItems = [
  { name: "overview", label: "概览", title: "概览", icon: "overview" },
  { name: "nodes", label: "节点", title: "节点", icon: "nodes" },
  { name: "users", label: "用户", title: "用户", icon: "users" },
  { name: "devices", label: "设备", title: "设备", icon: "devices" },
];
const current = computed(() => navItems.find((item) => item.name === route.name)?.title || "控制台");
const signal = ref({ monitor: null, entry: null, proxy: null, total: null, entryTotal: null, proxyTotal: null, probeAt: null, probeFresh: false, syncError: false });
const probeLabel = computed(() => {
  if (signal.value.syncError) return "同步失败";
  if (!signal.value.probeAt) return "探针未完成";
  const time = new Date(signal.value.probeAt).toLocaleTimeString("zh-CN", { hour12: false });
  return (signal.value.probeFresh ? "探针 " : "探针陈旧 ") + time;
});
let timer;

async function refreshSignal() {
  try {
    const [nodeRows, latency] = await Promise.all([api.nodes(), api.latencyStatus()]);
    const nodes = (nodeRows || []).filter(isRealNode);
    const enabled = nodes.filter((node) => node.enabled);
    const probe = summarizeProbe(latency);
    signal.value = {
      monitor: enabled.filter((node) => node.collector?.online === true).length,
      entry: probe.entryOk,
      proxy: probe.proxyOk,
      total: enabled.length,
      entryTotal: probe.entryTotal,
      proxyTotal: probe.proxyTotal,
      probeAt: latency?.finished_at || null,
      probeFresh: probe.fresh,
      syncError: false,
    };
  } catch {
    signal.value = { monitor: null, entry: null, proxy: null, total: null, entryTotal: null, proxyTotal: null, probeAt: null, probeFresh: false, syncError: true };
  }
}

async function logout() {
  try {
    await api.logout();
  } finally {
    auth.authenticated = false;
    auth.username = "";
    auth.role = "";
    router.push({ name: "login" });
  }
}

onMounted(() => {
  refreshSignal();
  timer = window.setInterval(refreshSignal, 30000);
});
onUnmounted(() => window.clearInterval(timer));
</script>

<template>
  <div class="shell">
    <aside class="rail">
      <div class="brand"><b>SUBAPP</b><span>运维控制台</span></div>
      <nav aria-label="主导航">
        <router-link
          v-for="item in navItems"
          :key="item.name"
          :to="{ name: item.name }"
          :aria-current="route.name === item.name ? 'page' : undefined"
        >
          <svg v-if="item.icon === 'overview'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="1.5" y="1.5" width="5" height="5"/><rect x="9.5" y="1.5" width="5" height="5"/><rect x="1.5" y="9.5" width="5" height="5"/><rect x="9.5" y="9.5" width="5" height="5"/></svg>
          <svg v-else-if="item.icon === 'nodes'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="1.5" y="2.5" width="13" height="4.5"/><rect x="1.5" y="9" width="13" height="4.5"/></svg>
          <svg v-else-if="item.icon === 'users'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><circle cx="8" cy="5.5" r="2.6"/><path d="M2.6 14c0-2.8 2.4-4.4 5.4-4.4s5.4 1.6 5.4 4.4"/></svg>
          <svg v-else viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="3.5" y="1.5" width="9" height="13"/><line x1="6.5" y1="12" x2="9.5" y2="12"/></svg>
          {{ item.label }}
        </router-link>
      </nav>
      <div class="rail-ft">
        <span class="mk info">监控 {{ signal.monitor == null ? "—" : `${signal.monitor}/${signal.total}` }}</span>
        <span class="lbl-cn">入口 {{ signal.entry == null ? "—" : `${signal.entry}/${signal.entryTotal}` }} · 出口 {{ signal.proxy == null ? "—" : `${signal.proxy}/${signal.proxyTotal}` }}</span>
        <button class="b b-txt" @click="logout">退出登录</button>
      </div>
    </aside>

    <main class="main">
      <header class="top">
        <h1><span class="tick">▍</span>{{ current }}</h1>
        <div class="top-actions">
          <span class="lbl">{{ auth.username || "管理员" }} · {{ probeLabel }}</span>
          <button class="b" aria-label="刷新节点信号" @click="refreshSignal">刷新</button>
        </div>
      </header>
      <div class="page"><slot /></div>
    </main>

    <nav class="mnav" aria-label="主导航">
      <router-link
        v-for="item in navItems"
        :key="item.name"
        :to="{ name: item.name }"
        :aria-current="route.name === item.name ? 'page' : undefined"
      >
        <svg v-if="item.icon === 'overview'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="1.5" y="1.5" width="5" height="5"/><rect x="9.5" y="1.5" width="5" height="5"/><rect x="1.5" y="9.5" width="5" height="5"/><rect x="9.5" y="9.5" width="5" height="5"/></svg>
        <svg v-else-if="item.icon === 'nodes'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="1.5" y="2.5" width="13" height="4.5"/><rect x="1.5" y="9" width="13" height="4.5"/></svg>
        <svg v-else-if="item.icon === 'users'" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><circle cx="8" cy="5.5" r="2.6"/><path d="M2.6 14c0-2.8 2.4-4.4 5.4-4.4s5.4 1.6 5.4 4.4"/></svg>
        <svg v-else viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true"><rect x="3.5" y="1.5" width="9" height="13"/><line x1="6.5" y1="12" x2="9.5" y2="12"/></svg>
        {{ item.label }}
      </router-link>
    </nav>
  </div>
</template>
