<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "../api.js";
import { isRealNode } from "../noc/data.js";
import { auth, requestDataRefresh } from "../store.js";

const route = useRoute();
const router = useRouter();
const navItems = [
  { name: "overview", label: "概览", title: "Overview", icon: "overview" },
  { name: "nodes", label: "节点", title: "Nodes", icon: "nodes" },
  { name: "users", label: "用户", title: "Users", icon: "users" },
  { name: "devices", label: "设备", title: "Devices", icon: "devices" },
];
const current = computed(() => navItems.find((item) => item.name === route.name)?.title || "Console");
const nodesOnline = ref(0);
const nodesTotal = ref(0);
const lastSync = ref("");
const navCounts = ref({});
let timer;

async function refreshSignal(refreshPage = true) {
  if (refreshPage) requestDataRefresh();
  try {
    const [allNodes, stats] = await Promise.all([api.nodes(), api.stats()]);
    const nodes = (allNodes || []).filter(isRealNode);
    nodesTotal.value = nodes.length;
    nodesOnline.value = nodes.filter((node) => node.collector?.online).length;
    navCounts.value = {
      nodes: nodes.length,
      users: Number(stats?.friends || 0),
      devices: Number(stats?.devices || 0),
    };
    lastSync.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  } catch {
    lastSync.value = "同步失败";
  }
}

async function logout() {
  try {
    await api.logout();
  } finally {
    auth.authenticated = false;
    router.push({ name: "login" });
  }
}

onMounted(() => {
  refreshSignal(false);
  timer = window.setInterval(() => refreshSignal(), 30000);
});
onUnmounted(() => window.clearInterval(timer));
</script>

<template>
  <div class="shell">
    <aside class="rail">
      <div class="brand"><b>SA Console</b></div>
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
          <span class="nav-label">{{ item.label }}</span>
          <span v-if="item.name !== 'overview' && navCounts[item.name] != null" class="nav-count">{{ navCounts[item.name] }}</span>
        </router-link>
      </nav>
      <div class="rail-ft">
        <span class="mk" :class="nodesOnline === nodesTotal && nodesTotal ? 'ok' : nodesOnline ? 'warn' : 'bad'">{{ nodesOnline }}/{{ nodesTotal }} 节点在线</span>
        <button class="b b-txt" @click="logout">退出登录</button>
      </div>
    </aside>

    <main class="main">
      <header class="top">
        <h1><span class="tick">▍</span>{{ current }}</h1>
        <div class="top-actions">
          <span class="lbl">{{ lastSync || "—" }}</span>
          <button class="b" aria-label="刷新面板数据" @click="refreshSignal">刷新</button>
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
        <span class="nav-label">{{ item.label }}</span>
      </router-link>
    </nav>
  </div>
</template>
