<script setup>
import { ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "../api.js";
import { auth } from "../store.js";

const password = ref("");
const error = ref("");
const submitting = ref(false);
const router = useRouter();
const route = useRoute();

async function submit() {
  if (!password.value || submitting.value) return;
  submitting.value = true;
  error.value = "";
  try {
    await api.login(password.value);
    auth.authenticated = true;
    auth.checked = true;
    const redirect = route.query.redirect;
    await router.push(typeof redirect === "string" ? redirect : { name: "overview" });
  } catch (e) {
    error.value = e.message || "登录失败";
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <main class="login-screen">
    <section class="login-card">
      <div class="login-brand"><b>SUB</b></div>

      <form class="login-form" @submit.prevent="submit">
        <span class="lbl lbl-am">Operator access</span>
        <h1 class="login-title">节点订阅管理</h1>
        <p class="login-lede">集中维护代理节点、按用户分配订阅、采集节点状态与流量。</p>
        <div class="login-rule"></div>
        <label class="field-label" for="pw">管理员密码</label>
        <input id="pw" v-model="password" class="field-input" type="password" autocomplete="current-password" placeholder="请输入管理员密码" autofocus>
        <p v-if="error" class="login-error" role="alert">{{ error }}</p>
        <button class="login-submit b-am" type="submit" :disabled="submitting">{{ submitting ? "验证中…" : "进入控制台 →" }}</button>
        <p class="login-note">线上实例仅限管理员访问。</p>
      </form>

      <div class="login-meta"><span>FastAPI</span><span>Vue 3</span><span>SQLite</span></div>
    </section>

    <aside class="login-aside">
      <span class="login-aside-kicker">Subscription control plane</span>
      <div class="login-aside-title">VLESS · VMess<br>Trojan · Hysteria2<br>Shadowsocks</div>
      <div class="login-aside-rule"></div>
      <div class="login-aside-copy">订阅输出 V2Ray / Base64 / Clash / Mihomo 兼容格式。</div>
    </aside>
  </main>
</template>
