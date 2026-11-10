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
    const result = await api.login(password.value);
    auth.authenticated = true;
    auth.checked = true;
    auth.username = result?.username || "";
    auth.role = result?.role || "";
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
    <form class="login-card" @submit.prevent="submit">
      <div class="login-brand"><b>SUBAPP</b><span>运维控制台</span></div>
      <span class="lbl lbl-am">管理员登录</span>
      <h1 class="login-title">节点订阅管理</h1>
      <p class="login-lede">管理节点、用户、设备与流量状态。</p>
      <label class="field-label" for="pw">管理员密码</label>
      <input id="pw" v-model="password" class="field-input" type="password" autocomplete="current-password" placeholder="请输入管理员密码" autofocus>
      <p v-if="error" class="login-error" role="alert">{{ error }}</p>
      <button class="login-submit" type="submit" :disabled="submitting">{{ submitting ? "验证中…" : "进入控制台 →" }}</button>
    </form>
  </main>
</template>
