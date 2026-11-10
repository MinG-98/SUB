import { createRouter, createWebHashHistory } from "vue-router";
import { auth } from "./store.js";
import { api } from "./api.js";
import LoginView from "./views/LoginView.vue";
import OverviewView from "./views/OverviewView.vue";
import NodesView from "./views/NodesView.vue";
import UsersView from "./views/UsersView.vue";
import DevicesView from "./views/DevicesView.vue";

const routes = [
  { path: "/", redirect: "/overview" },
  { path: "/login", name: "login", component: LoginView, meta: { public: true } },
  { path: "/overview", name: "overview", component: OverviewView },
  { path: "/nodes", name: "nodes", component: NodesView },
  { path: "/users", name: "users", component: UsersView },
  { path: "/devices", name: "devices", component: DevicesView },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

router.beforeEach(async (to) => {
  if (!auth.checked) {
    try {
      const res = await api.me();
      auth.authenticated = !!res.authenticated;
      auth.username = res.username || "";
      auth.role = res.role || "";
    } catch {
      auth.authenticated = false;
      auth.username = "";
      auth.role = "";
    }
    auth.checked = true;
  }
  if (!to.meta.public && !auth.authenticated) {
    return { name: "login", query: { redirect: to.fullPath } };
  }
  if (to.meta.public && auth.authenticated) {
    return { name: "overview" };
  }
  return true;
});
