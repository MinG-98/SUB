export function healthRows(d) {
  const c = d.collector || {};
  const agentNodes = (d.latency?.nodes || []).filter((n) => (n.entry?.state || "") === "waiting_agent").length;
  const row = (name, ok, detail, at, text) => ({
    name,
    tone: ok === null ? "" : ok ? "is-ok" : "is-bad",
    text: text || (ok === null ? "未知" : ok ? "正常" : "异常"),
    detail,
    at,
  });
  const collectorStatus = String(c.status || "").toLowerCase();
  const collectorAt = c.finished_at || c.started_at || c.last_success_at;
  const hasCollectorCounts = Number.isFinite(Number(c.nodes_total)) && Number.isFinite(Number(c.samples_written));
  const collectorCounts = hasCollectorCounts ? `已写入 ${Number(c.samples_written)}/${Number(c.nodes_total)} 个采样` : "";
  const ageText = (status) => {
    const age = Number(status?.age_seconds);
    if (!Number.isFinite(age) || age < 0) return "时间未知";
    if (age < 3600) return `${Math.floor(age / 60)} 分钟前`;
    return `${Math.floor(age / 3600)} 小时前`;
  };
  let collectorRow;

  if (c.stale === true && collectorStatus !== "never_run") {
    collectorRow = {
      ...row("哪吒采集", null, `最近一次记录 ${ageText(c)}`, collectorAt, "陈旧"),
      tone: "is-warn",
    };
  } else switch (collectorStatus) {
    case "success":
      collectorRow = row("哪吒采集", true, collectorCounts || "采集成功", collectorAt, "正常");
      break;
    case "partial":
      collectorRow = row("哪吒采集", false, c.error || collectorCounts || "部分节点采集失败", collectorAt, "部分成功");
      break;
    case "running":
      collectorRow = row("哪吒采集", null, collectorCounts || "采集任务运行中", collectorAt, "采集中");
      break;
    case "never_run":
      collectorRow = row(
        "哪吒采集",
        null,
        c.configured === true ? "已配置，等待首次采集" : "未配置哪吒采集凭据",
        collectorAt,
        "未运行",
      );
      break;
    case "unconfigured":
      collectorRow = row("哪吒采集", null, c.error || "未配置哪吒采集凭据", collectorAt, "未配置");
      break;
    case "error":
      collectorRow = row("哪吒采集", false, c.error || "采集失败", collectorAt, "异常");
      break;
    default:
      collectorRow = row("哪吒采集", null, "采集状态不可识别", collectorAt, "未知");
  }
  const proxyStatus = c.proxy || {};
  const proxyRow = proxyStatus.status === "never_run"
    ? row("代理统计", null, "尚无运行记录", null, "未运行")
    : proxyStatus.stale === true
    ? { ...row("代理统计", null, `最近一次记录 ${ageText(proxyStatus)}`, proxyStatus.at, "陈旧"), tone: "is-warn" }
    : row("代理统计", proxyStatus.status ? proxyStatus.status === "success" : null, proxyStatus.reason || "流量计数来源", proxyStatus.at);
  const reconciler = c.reconciler || {};
  const reconcilerRow = reconciler.status === "never_run"
    ? row("凭据协调器", null, "尚无运行记录", null, "未运行")
    : reconciler.stale === true
    ? { ...row("凭据协调器", null, `最近一次记录 ${ageText(reconciler)}`, reconciler.at, "陈旧"), tone: "is-warn" }
    : row("凭据协调器", reconciler.status ? reconciler.status === "success" : null, reconciler.error || "用户凭据状态同步", reconciler.at);
  const sqliteNeedsVerification = c.sqlite_wal_reset_fix === "verify_backport";
  const databaseRow = sqliteNeedsVerification
    ? { ...row("数据库", null, `SQLite ${c.sqlite_version || "未知"}：需确认 WAL 修复回补`, null, "需核实版本"), tone: "is-warn" }
    : row("数据库", c.database === undefined ? true : !!c.database, `SQLite ${c.sqlite_version || "版本未知"} · 读写正常`, d.latency?.finished_at);
  return [
    row("应用服务", true, "控制面响应正常", d.latency?.finished_at),
    databaseRow,
    collectorRow,
    proxyRow,
    reconcilerRow,
    row(
      "远端 Agent",
      agentNodes ? false : true,
      agentNodes ? `${agentNodes} 个节点等待 Agent 上线` : "全部节点已上报",
      d.latency?.finished_at,
    ),
  ];
}

export function activityByUser(devices = []) {
  const map = new Map();
  for (const d of devices) {
    const k = d.friend_uid || "—";
    const cur = map.get(k) || { uid: k, fetches: 0, devices: 0 };
    cur.fetches += Number(d.fetch_count) || 0;
    cur.devices += 1;
    map.set(k, cur);
  }
  return [...map.values()].sort((a, b) => b.fetches - a.fetches);
}

export const isAnnouncement = (n) => {
  return Boolean(n?.is_announcement);
};
export const isRealNode = (n) => !isAnnouncement(n);

const PROBE_MAX_AGE_MS = 15 * 60 * 1000;

export function summarizeProbe(latency = {}, now = Date.now()) {
  const summary = latency?.summary || {};
  const nodesTotal = summary.nodes_total;
  const entryTotal = summary.entry_total ?? nodesTotal;
  const proxyTotal = summary.proxy_total ?? nodesTotal;
  const entryOk = summary.entry_ok;
  const proxyOk = summary.proxy_ok;
  const finishedAt = Date.parse(latency?.finished_at || "");
  const ageMs = now - finishedAt;
  const completed = latency?.status === "success" || latency?.status === "partial";
  const validCount = (value) => Number.isSafeInteger(value) && value >= 0;
  const countsValid =
    validCount(nodesTotal) &&
    validCount(entryTotal) &&
    validCount(entryOk) &&
    validCount(proxyTotal) &&
    validCount(proxyOk) &&
    entryTotal <= nodesTotal &&
    proxyTotal <= nodesTotal &&
    entryOk <= entryTotal &&
    proxyOk <= proxyTotal;
  const fresh =
    completed &&
    Number.isFinite(finishedAt) &&
    ageMs >= 0 &&
    ageMs <= PROBE_MAX_AGE_MS &&
    countsValid;

  return {
    fresh,
    stale: completed && !fresh,
    running: latency?.status === "running",
    finishedAt: Number.isFinite(finishedAt) ? finishedAt : null,
    ageMs: Number.isFinite(ageMs) && ageMs >= 0 ? ageMs : null,
    nodesTotal: fresh ? nodesTotal : null,
    entryTotal: fresh ? entryTotal : null,
    entryOk: fresh && entryTotal > 0 ? entryOk : null,
    proxyTotal: fresh ? proxyTotal : null,
    proxyOk: fresh && proxyTotal > 0 ? proxyOk : null,
  };
}

export function nodeStatus(n) {
  if (!n.enabled) return { tone: "", text: "已停用" };
  const probe = n.probe || {};
  const entry = probe.entry || {};
  const proxy = probe.proxy || {};
  if (entry.state === "pending" || proxy.state === "pending") {
    return { key: "probe_pending", tone: "is-info", text: "探测中" };
  }
  if (entry.state === "waiting_agent" || proxy.state === "waiting_agent") {
    return { key: "waiting_agent", tone: "is-accent", text: "等待 Agent" };
  }
  if (entry.state === "unsupported" || proxy.state === "unsupported") {
    return { key: "probe_unavailable", tone: "is-warn", text: "探测器未就绪/不支持" };
  }
  if (proxy.state === "ok") {
    return { key: "proxy_ok", tone: "is-ok", text: "代理出口正常" };
  }
  if (entry.state === "ok") {
    return { key: "entry_ok", tone: "is-warn", text: "入口可达 · 出口失败" };
  }
  if (entry.state && entry.state !== "ok") {
    return { key: "entry_bad", tone: "is-bad", text: "入口不可达" };
  }
  if (!n.collector || !n.collector.mapped) return { tone: "", text: "未接入监控" };
  if (n.collector.stale || n.collector.online == null) {
    const seconds = Number(n.collector.collector_delay_seconds);
    const age = Number.isFinite(seconds)
      ? ` · ${Math.floor(seconds / 60)} 分钟前`
      : "";
    return { key: "monitor_stale", tone: "is-warn", text: `监控数据陈旧${age}` };
  }
  if (n.collector.online === true) return { key: "monitor_online", tone: "is-info", text: "监控在线 · 未探测" };
  return { key: "monitor_offline", tone: "is-warn", text: "监控中 · 离线" };
}

export function probeState(node) {
  const e = node.entry || {};
  const p = node.proxy || {};
  if (e.state === "pending" || p.state === "pending") return { key: "pending", tone: "is-info", text: "探测中" };
  if (e.state === "waiting_agent" || p.state === "waiting_agent") return { key: "waiting", tone: "is-accent", text: "等待 Agent" };
  if (!e.state && !p.state) return { key: "untested", tone: "", text: "尚未测试" };
  if (e.state === "unsupported" || p.state === "unsupported") return { key: "unsupported", tone: "is-warn", text: "探测器未就绪/不支持" };
  if (e.state === "ok" && p.state === "ok") return { key: "connected", tone: "is-ok", text: "已连接" };
  if (e.state === "ok" && p.state !== "ok") {
    if ((p.reason || p.value || "").includes("超时")) return { key: "timeout", tone: "is-warn", text: "出口探测超时" };
    return { key: "exit_fail", tone: "is-warn", text: "入口正常 · 出口失败" };
  }
  if (e.state !== "ok") return { key: "unreachable", tone: "is-bad", text: "入口不可达" };
  return { key: "untested", tone: "", text: "尚未测试" };
}
