class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    ...options,
  });
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const message = (data && data.detail) || res.statusText || "请求失败";
    throw new ApiError(message, res.status);
  }
  return data;
}

const get = (path) => request(path);
const post = (path, body) => request(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
const patch = (path, body) => request(path, { method: "PATCH", body: JSON.stringify(body) });
const del = (path) => request(path, { method: "DELETE" });

export const api = {
  ApiError,

  login: (password) => post("/api/admin/login", { password }),
  logout: () => post("/api/admin/logout"),
  me: () => get("/api/admin/me"),

  stats: () => get("/api/admin/stats"),
  topology: () => get("/api/admin/overview/topology"),
  collectorStatus: () => get("/api/admin/collector/status"),
  latencyStatus: () => get("/api/admin/latency"),
  triggerLatencyProbe: () => post("/api/admin/latency/probe"),

  nodes: () => get("/api/admin/nodes"),
  announcements: () => get("/api/admin/announcements"),
  nodeTraffic: (id, range = "24h") => get(`/api/admin/nodes/${id}/traffic?range=${range}`),
  createNodes: (payload) => post("/api/admin/nodes", payload),
  createAnnouncement: (payload) => post("/api/admin/announcements", payload),
  updateNode: (id, payload) => patch(`/api/admin/nodes/${id}`, payload),
  updateAnnouncement: (id, payload) => patch(`/api/admin/announcements/${id}`, payload),
  deleteNode: (id) => del(`/api/admin/nodes/${id}`),
  deleteAnnouncement: (id) => del(`/api/admin/announcements/${id}`),
  prepareNodeCredentials: (id) => post(`/api/admin/nodes/${id}/per-user/prepare`),
  registerAgent: (nodeId) => post("/api/admin/agents", { node_id: nodeId }),
  rotateAgentToken: (nodeId) => post(`/api/admin/agents/${nodeId}/rotate`),
  confirmAgentTokenRotation: (nodeId) => post(`/api/admin/agents/${nodeId}/rotate/confirm`),
  cancelAgentTokenRotation: (nodeId) => del(`/api/admin/agents/${nodeId}/rotate`),

  friends: () => get("/api/admin/friends"),
  createFriend: (payload) => post("/api/admin/friends", payload),
  updateFriend: (id, payload) => patch(`/api/admin/friends/${id}`, payload),
  deleteFriend: (id) => del(`/api/admin/friends/${id}`),
  friendTraffic: (id, range = "24h") => get(`/api/admin/friends/${id}/traffic?range=${range}`),
  friendCredentials: (id) => get(`/api/admin/friends/${id}/credentials`),
  prepareDeviceCredentials: (id) => post(`/api/admin/friends/${id}/device-credentials/prepare`),
  activateDeviceCredentials: (id) => post(`/api/admin/friends/${id}/device-credentials/activate`),
  restoreCompatibleCredentials: (id) => post(`/api/admin/friends/${id}/device-credentials/restore`),
  friendSubscriptionDiagnostics: (id, target = "shadowrocket", deviceId = null) => {
    const query = new URLSearchParams({ target });
    if (deviceId !== null && deviceId !== undefined && deviceId !== "") query.set("device_id", deviceId);
    return get(`/api/admin/friends/${encodeURIComponent(id)}/subscription-diagnostics?${query}`);
  },

  syncCredential: (id) => post(`/api/admin/credentials/${id}/sync`),
  rotateCredential: (id) => post(`/api/admin/credentials/${id}/rotate`),
  revokeCredential: (id) => post(`/api/admin/credentials/${id}/revoke`),

  devices: () => get("/api/admin/devices"),
  createDeviceLink: (friendId, label) => post(`/api/admin/friends/${friendId}/devices`, { label }),
  rotateDeviceLink: (id) => post(`/api/admin/devices/${id}/rotate-link`),
  revokeDeviceLink: (id) => post(`/api/admin/devices/${id}/revoke-link`),
  updateDevice: (id, payload) => patch(`/api/admin/devices/${id}`, payload),
  deleteDevice: (id) => del(`/api/admin/devices/${id}`),
};
