const BASE = "/api";
async function req(path, opts) {
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`${res.status}: ${err}`);
  }
  return res.json();
}
const api = {
  traffic: {
    list: (p) => req("/traffic?" + new URLSearchParams(p ?? {})),
    get: (id) => req(`/traffic/${id}`),
    summary: () => req("/traffic/stats/summary"),
    clear: () => req("/traffic", { method: "DELETE" })
  },
  findings: {
    list: (p) => req("/findings?" + new URLSearchParams(p ?? {})),
    byRule: () => req("/findings/stats/by-rule"),
    suppressBreakdown: () => req("/findings/stats/suppress-breakdown")
  },
  pipeline: {
    stats: () => req("/pipeline/stats"),
    snapshots: (range_h = 1) => req(`/pipeline/snapshots?range_h=${range_h}`)
  },
  control: {
    get: () => req("/control"),
    put: (body) => req("/control", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
  },
  process: {
    list: () => req("/process"),
    start: (name) => req(`/process/${name}/start`, { method: "POST" }),
    stop: (name) => req(`/process/${name}/stop`, { method: "POST" })
  },
  audit: {
    list: (p) => req("/audit?" + new URLSearchParams(p ?? {})),
    migrateJsonl: () => req("/audit/migrate-jsonl", { method: "POST" }),
    exportCsv: async () => {
      const res = await fetch(BASE + "/audit/export/csv");
      if (!res.ok) throw new Error(`${res.status}`);
      return res.blob();
    }
  },
  logs: {
    list: (p) => req("/logs?" + new URLSearchParams(p ?? {})),
    clear: () => req("/logs", { method: "DELETE" })
  },
  rules: {
    list: () => req("/rules"),
    create: (body) => req("/rules", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    update: (name, body) => req(`/rules/${name}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    delete: (name) => fetch(BASE + `/rules/${name}`, { method: "DELETE" }),
    toggle: (name) => req(`/rules/${name}/toggle`, { method: "PATCH" })
  },
  assets: {
    list: () => req("/assets"),
    create: (body) => req("/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    update: (id, body) => req(`/assets/${id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    delete: (id) => fetch(BASE + `/assets/${id}`, { method: "DELETE" }),
    resetDefaults: () => req("/assets/reset-defaults", { method: "POST" })
  },
  allowlist: {
    list: (p) => req("/allowlist?" + new URLSearchParams(p ?? {})),
    add: (body) => req("/allowlist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    remove: (idx) => fetch(BASE + `/allowlist/${idx}`, { method: "DELETE" }),
    purgeExpired: () => req("/allowlist/purge-expired", { method: "DELETE" })
  },
  health: () => req("/health")
};
export {
  api as a
};
