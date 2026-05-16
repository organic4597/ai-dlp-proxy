/** REST API 클라이언트 헬퍼. */

const BASE = '/api';

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`${res.status}: ${err}`);
  }
  return res.json() as Promise<T>;
}

// ── 트래픽 ─────────────────────────────────────────────────────────────────
export const api = {
  traffic: {
    list: (p?: Record<string, string | number | boolean>) =>
      req<unknown[]>('/traffic?' + new URLSearchParams(p as Record<string,string> ?? {})),
    get:  (id: string) => req<unknown>(`/traffic/${id}`),
    summary: () => req<unknown>('/traffic/stats/summary'),
    clear: () => req<{ deleted_requests: number; deleted_findings: number }>('/traffic', { method: 'DELETE' }),
  },
  findings: {
    list:    (p?: Record<string, string | number | boolean>) =>
      req<unknown[]>('/findings?' + new URLSearchParams(p as Record<string,string> ?? {})),
    byRule:  () => req<unknown[]>('/findings/stats/by-rule'),
    suppressBreakdown: () => req<unknown[]>('/findings/stats/suppress-breakdown'),
  },
  pipeline: {
    stats:     () => req<unknown>('/pipeline/stats'),
    snapshots: (range_h = 1) => req<unknown[]>(`/pipeline/snapshots?range_h=${range_h}`),
    slmHealth: () => req<{ status: string; model?: string; device?: string; dtype?: string; error?: string; url?: string }>('/slm/health'),
  },
  control: {
    get: () => req<unknown>('/control'),
    put: (body: Record<string, unknown>) =>
      req<unknown>('/control', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  },
  process: {
    list:  () => req<unknown[]>('/process'),
    start: (name: string) => req<unknown>(`/process/${name}/start`, { method: 'POST' }),
    stop:  (name: string) => req<unknown>(`/process/${name}/stop`, { method: 'POST' }),
  },
  audit: {
    list:    (p?: Record<string, string | number | boolean>) =>
      req<unknown[]>('/audit?' + new URLSearchParams(p as Record<string,string> ?? {})),
    migrateJsonl: () => req<unknown>('/audit/migrate-jsonl', { method: 'POST' }),
    exportCsv:   async () => {
      const res = await fetch(BASE + '/audit/export/csv');
      if (!res.ok) throw new Error(`${res.status}`);
      return res.blob();
    },
  },
  logs: {
    list: (p?: Record<string, string | number>) =>
      req<unknown[]>('/logs?' + new URLSearchParams(p as Record<string,string> ?? {})),
    clear: () => req<{ deleted: number }>('/logs', { method: 'DELETE' }),
  },
  rules: {
    list:   () => req<{ builtin: unknown[]; custom: unknown[] }>('/rules'),
    create: (body: Record<string, unknown>) =>
      req<unknown>('/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    update: (name: string, body: Record<string, unknown>) =>
      req<unknown>(`/rules/${name}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    delete: (name: string) =>
      fetch(BASE + `/rules/${name}`, { method: 'DELETE' }),
    toggle: (name: string) =>
      req<{ name: string; enabled: boolean }>(`/rules/${name}/toggle`, { method: 'PATCH' }),
  },
  assets: {
    list:          () => req<unknown[]>('/assets'),
    create:        (body: Record<string, unknown>) =>
      req<unknown>('/assets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    update:        (id: string, body: Record<string, unknown>) =>
      req<unknown>(`/assets/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    delete:        (id: string) => fetch(BASE + `/assets/${id}`, { method: 'DELETE' }),
    resetDefaults: () => req<unknown>('/assets/reset-defaults', { method: 'POST' }),
  },
  allowlist: {
    list:         (p?: Record<string, string>) =>
      req<unknown[]>('/allowlist?' + new URLSearchParams(p ?? {})),
    add:          (body: Record<string, unknown>) =>
      req<unknown>('/allowlist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    remove:       (idx: number) => fetch(BASE + `/allowlist/${idx}`, { method: 'DELETE' }),
    purgeExpired: () => req<unknown>('/allowlist/purge-expired', { method: 'DELETE' }),
  },
  health: () => req<{ ok: boolean }>('/health'),
};
