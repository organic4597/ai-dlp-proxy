<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import ActionBadge from '$lib/components/ActionBadge.svelte';
  import SevBadge from '$lib/components/SevBadge.svelte';

  type AuditEntry = {
    id: number; ts: string; request_id: string;
    action: string; rule: string; severity: string;
    field_path: string; match_text: string;
    suppressed: boolean; suppressed_reason: string;
    provider: string; model: string;
  };

  let entries = $state<AuditEntry[]>([]);
  let selected = $state<AuditEntry | null>(null);
  let loading = $state(true);
  let filterAction = $state('');
  let filterRule   = $state('');
  let dateFrom = $state('');
  let dateTo   = $state('');
  let exportLoading = $state(false);
  let migrateMsg = $state('');

  async function load() {
    loading = true;
    try {
      const params: Record<string, string> = { limit: '300' };
      if (filterAction) params.action = filterAction;
      if (filterRule)   params.rule   = filterRule;
      if (dateFrom)     params.date_from = dateFrom;
      if (dateTo)       params.date_to   = dateTo;
      entries = await api.audit.list(params) as AuditEntry[];
    } finally { loading = false; }
  }

  async function exportCsv() {
    exportLoading = true;
    try {
      const blob = await api.audit.exportCsv() as Blob;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `audit_${new Date().toISOString().slice(0, 10)}.csv`;
      a.click(); URL.revokeObjectURL(url);
    } finally { exportLoading = false; }
  }

  async function migrateJsonl() {
    migrateMsg = '마이그레이션 중…';
    try {
      const result = await api.audit.migrateJsonl() as { inserted: number };
      migrateMsg = `완료: ${result.inserted}건 삽입됨`;
    } catch (e) { migrateMsg = `오류: ${String(e)}`; }
    setTimeout(() => migrateMsg = '', 3000);
  }

  function fmt(ts: string) { return ts ? ts.slice(0, 19) : ''; }

  onMount(load);
</script>

<div class="flex flex-col h-full">
  <div class="flex items-center justify-between px-6 py-4 border-b border-slate-700">
    <h1 class="text-lg font-semibold text-slate-100">📋 감사 로그</h1>
    <div class="flex items-center gap-2">
      {#if migrateMsg}<span class="text-xs text-slate-400">{migrateMsg}</span>{/if}
      <button onclick={migrateJsonl} class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs px-3 py-1.5 rounded transition-colors">
        JSONL 마이그레이션
      </button>
      <button onclick={exportCsv} disabled={exportLoading} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors disabled:opacity-50">
        {exportLoading ? '내보내는 중…' : 'CSV 내보내기'}
      </button>
    </div>
  </div>

  <!-- 필터 -->
  <div class="flex flex-wrap items-center gap-3 px-6 py-3 border-b border-slate-800 text-sm">
    <select bind:value={filterAction} class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm">
      <option value="">액션 전체</option>
      <option value="pass">PASS</option><option value="alert">ALERT</option>
      <option value="mask">MASK</option><option value="block">BLOCK</option>
    </select>
    <input bind:value={filterRule} placeholder="규칙 검색…"
      class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm w-36" />
    <input type="date" bind:value={dateFrom}
      class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm" />
    <span class="text-slate-600">~</span>
    <input type="date" bind:value={dateTo}
      class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm" />
    <button onclick={load} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">검색</button>
  </div>

  <div class="flex flex-1 overflow-hidden">
    <!-- 테이블 -->
    <div class={`flex-1 overflow-auto transition-all ${selected ? 'w-1/2' : ''}`}>
      {#if loading}
        <div class="flex items-center justify-center h-40 text-slate-500">로딩 중…</div>
      {:else}
        <table class="w-full text-sm">
          <thead class="sticky top-0 bg-slate-900 border-b border-slate-700 z-10">
            <tr class="text-left text-xs text-slate-500 uppercase">
              <th class="px-4 py-2">시각</th>
              <th class="px-4 py-2">액션</th>
              <th class="px-4 py-2">규칙</th>
              <th class="px-4 py-2">심각도</th>
              <th class="px-4 py-2">제공자</th>
              <th class="px-4 py-2">상태</th>
            </tr>
          </thead>
          <tbody>
            {#each entries as e (e.id)}
              <tr
                onclick={() => selected = selected?.id === e.id ? null : e}
                class={`border-b border-slate-800 cursor-pointer transition-colors
                  ${selected?.id === e.id ? 'bg-blue-500/10' : 'hover:bg-slate-800/40'}
                  ${e.suppressed ? 'opacity-60' : ''}`}
              >
                <td class="px-4 py-2 text-slate-400 font-mono text-xs">{fmt(e.ts)}</td>
                <td class="px-4 py-2"><ActionBadge action={e.action} /></td>
                <td class="px-4 py-2 text-slate-200">{e.rule ?? '—'}</td>
                <td class="px-4 py-2"><SevBadge severity={e.severity ?? ''} /></td>
                <td class="px-4 py-2 text-slate-400 text-xs">{e.provider ?? '—'}</td>
                <td class="px-4 py-2 text-xs">
                  {#if e.suppressed}
                    <span class="text-slate-500 italic">억제</span>
                  {:else}
                    <span class="text-green-400">유효</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if entries.length === 0}
          <div class="text-center py-16 text-slate-500">감사 로그 없음</div>
        {/if}
      {/if}
    </div>

    <!-- 상세 패널 -->
    {#if selected}
      <div class="w-80 border-l border-slate-700 flex flex-col overflow-hidden shrink-0">
        <div class="flex items-center justify-between px-4 py-3 border-b border-slate-700 bg-slate-900">
          <span class="text-sm font-semibold text-slate-200">상세</span>
          <button onclick={() => selected = null} class="text-slate-500 hover:text-slate-300">✕</button>
        </div>
        <div class="p-4 space-y-3 overflow-auto text-xs">
          {#each [
            ['시각', selected.ts],
            ['Request ID', selected.request_id],
            ['액션', selected.action],
            ['규칙', selected.rule],
            ['심각도', selected.severity],
            ['제공자', selected.provider],
            ['모델', selected.model],
            ['필드', selected.field_path],
            ['억제 이유', selected.suppressed_reason],
          ] as [label, val]}
            {#if val}
              <div>
                <div class="text-slate-500">{label}</div>
                <div class="text-slate-200 font-mono break-all mt-0.5">{val}</div>
              </div>
            {/if}
          {/each}
          {#if selected.match_text}
            <div>
              <div class="text-slate-500">매치 원문</div>
              <div class="mt-0.5 bg-slate-900 rounded p-2 font-mono text-slate-300 break-all whitespace-pre-wrap">{selected.match_text}</div>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
