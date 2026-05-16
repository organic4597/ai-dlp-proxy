<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { sse } from '$lib/stores/events.svelte';
  import { api } from '$lib/api';
  import ActionBadge from '$lib/components/ActionBadge.svelte';
  import StatsCard from '$lib/components/StatsCard.svelte';
  import SevBadge from '$lib/components/SevBadge.svelte';

  type TrafficRow = {
    id: number; ts: string; request_id: string;
    prompt_excerpt?: string;
    provider: string; model: string; pipeline_action: string;
    raw_finding_count: number; effective_finding_count: number;
    elapsed_ms: number; cache_hit: boolean;
    findings?: FindingRow[];
  };
  type FindingRow = {
    rule: string; severity: string; confidence: number;
    suppressed: boolean; suppressed_reason: string;
    match_text: string; stage: string; metadata: Record<string, unknown>;
  };

  let rows = $state<TrafficRow[]>([]);
  let summary = $state<Record<string, number>>({});
  let selected = $state<TrafficRow | null>(null);
  let loading = $state(true);
  let detailLoading = $state(false);
  let filterAction = $state('all');
  let autoScroll = $state(true);

  function toExcerpt(messages: unknown, maxLen = 220): string {
    if (!Array.isArray(messages)) return '';
    const chunks: string[] = [];
    for (const m of messages) {
      if (!m || typeof m !== 'object') continue;
      const rec = m as Record<string, unknown>;
      const role = typeof rec.role === 'string' ? rec.role : '';
      const text = typeof rec.text === 'string' ? rec.text : '';
      if (!text.trim()) continue;
      chunks.push(role ? `[${role}] ${text.trim()}` : text.trim());
      if (chunks.join(' ').length >= maxLen) break;
    }
    return chunks.join(' ').slice(0, maxLen);
  }

  // request_id 정규화 — SSE 이벤트의 id(숫자)를 문자열로 통일
  function rowKey(row: TrafficRow): string {
    return String(row.request_id ?? row.id);
  }

  async function load() {
    loading = true;
    try {
      const [data, sum] = await Promise.all([
        api.traffic.list({ limit: 200, with_findings: false }),
        api.traffic.summary(),
      ]);
      const dbRows = data as TrafficRow[];
      // SSE로 먼저 추가된 행이 있으면 병합 (중복 제거)
      const dbKeys = new Set(dbRows.map(rowKey));
      const sseOnly = rows.filter(r => !dbKeys.has(rowKey(r)));
      rows = [...sseOnly, ...dbRows];
      summary = sum as Record<string, number>;
    } finally {
      loading = false;
    }
  }

  async function selectRow(row: TrafficRow) {
    const key = rowKey(row);
    if (selected && rowKey(selected) === key) { selected = null; return; }
    detailLoading = true;
    try {
      // SSE 실시간 행은 findings 포함 — DB 조회 불필요한 경우도 있음
      if (row.findings && row.findings.length > 0) {
        selected = { ...row, request_id: key };
      } else {
        const detail = await api.traffic.get(key) as TrafficRow;
        selected = detail;
      }
    } catch {
      selected = { ...row, request_id: key };
    } finally {
      detailLoading = false;
    }
  }

  // SSE로 새 이벤트 수신 시 최상단에 추가
  const unsub = sse.on('scan_result', (ev: unknown) => {
    const e = ev as TrafficRow & { type: string; id: number };
    if (filterAction !== 'all' && e.pipeline_action !== filterAction) return;
    // id → request_id 정규화
    const normalized: TrafficRow = {
      ...e,
      request_id: String(e.request_id ?? e.id),
      prompt_excerpt: (e as Record<string, unknown>).prompt_excerpt as string | undefined
        ?? toExcerpt((e as Record<string, unknown>).messages),
    };
    // 기존 행 중복 방지
    rows = [normalized, ...rows.filter(r => rowKey(r) !== rowKey(normalized)).slice(0, 498)];
    // summary 갱신
    summary = {
      ...summary,
      total: (summary.total ?? 0) + 1,
      [`${e.pipeline_action}_count`]: ((summary[`${e.pipeline_action}_count`] as number) ?? 0) + 1,
      total_findings: ((summary.total_findings as number) ?? 0) + (e.raw_finding_count ?? 0),
    };
  });

  let filteredRows = $derived(
    filterAction === 'all' ? rows : rows.filter(r => r.pipeline_action === filterAction)
  );

  function fmt(ts: string) {
    if (!ts) return '';
    return ts.includes('T') ? ts.slice(11, 19) : ts.slice(11, 19);
  }

  onMount(load);
  onDestroy(unsub);
</script>

<div class="flex flex-col h-full">
  <!-- 헤더 -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-slate-700">
    <h1 class="text-lg font-semibold text-slate-100">📡 실시간 트래픽</h1>
    <div class="flex items-center gap-3">
      <select
        bind:value={filterAction}
        class="bg-slate-800 border border-slate-600 text-slate-200 text-sm rounded px-3 py-1.5"
      >
        <option value="all">전체</option>
        <option value="pass">PASS</option>
        <option value="alert">ALERT</option>
        <option value="mask">MASK</option>
        <option value="block">BLOCK</option>
      </select>
      <label class="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
        <input type="checkbox" bind:checked={autoScroll} class="accent-blue-500" />
        자동 스크롤
      </label>
      <button
        onclick={load}
        class="bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm px-3 py-1.5 rounded transition-colors"
      >새로고침</button>
    </div>
  </div>

  <!-- 통계 카드 -->
  <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 px-6 py-4">
    <StatsCard title="총 스캔" value={summary.total ?? 0} />
    <StatsCard title="PASS"  value={summary.pass_count  ?? 0} color="text-green-400" />
    <StatsCard title="ALERT" value={summary.alert_count ?? 0} color="text-amber-400" />
    <StatsCard title="MASK"  value={summary.mask_count  ?? 0} color="text-orange-400" />
    <StatsCard title="BLOCK" value={summary.block_count ?? 0} color="text-red-400" />
    <StatsCard title="탐지 수" value={summary.total_findings ?? 0} color="text-blue-400" />
    <StatsCard
      title="평균 응답"
      value={summary.avg_elapsed_ms ? `${Math.round(summary.avg_elapsed_ms as number)}ms` : '—'}
    />
  </div>

  <!-- 테이블 + 상세 분할 -->
  <div class="flex flex-1 overflow-hidden gap-0">
    <!-- 요청 테이블 -->
    <div class={`flex flex-col overflow-hidden transition-all ${selected ? 'w-1/2' : 'w-full'}`}>
      {#if loading}
        <div class="flex items-center justify-center h-40 text-slate-500">로딩 중…</div>
      {:else}
        <div class="overflow-auto flex-1">
          <table class="w-full text-sm">
            <thead class="sticky top-0 bg-slate-900 z-10">
              <tr class="text-left text-xs text-slate-500 uppercase border-b border-slate-700">
                <th class="px-4 py-2">시각</th>
                <th class="px-4 py-2">제공자</th>
                <th class="px-4 py-2">프롬프트 요약</th>
                <th class="px-4 py-2">모델</th>
                <th class="px-4 py-2">액션</th>
                <th class="px-4 py-2 text-right">탐지</th>
                <th class="px-4 py-2 text-right">응답</th>
                <th class="px-4 py-2 text-center">캐시</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredRows as row (rowKey(row))}
                <tr
                  onclick={() => selectRow(row)}
                  class={`border-b border-slate-800 cursor-pointer transition-colors
                    ${selected && rowKey(selected) === rowKey(row)
                      ? 'bg-blue-500/10 border-blue-500/30'
                      : 'hover:bg-slate-800/60'}`}
                >
                  <td class="px-4 py-2 text-slate-400 font-mono text-xs">{fmt(row.ts)}</td>
                  <td class="px-4 py-2 text-slate-300 max-w-24 truncate">{row.provider ?? '—'}</td>
                  <td class="px-4 py-2 text-slate-400 max-w-72 truncate text-xs">{row.prompt_excerpt ?? '—'}</td>
                  <td class="px-4 py-2 text-slate-400 max-w-32 truncate text-xs">{row.model ?? '—'}</td>
                  <td class="px-4 py-2"><ActionBadge action={row.pipeline_action} /></td>
                  <td class="px-4 py-2 text-right">
                    {#if row.raw_finding_count > 0}
                      <span class="text-red-400 font-semibold">{row.effective_finding_count}</span>
                      {#if row.raw_finding_count !== row.effective_finding_count}
                        <span class="text-slate-500 text-xs">/{row.raw_finding_count}</span>
                      {/if}
                    {:else}
                      <span class="text-slate-600">0</span>
                    {/if}
                  </td>
                  <td class="px-4 py-2 text-right text-slate-400 text-xs font-mono">
                    {row.elapsed_ms ? `${Math.round(row.elapsed_ms)}ms` : '—'}
                  </td>
                  <td class="px-4 py-2 text-center text-xs">
                    {#if row.cache_hit}
                      <span class="text-green-400">HIT</span>
                    {:else}
                      <span class="text-slate-600">—</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if filteredRows.length === 0}
            <div class="text-center py-16 text-slate-500">트래픽 데이터 없음</div>
          {/if}
        </div>
      {/if}
    </div>

    <!-- 상세 패널 -->
    {#if selected || detailLoading}
      <div class="w-1/2 border-l border-slate-700 flex flex-col overflow-hidden">
        <div class="flex items-center justify-between px-4 py-3 border-b border-slate-700 bg-slate-900">
          <span class="text-sm font-semibold text-slate-200">상세 정보</span>
          <button onclick={() => { selected = null; }} class="text-slate-500 hover:text-slate-300 text-lg leading-none">✕</button>
        </div>
        {#if detailLoading}
          <div class="flex items-center justify-center h-40 text-slate-500 text-sm">로딩 중…</div>
        {:else if selected}
          <!-- 메타 -->
          <div class="overflow-auto flex-1 p-4 text-sm space-y-4">
          <div class="grid grid-cols-2 gap-3 text-xs">
            <div><span class="text-slate-500">Request ID</span><br/><span class="text-slate-300 font-mono break-all">{selected.request_id}</span></div>
            <div><span class="text-slate-500">시각</span><br/><span class="text-slate-300">{selected.ts}</span></div>
            <div><span class="text-slate-500">제공자</span><br/><span class="text-slate-300">{selected.provider ?? '—'}</span></div>
            <div><span class="text-slate-500">모델</span><br/><span class="text-slate-300 break-all">{selected.model ?? '—'}</span></div>
            <div><span class="text-slate-500">액션</span><br/><ActionBadge action={selected.pipeline_action} /></div>
            <div><span class="text-slate-500">응답 시간</span><br/><span class="text-slate-300">{selected.elapsed_ms ? `${Math.round(selected.elapsed_ms)}ms` : '—'}</span></div>
            <div class="col-span-2"><span class="text-slate-500">프롬프트 요약</span><br/><span class="text-slate-300 whitespace-pre-wrap break-words">{selected.prompt_excerpt ?? '—'}</span></div>
          </div>

          <!-- Finding 목록 -->
          {#if selected.findings && selected.findings.length > 0}
            <div>
              <div class="text-xs text-slate-500 uppercase mb-2">탐지 결과 ({selected.findings.length}건)</div>
              <div class="space-y-2">
                {#each selected.findings as f}
                  <div class={`rounded border p-3 text-xs space-y-1.5
                    ${f.suppressed ? 'border-slate-700 bg-slate-800/40 opacity-60' : 'border-slate-600 bg-slate-800'}`}>
                    <div class="flex items-center gap-2 flex-wrap">
                      <SevBadge severity={f.severity} />
                      <span class="text-slate-200 font-medium">{f.rule}</span>
                      <span class="text-slate-500">conf={f.confidence?.toFixed(2)}</span>
                      <span class="text-slate-600">stage={f.stage}</span>
                      {#if f.suppressed}
                        <span class="text-slate-500 italic">억제됨 ({f.suppressed_reason ?? (f.metadata as Record<string,string>)?.suppressed_reason ?? '?'})</span>
                      {/if}
                    </div>
                    {#if f.match_text}
                      <div class="font-mono bg-slate-900 rounded px-2 py-1 text-slate-300 break-all whitespace-pre-wrap">{f.match_text}</div>
                    {/if}
                  </div>
                {/each}
              </div>
            </div>
          {:else}
            <div class="text-slate-600 text-xs">탐지 결과 없음</div>
          {/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>
