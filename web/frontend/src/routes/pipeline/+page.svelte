<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '$lib/api';
  import { sse } from '$lib/stores/events.svelte';
  import { Chart, registerables } from 'chart.js';
  Chart.register(...registerables);

  type Stats = {
    ok: boolean; total: number; scanned: number; findings: number; errors: number;
    cache: { hits: number; misses: number; size: number };
    slm: { total_calls: number; total_findings: number; errors: number; avg_ms: number; p95_ms: number };
  };
  type Snapshot = {
    ts: string; cache_hits: number; cache_misses: number;
    action_pass: number; action_alert: number; action_mask: number; action_block: number;
    nms_suppressed: number; ml_suppressed: number; al_suppressed: number;
    slm_calls: number; slm_avg_ms: number;
  };
  type Control = { regex_enabled: boolean; asset_enabled: boolean; slm_enabled: boolean; ml_filter_enabled: boolean; ml_filter_threshold: number; confidence_threshold: number; context_penalty_enabled: boolean; };

  let stats = $state<Stats | null>(null);
  let ctrl  = $state<Control | null>(null);
  let snapshots = $state<Snapshot[]>([]);
  let chartCanvas = $state<HTMLCanvasElement | null>(null);
  let chart: Chart | null = null;
  let rangeH = $state(1);

  async function load() {
    const [s, c, snaps] = await Promise.all([
      api.pipeline.stats(),
      api.control.get(),
      api.pipeline.snapshots(rangeH),
    ]);
    stats = s as Stats;
    ctrl  = c as Control;
    snapshots = snaps as Snapshot[];
    renderChart();
  }

  function renderChart() {
    if (!chartCanvas || snapshots.length === 0) return;
    const labels = snapshots.map(s => s.ts.slice(11, 16));
    const datasets = [
      { label: 'PASS',  data: snapshots.map(s => s.action_pass),  borderColor: '#22c55e', backgroundColor: '#22c55e20', tension: 0.3 },
      { label: 'ALERT', data: snapshots.map(s => s.action_alert), borderColor: '#f59e0b', backgroundColor: '#f59e0b20', tension: 0.3 },
      { label: 'MASK',  data: snapshots.map(s => s.action_mask),  borderColor: '#f97316', backgroundColor: '#f97316', tension: 0.3 },
      { label: 'BLOCK', data: snapshots.map(s => s.action_block), borderColor: '#ef4444', backgroundColor: '#ef4444', tension: 0.3 },
    ];
    if (chart) { chart.data.labels = labels; chart.data.datasets = datasets; chart.update(); return; }
    chart = new Chart(chartCanvas, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#64748b', maxTicksLimit: 12 }, grid: { color: '#1e293b' } },
          y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
        },
        plugins: { legend: { labels: { color: '#94a3b8', boxWidth: 12 } } },
      },
    });
  }

  const unsub = sse.on('scan_result', () => load());

  function pct(a: number, b: number) { return (a + b) > 0 ? Math.round(a / (a + b) * 100) : 0; }

  onMount(load);
  onDestroy(() => { unsub(); chart?.destroy(); });
</script>

<div class="flex flex-col h-full p-6 gap-6 overflow-auto">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">🔗 파이프라인</h1>
    <div class="flex items-center gap-2">
      <select bind:value={rangeH} onchange={load} class="bg-slate-800 border border-slate-600 text-slate-200 text-sm rounded px-3 py-1.5">
        <option value={1}>1시간</option><option value={6}>6시간</option>
        <option value={24}>24시간</option><option value={168}>7일</option>
      </select>
      <button onclick={load} class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- 파이프라인 플로우 다이어그램 -->
    <div class="lg:col-span-2 bg-slate-800 border border-slate-700 rounded-lg p-5">
      <div class="text-xs text-slate-500 uppercase mb-4">파이프라인 플로우</div>
      <div class="flex flex-col items-center gap-0 text-sm">
        <!-- 요청 -->
        <div class="text-slate-400 text-xs mb-1">LLM API 요청</div>
        <div class="w-px h-4 bg-slate-600"></div>

        {#each [
          { icon: '🔍', name: 'RegexStage', on: ctrl?.regex_enabled ?? true, color: 'blue' },
          { icon: '🤖', name: `ML FP Filter (thr=${ctrl?.ml_filter_threshold?.toFixed(2) ?? '0.40'})`, on: ctrl?.ml_filter_enabled ?? false, color: 'purple' },
        ] as stage}
          <div class={`w-full max-w-sm rounded-lg border px-4 py-2.5 flex items-center justify-between
            ${stage.on ? 'border-blue-500/40 bg-blue-500/5' : 'border-slate-600 bg-slate-900/40 opacity-60'}`}>
            <span class="font-medium text-slate-200">{stage.icon} {stage.name}</span>
            <span class={`text-xs font-semibold ${stage.on ? 'text-green-400' : 'text-slate-500'}`}>{stage.on ? 'ON' : 'OFF'}</span>
          </div>
          <div class="w-px h-3 bg-slate-600"></div>
        {/each}

        <!-- NMS -->
        <div class="w-full max-w-sm border border-dashed border-amber-500/30 rounded px-3 py-1.5 text-center text-xs text-amber-400/70">
          ✂ NMS 중첩제거
        </div>
        <div class="w-px h-3 bg-slate-600"></div>

        {#each [
          { icon: '🛡', name: 'AssetStage', on: ctrl?.asset_enabled ?? true },
          { icon: '🔬', name: 'SLM Stage (Gemma 4 2B)', on: ctrl?.slm_enabled ?? false },
        ] as stage}
          <div class={`w-full max-w-sm rounded-lg border px-4 py-2.5 flex items-center justify-between
            ${stage.on ? 'border-blue-500/40 bg-blue-500/5' : 'border-slate-600 bg-slate-900/40 opacity-60'}`}>
            <span class="font-medium text-slate-200">{stage.icon} {stage.name}</span>
            <span class={`text-xs font-semibold ${stage.on ? 'text-green-400' : 'text-slate-500'}`}>{stage.on ? 'ON' : 'OFF'}</span>
          </div>
          <div class="w-px h-3 bg-slate-600"></div>
        {/each}

        <!-- 액션 결정 -->
        <div class="w-full max-w-sm rounded-lg border border-slate-600 bg-slate-900/60 px-4 py-2.5 text-center text-slate-300 text-xs">
          ⚖ decide_action  threshold={ctrl?.confidence_threshold?.toFixed(2) ?? '0.50'}
        </div>
      </div>
    </div>

    <!-- 우측: 캐시 + SLM + Suppress -->
    <div class="flex flex-col gap-4">
      <!-- 캐시 히트율 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-4">
        <div class="text-xs text-slate-500 uppercase mb-3">엔진 캐시</div>
        {#if stats?.cache}
          {@const c = stats.cache}
          {@const rate = pct(c.hits, c.misses)}
          <div class="flex items-center gap-4 mb-2">
            <div class="text-3xl font-bold {rate >= 80 ? 'text-green-400' : rate >= 50 ? 'text-amber-400' : 'text-slate-400'}">{rate}%</div>
            <div class="text-xs text-slate-500 space-y-0.5">
              <div>히트: <span class="text-slate-300">{c.hits}</span></div>
              <div>미스: <span class="text-slate-300">{c.misses}</span></div>
              <div>크기: <span class="text-slate-300">{c.size}건</span></div>
            </div>
          </div>
          <div class="w-full bg-slate-700 rounded-full h-2">
            <div class="h-2 rounded-full {rate >= 80 ? 'bg-green-500' : rate >= 50 ? 'bg-amber-500' : 'bg-slate-500'}"
              style={`width: ${rate}%`}></div>
          </div>
        {:else}
          <div class="text-slate-600 text-xs">데이터 없음</div>
        {/if}
      </div>

      <!-- SLM 통계 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-4">
        <div class="text-xs text-slate-500 uppercase mb-3">SLM 추론 통계</div>
        {#if stats?.slm?.total_calls}
          {@const s = stats.slm}
          <div class="space-y-1.5 text-xs">
            <div class="flex justify-between"><span class="text-slate-500">추론 횟수</span><span class="text-slate-200">{s.total_calls}회</span></div>
            <div class="flex justify-between"><span class="text-slate-500">탐지 건수</span><span class="text-slate-200">{s.total_findings}건</span></div>
            <div class="flex justify-between"><span class="text-slate-500">평균 응답</span>
              <span class={s.avg_ms < 500 ? 'text-green-400' : s.avg_ms < 3000 ? 'text-amber-400' : 'text-red-400'}>{s.avg_ms}ms</span>
            </div>
            <div class="flex justify-between"><span class="text-slate-500">p95 응답</span><span class="text-slate-400">{s.p95_ms}ms</span></div>
            {#if s.errors > 0}
              <div class="flex justify-between"><span class="text-slate-500">오류</span><span class="text-red-400">{s.errors}건</span></div>
            {/if}
          </div>
        {:else}
          <div class="text-slate-600 text-xs">SLM 추론 기록 없음</div>
        {/if}
      </div>

      <!-- Suppress 분류 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-4">
        <div class="text-xs text-slate-500 uppercase mb-3">Suppress 분류</div>
        {#if stats}
          <div class="space-y-2 text-xs">
            {#each [
              { label: 'NMS 중첩제거', key: 'nms_suppressed', color: 'text-amber-400' },
              { label: 'ML FP 필터',   key: 'ml_suppressed',  color: 'text-purple-400' },
              { label: '허용목록',      key: 'al_suppressed',  color: 'text-green-400' },
            ] as item}
              <div class="flex justify-between items-center">
                <span class="text-slate-500">{item.label}</span>
                <span class={item.color}>{(stats as Record<string,number>)[item.key] ?? 0}건</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-slate-600 text-xs">데이터 없음</div>
        {/if}
      </div>
    </div>
  </div>

  <!-- 시계열 그래프 -->
  <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
    <div class="text-xs text-slate-500 uppercase mb-4">액션별 요청 추이 (최근 {rangeH}시간)</div>
    <div class="h-48">
      {#if snapshots.length > 0}
        <canvas bind:this={chartCanvas}></canvas>
      {:else}
        <div class="flex items-center justify-center h-full text-slate-600 text-sm">스냅샷 데이터 없음 (엔진 가동 후 수집 시작)</div>
      {/if}
    </div>
  </div>
</div>
