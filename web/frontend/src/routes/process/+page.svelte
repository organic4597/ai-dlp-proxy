<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';

  type ProcessStatus = {
    name: string; running: boolean; pid?: number;
    uptime_s?: number; error?: string;
  };

  let processes = $state<ProcessStatus[]>([]);
  let loading = $state(true);
  let actionMsg = $state<Record<string, string>>({});

  async function load() {
    loading = true;
    try { processes = await api.process.list() as ProcessStatus[]; }
    finally { loading = false; }
  }

  async function startProc(name: string) {
    actionMsg = { ...actionMsg, [name]: '시작 중…' };
    try {
      await api.process.start(name);
      await load();
      actionMsg = { ...actionMsg, [name]: '시작됨' };
    } catch (e) { actionMsg = { ...actionMsg, [name]: `오류: ${String(e)}` }; }
    setTimeout(() => { actionMsg = { ...actionMsg, [name]: '' }; }, 3000);
  }

  async function stopProc(name: string) {
    actionMsg = { ...actionMsg, [name]: '중지 중…' };
    try {
      await api.process.stop(name);
      await load();
      actionMsg = { ...actionMsg, [name]: '중지됨' };
    } catch (e) { actionMsg = { ...actionMsg, [name]: `오류: ${String(e)}` }; }
    setTimeout(() => { actionMsg = { ...actionMsg, [name]: '' }; }, 3000);
  }

  function fmtUptime(sec?: number) {
    if (!sec) return '—';
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  }

  const PROCESS_META: Record<string, { label: string; icon: string; desc: string }> = {
    engine:    { label: 'DLP Engine',   icon: '⚙️', desc: 'Unix Socket 기반 NDJSON 파이프라인 엔진' },
    mitmproxy: { label: 'mitmproxy',    icon: '🔀', desc: '투명 프록시 — LLM API 트래픽 인터셉트' },
  };

  onMount(load);
</script>

<div class="p-6 flex flex-col gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">🖥 프로세스 상태</h1>
    <button onclick={load} class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button>
  </div>

  {#if loading}
    <div class="text-slate-500 text-sm">로딩 중…</div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
      {#each processes as proc}
        {@const meta = PROCESS_META[proc.name] ?? { label: proc.name, icon: '⚙', desc: '' }}
        <div class={`bg-slate-800 border rounded-lg p-5 flex flex-col gap-4
          ${proc.running ? 'border-green-500/30' : 'border-slate-700'}`}>
          <!-- 헤더 -->
          <div class="flex items-start justify-between">
            <div>
              <div class="flex items-center gap-2">
                <span class="text-2xl">{meta.icon}</span>
                <span class="text-slate-100 font-semibold">{meta.label}</span>
              </div>
              <div class="text-xs text-slate-500 mt-1">{meta.desc}</div>
            </div>
            <!-- 상태 표시 -->
            <div class="flex items-center gap-2">
              <span class={`w-2.5 h-2.5 rounded-full ${proc.running ? 'bg-green-400 animate-pulse' : 'bg-slate-600'}`}></span>
              <span class={`text-sm font-medium ${proc.running ? 'text-green-400' : 'text-slate-500'}`}>
                {proc.running ? 'RUNNING' : 'STOPPED'}
              </span>
            </div>
          </div>

          <!-- 정보 -->
          <div class="grid grid-cols-2 gap-3 text-xs">
            <div>
              <div class="text-slate-500">PID</div>
              <div class="text-slate-200 font-mono">{proc.pid ?? '—'}</div>
            </div>
            <div>
              <div class="text-slate-500">가동 시간</div>
              <div class="text-slate-200">{fmtUptime(proc.uptime_s)}</div>
            </div>
          </div>

          {#if proc.error}
            <div class="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{proc.error}</div>
          {/if}

          {#if actionMsg[proc.name]}
            <div class="text-xs text-slate-400 italic">{actionMsg[proc.name]}</div>
          {/if}

          <!-- 버튼 -->
          <div class="flex gap-2 mt-auto">
            {#if proc.running}
              <button
                onclick={() => stopProc(proc.name)}
                class="flex-1 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 text-red-400 text-sm py-2 rounded transition-colors"
              >중지</button>
            {:else}
              <button
                onclick={() => startProc(proc.name)}
                class="flex-1 bg-green-600/20 hover:bg-green-600/40 border border-green-500/30 text-green-400 text-sm py-2 rounded transition-colors"
              >시작</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    <!-- 안내 -->
    <div class="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4 text-xs text-amber-300/80">
      <strong>참고:</strong> 프로세스 시작/중지는 PID 파일 기반으로 상태를 확인합니다.
      직접 실행된 프로세스는 "시작" 버튼으로 새 프로세스를 생성하거나 기존 것을 종료할 수 있습니다.
    </div>
  {/if}
</div>
