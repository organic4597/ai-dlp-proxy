<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { api } from '$lib/api';
  // /control 은 /settings 로 통합됨 — 리다이렉트
  onMount(() => goto('/settings', { replaceState: true }));

  type Control = {
    regex_enabled: boolean; asset_enabled: boolean; slm_enabled: boolean;
    ml_filter_enabled: boolean; ml_filter_threshold: number;
    mask_on_detect: boolean; block_on_alert: boolean; block_on_mask: boolean;
    confidence_threshold: number; context_penalty_enabled: boolean;
    disabled_rules: string[]; allowlist: { rule: string; value: string; expires?: string }[];
    mask_templates: Record<string, string>;
  };

  let ctrl = $state<Control | null>(null);
  let saving = $state(false);
  let toast = $state('');
  let newAlValue = $state('');
  let newAlRule = $state('');

  async function load() { ctrl = await api.control.get() as Control; }

  async function patch(key: string, value: unknown) {
    if (!ctrl) return;
    saving = true;
    try {
      ctrl = await api.control.put({ [key]: value }) as Control;
      showToast('저장됨');
    } catch (e) { showToast('오류: ' + String(e)); }
    finally { saving = false; }
  }

  function showToast(msg: string) {
    toast = msg;
    setTimeout(() => { toast = ''; }, 2000);
  }

  async function addAllowlist() {
    if (!newAlValue.trim() || !ctrl) return;
    const entry = { rule: newAlRule || '*', value: newAlValue.trim() };
    await patch('allowlist', [...ctrl.allowlist, entry]);
    newAlValue = ''; newAlRule = '';
  }

  async function removeAllowlist(i: number) {
    if (!ctrl) return;
    const al = [...ctrl.allowlist];
    al.splice(i, 1);
    await patch('allowlist', al);
  }

  onMount(load);
</script>

<div class="flex flex-col h-full overflow-auto p-6 gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">⚙️ 파이프라인 제어</h1>
    {#if toast}
      <span class="text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded px-3 py-1">{toast}</span>
    {/if}
  </div>

  {#if !ctrl}
    <div class="text-slate-500 text-sm">로딩 중…</div>
  {:else}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

      <!-- 스테이지 ON/OFF -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
        <div class="text-xs text-slate-500 uppercase mb-4">스테이지 제어</div>
        <div class="space-y-3">
          {#each [
            { key: 'regex_enabled',           label: 'Regex Stage',          desc: '정규식 기반 PII 탐지 (12개 룰)' },
            { key: 'asset_enabled',            label: 'Asset Stage',          desc: '보호 자산 키워드·임베딩 탐지' },
            { key: 'slm_enabled',              label: 'SLM Stage',            desc: '소형 언어모델 보완 탐지 (Gemma 4 2B)' },
            { key: 'ml_filter_enabled',        label: 'ML FP 필터',           desc: 'XGBoost False Positive 억제' },
            { key: 'context_penalty_enabled',  label: '문맥 페널티',           desc: '코드·URL 컨텍스트 시 신뢰도 ×0.3' },
          ] as item}
            <div class="flex items-center justify-between py-2 border-b border-slate-700/50">
              <div>
                <div class="text-sm text-slate-200">{item.label}</div>
                <div class="text-xs text-slate-500 mt-0.5">{item.desc}</div>
              </div>
              <button
                onclick={() => patch(item.key, !(ctrl as Record<string,unknown>)[item.key])}
                class={`relative w-12 h-6 rounded-full transition-colors ${(ctrl as Record<string,boolean>)[item.key] ? 'bg-blue-500' : 'bg-slate-600'}`}
              >
                <span class={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${(ctrl as Record<string,boolean>)[item.key] ? 'left-7' : 'left-1'}`}></span>
              </button>
            </div>
          {/each}
        </div>
      </div>

      <!-- 임계값 설정 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 space-y-5">
        <div class="text-xs text-slate-500 uppercase">임계값 설정</div>
        <!-- 신뢰도 임계값 -->
        <div>
          <div class="flex justify-between text-sm text-slate-200 mb-2">
            <span>신뢰도 임계값</span>
            <span class="font-mono text-blue-400">{ctrl.confidence_threshold.toFixed(2)}</span>
          </div>
          <input
            type="range" min="0" max="1" step="0.01"
            value={ctrl.confidence_threshold}
            oninput={(e) => { if (ctrl) ctrl.confidence_threshold = parseFloat((e.target as HTMLInputElement).value); }}
            onchange={(e) => patch('confidence_threshold', parseFloat((e.target as HTMLInputElement).value))}
            class="w-full accent-blue-500"
          />
          <div class="flex justify-between text-xs text-slate-600 mt-1"><span>0.0</span><span>1.0</span></div>
        </div>
        <!-- ML FP 임계값 -->
        <div>
          <div class="flex justify-between text-sm text-slate-200 mb-2">
            <span>ML FP 필터 임계값</span>
            <span class="font-mono text-purple-400">{ctrl.ml_filter_threshold.toFixed(2)}</span>
          </div>
          <input
            type="range" min="0" max="1" step="0.01"
            value={ctrl.ml_filter_threshold}
            oninput={(e) => { if (ctrl) ctrl.ml_filter_threshold = parseFloat((e.target as HTMLInputElement).value); }}
            onchange={(e) => patch('ml_filter_threshold', parseFloat((e.target as HTMLInputElement).value))}
            class="w-full accent-purple-500"
          />
        </div>
        <!-- 액션 설정 -->
        <div class="text-xs text-slate-500 uppercase mt-4">액션 설정</div>
        {#each [
          { key: 'mask_on_detect',  label: '탐지 시 마스킹',  desc: 'mask_on_detect' },
          { key: 'block_on_alert',  label: 'ALERT 시 차단',   desc: 'block_on_alert' },
          { key: 'block_on_mask',   label: 'MASK 시 차단',    desc: 'block_on_mask' },
        ] as item}
          <div class="flex items-center justify-between py-1.5">
            <div class="text-sm text-slate-300">{item.label}</div>
            <button
              onclick={() => patch(item.key, !(ctrl as Record<string,unknown>)[item.key])}
              class={`relative w-10 h-5 rounded-full transition-colors ${(ctrl as Record<string,boolean>)[item.key] ? 'bg-blue-500' : 'bg-slate-600'}`}
            >
              <span class={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${(ctrl as Record<string,boolean>)[item.key] ? 'left-5' : 'left-0.5'}`}></span>
            </button>
          </div>
        {/each}
      </div>

      <!-- 허용목록 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 lg:col-span-2">
        <div class="text-xs text-slate-500 uppercase mb-4">허용목록 (Allowlist)</div>
        <div class="flex gap-2 mb-4">
          <input bind:value={newAlRule} placeholder="규칙 (예: kr_rrn)" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-sm text-slate-200 w-36 placeholder:text-slate-500" />
          <input bind:value={newAlValue} placeholder="패턴 값" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-sm text-slate-200 flex-1 placeholder:text-slate-500" />
          <button onclick={addAllowlist} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 rounded transition-colors">추가</button>
        </div>
        {#if ctrl.allowlist.length === 0}
          <div class="text-slate-600 text-sm">허용목록 없음</div>
        {:else}
          <table class="w-full text-sm">
            <thead><tr class="text-xs text-slate-500 border-b border-slate-700">
              <th class="pb-2 text-left">규칙</th><th class="pb-2 text-left">값</th><th class="pb-2 text-right">삭제</th>
            </tr></thead>
            <tbody>
              {#each ctrl.allowlist as al, i}
                <tr class="border-b border-slate-800">
                  <td class="py-2 text-slate-400">{al.rule}</td>
                  <td class="py-2 text-slate-200 font-mono">{al.value}</td>
                  <td class="py-2 text-right">
                    <button onclick={() => removeAllowlist(i)} class="text-red-400 hover:text-red-300 text-xs">삭제</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>
  {/if}
</div>
