<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';

  type AllowlistEntry = { rule: string; value: string; expires?: string };
  type Control = {
    regex_enabled: boolean; asset_enabled: boolean; slm_enabled: boolean;
    ml_filter_enabled: boolean; context_penalty_enabled: boolean;
    mask_on_detect: boolean; block_on_alert: boolean; block_on_mask: boolean;
    confidence_threshold: number; ml_filter_threshold: number;
    disabled_rules: string[];
    skip_roles: string[];
    allowlist: AllowlistEntry[];
    mask_templates: Record<string, string>;
    slm_backend: string;
    slm_api_url: string;
  };

  let ctrl = $state<Control | null>(null);
  let toast = $state('');
  let toastKind = $state<'ok' | 'err' | 'warn'>('ok');
  let newRole = $state('');
  let newAlRule = $state('');
  let newAlValue = $state('');
  let clearConfirm = $state<null | 'logs' | 'traffic'>(null);

  // SLM 헬스 체크
  type SlmHealth = { status: string; model?: string; device?: string; dtype?: string; error?: string; url?: string };
  let slmHealth = $state<SlmHealth | null>(null);
  let slmHealthLoading = $state(false);
  let editingApiUrl = $state(false);
  let apiUrlDraft = $state('');

  async function checkSlmHealth() {
    slmHealthLoading = true;
    slmHealth = null;
    try {
      slmHealth = await api.pipeline.slmHealth();
    } catch (e) {
      slmHealth = { status: 'error', error: String(e) };
    } finally {
      slmHealthLoading = false;
    }
  }

  async function saveSlmBackend(backend: string) {
    if (!ctrl) return;
    ctrl = { ...ctrl, slm_backend: backend };
    try {
      await api.control.put({ slm_backend: backend });
      showToast('저장됨', 'ok');
    } catch (e) { showToast('오류: ' + String(e), 'err'); }
  }

  async function saveApiUrl() {
    if (!ctrl) return;
    const url = apiUrlDraft.trim();
    if (!url) return;
    ctrl = { ...ctrl, slm_api_url: url };
    editingApiUrl = false;
    try {
      await api.control.put({ slm_api_url: url });
      showToast('저장됨', 'ok');
    } catch (e) { showToast('오류: ' + String(e), 'err'); }
  }


  async function load() {
    ctrl = await api.control.get() as Control;
    if (ctrl) apiUrlDraft = ctrl.slm_api_url;
  }

  async function toggle(key: string) {
    if (!ctrl) return;
    const val = !(ctrl as Record<string,boolean>)[key];
    ctrl = { ...ctrl, [key]: val };
    try {
      await api.control.put({ [key]: val });
      showToast('저장됨', 'ok');
    } catch (e) {
      ctrl = { ...ctrl, [key]: !val };
      showToast('오류: ' + String(e), 'err');
    }
  }

  async function saveThreshold(key: string, val: number) {
    if (!ctrl) return;
    ctrl = { ...ctrl, [key]: val };
    try {
      await api.control.put({ [key]: val });
      showToast('저장됨', 'ok');
    } catch (e) { showToast('오류: ' + String(e), 'err'); }
  }

  async function addSkipRole() {
    if (!ctrl || !newRole.trim()) return;
    const role = newRole.trim();
    if (ctrl.skip_roles.includes(role)) return;
    const next = [...ctrl.skip_roles, role];
    ctrl = { ...ctrl, skip_roles: next };
    await api.control.put({ skip_roles: next });
    newRole = '';
    showToast('저장됨', 'ok');
  }

  async function removeSkipRole(role: string) {
    if (!ctrl) return;
    const next = ctrl.skip_roles.filter(r => r !== role);
    ctrl = { ...ctrl, skip_roles: next };
    await api.control.put({ skip_roles: next });
    showToast('저장됨', 'ok');
  }

  async function addAllowlist() {
    if (!ctrl || !newAlValue.trim()) return;
    const entry: AllowlistEntry = { rule: newAlRule.trim() || '*', value: newAlValue.trim() };
    const next = [...ctrl.allowlist, entry];
    ctrl = { ...ctrl, allowlist: next };
    await api.control.put({ allowlist: next });
    newAlValue = ''; newAlRule = '';
    showToast('저장됨', 'ok');
  }

  async function removeAllowlist(i: number) {
    if (!ctrl) return;
    const next = [...ctrl.allowlist];
    next.splice(i, 1);
    ctrl = { ...ctrl, allowlist: next };
    await api.control.put({ allowlist: next });
    showToast('저장됨', 'ok');
  }

  async function doClear(kind: 'logs' | 'traffic') {
    clearConfirm = null;
    try {
      if (kind === 'logs') {
        const r = await api.logs.clear();
        showToast(`엔진 로그 ${r.deleted}건 삭제됨`, 'warn');
      } else {
        const r = await api.traffic.clear();
        showToast(`트래픽 ${r.deleted_requests}건·탐지 ${r.deleted_findings}건 삭제됨`, 'warn');
      }
    } catch (e) { showToast('오류: ' + String(e), 'err'); }
  }

  function showToast(msg: string, kind: 'ok' | 'err' | 'warn' = 'ok') {
    toast = msg; toastKind = kind;
    setTimeout(() => { toast = ''; }, 3000);
  }

  const STAGE_TOGGLES = [
    { key: 'regex_enabled',           label: 'Regex Stage',    desc: '정규식 기반 PII 탐지' },
    { key: 'asset_enabled',           label: 'Asset Stage',    desc: '보호 자산 키워드·임베딩 탐지' },
    { key: 'slm_enabled',             label: 'SLM Stage',      desc: '소형 언어모델 보완 탐지 (아래 백엔드 설정 점상)' },
    { key: 'ml_filter_enabled',       label: 'ML FP 필터',     desc: 'XGBoost False Positive 억제' },
    { key: 'context_penalty_enabled', label: '문맥 페널티',    desc: '코드·URL 컨텍스트 감지 시 신뢰도 ×0.3' },
  ];

  const SLM_BACKENDS = [
    { value: 'auto',    label: 'Auto',    desc: 'GPU있으면 adapter, 없으면 GGUF' },
    { value: 'gguf',    label: 'GGUF',    desc: 'llama-cpp-python (Gemma 4 2B)' },
    { value: 'adapter', label: 'Adapter', desc: 'HuggingFace Qwen3.5-4B QLoRA' },
    { value: 'api',     label: 'API',     desc: '외부 충론 서버 (SSH 터널)' },
  ];

  const ACTION_TOGGLES = [
    { key: 'mask_on_detect', label: '탐지 시 마스킹', desc: '임계값 이상 PII 자동 마스킹' },
    { key: 'block_on_alert', label: 'ALERT 시 차단',  desc: 'ALERT 액션 판정 시 요청 차단' },
    { key: 'block_on_mask',  label: 'MASK 시 차단',   desc: 'MASK 액션 판정 시 요청 차단' },
  ];

  onMount(load);
</script>

<div class="p-6 overflow-auto flex flex-col gap-6">
  <!-- 헤더 -->
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">⚙️ 제어 &amp; 설정</h1>
    {#if toast}
      <span class={`text-xs border rounded px-3 py-1 transition-all
        ${toastKind === 'ok'   ? 'bg-green-500/20 text-green-400 border-green-500/30'
        : toastKind === 'warn' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                               : 'bg-red-500/20 text-red-400 border-red-500/30'}`}>
        {toast}
      </span>
    {/if}
  </div>

  {#if !ctrl}
    <div class="text-slate-500 text-sm">로딩 중…</div>
  {:else}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

      <!-- ① 파이프라인 스테이지 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
        <div class="text-xs text-slate-500 uppercase mb-4">파이프라인 스테이지</div>
        <div class="space-y-2">
          {#each STAGE_TOGGLES as item}
            <div class="flex items-center justify-between py-1.5 border-b border-slate-700/50">
              <div>
                <div class="text-sm text-slate-200">{item.label}</div>
                <div class="text-xs text-slate-500 mt-0.5">{item.desc}</div>
              </div>
              <button
                onclick={() => toggle(item.key)}
                class={`relative w-12 h-6 rounded-full transition-colors shrink-0
                  ${(ctrl as Record<string,boolean>)[item.key] ? 'bg-blue-500' : 'bg-slate-600'}`}
              >
                <span class={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform
                  ${(ctrl as Record<string,boolean>)[item.key] ? 'left-7' : 'left-1'}`}></span>
              </button>
            </div>
          {/each}
        </div>

        <div class="text-xs text-slate-500 uppercase mt-5 mb-3">액션 설정</div>
        <div class="space-y-2">
          {#each ACTION_TOGGLES as item}
            <div class="flex items-center justify-between py-1.5 border-b border-slate-700/50">
              <div>
                <div class="text-sm text-slate-200">{item.label}</div>
                <div class="text-xs text-slate-500 mt-0.5">{item.desc}</div>
              </div>
              <button
                onclick={() => toggle(item.key)}
                class={`relative w-12 h-6 rounded-full transition-colors shrink-0
                  ${(ctrl as Record<string,boolean>)[item.key] ? 'bg-red-500' : 'bg-slate-600'}`}
              >
                <span class={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform
                  ${(ctrl as Record<string,boolean>)[item.key] ? 'left-7' : 'left-1'}`}></span>
              </button>
            </div>
          {/each}
        </div>
      </div>

      <!-- ② 임계값 + Skip Roles -->
      <div class="flex flex-col gap-5">
        <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 space-y-5">
          <div class="text-xs text-slate-500 uppercase">임계값</div>
          <div>
            <div class="flex justify-between text-sm text-slate-200 mb-2">
              <span>신뢰도 임계값 <span class="text-xs text-slate-500">(이 값 이상만 유효 탐지)</span></span>
              <span class="font-mono text-blue-400">{ctrl.confidence_threshold.toFixed(2)}</span>
            </div>
            <input type="range" min="0" max="1" step="0.01"
              value={ctrl.confidence_threshold}
              oninput={(e) => { if (ctrl) ctrl.confidence_threshold = parseFloat((e.target as HTMLInputElement).value); }}
              onchange={(e) => saveThreshold('confidence_threshold', parseFloat((e.target as HTMLInputElement).value))}
              class="w-full accent-blue-500" />
            <div class="flex justify-between text-xs text-slate-600 mt-1"><span>0.0 (민감)</span><span>1.0 (엄격)</span></div>
          </div>
          <div>
            <div class="flex justify-between text-sm text-slate-200 mb-2">
              <span>ML FP 필터 임계값 <span class="text-xs text-slate-500">(TP 확률 기준)</span></span>
              <span class="font-mono text-purple-400">{ctrl.ml_filter_threshold.toFixed(2)}</span>
            </div>
            <input type="range" min="0" max="1" step="0.01"
              value={ctrl.ml_filter_threshold}
              oninput={(e) => { if (ctrl) ctrl.ml_filter_threshold = parseFloat((e.target as HTMLInputElement).value); }}
              onchange={(e) => saveThreshold('ml_filter_threshold', parseFloat((e.target as HTMLInputElement).value))}
              class="w-full accent-purple-500" />
            <div class="flex justify-between text-xs text-slate-600 mt-1"><span>0.0 (넓게 억제)</span><span>1.0 (거의 억제 안함)</span></div>
          </div>
        </div>

        <!-- Skip Roles -->
        <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
          <div class="text-xs text-slate-500 uppercase mb-2">스캔 제외 역할</div>
          <div class="text-xs text-slate-500 mb-3">
            해당 역할 메시지는 PII 스캔 건너뜀.
            기본값: <code class="bg-slate-700 px-1 rounded">system</code> <code class="bg-slate-700 px-1 rounded">tool_def</code>
          </div>
          <div class="flex gap-2 mb-3">
            <input bind:value={newRole} placeholder="역할 이름 (예: assistant)"
              onkeydown={(e) => e.key === 'Enter' && addSkipRole()}
              class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm flex-1 min-w-0" />
            <button onclick={addSkipRole} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors shrink-0">추가</button>
          </div>
          <div class="flex flex-wrap gap-2">
            {#each ctrl.skip_roles as role}
              <span class="flex items-center gap-1.5 bg-slate-700 border border-slate-600 rounded-full px-3 py-1 text-xs text-slate-300">
                {role}
                <button onclick={() => removeSkipRole(role)} class="text-slate-500 hover:text-red-400 leading-none">✕</button>
              </span>
            {:else}
              <span class="text-xs text-slate-600">역할 없음 (모든 역할 스캔)</span>
            {/each}
          </div>
        </div>
      </div>

      <!-- ② SLM 백엔드 설정 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 lg:col-span-2">
        <div class="text-xs text-slate-500 uppercase mb-4">🤖 SLM 백엔드 설정</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">

          <!-- 백엔드 선택 -->
          <div>
            <div class="text-sm text-slate-300 mb-3">추론 백엔드</div>
            <div class="space-y-2">
              {#each SLM_BACKENDS as b}
                <label class={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors
                  ${ctrl.slm_backend === b.value
                    ? 'bg-blue-500/10 border-blue-500/40'
                    : 'bg-slate-700/40 border-slate-700 hover:border-slate-600'}`}>
                  <input
                    type="radio"
                    name="slm_backend"
                    value={b.value}
                    checked={ctrl.slm_backend === b.value}
                    onchange={() => saveSlmBackend(b.value)}
                    class="mt-0.5 accent-blue-500"
                  />
                  <div>
                    <div class="text-sm text-slate-200 font-medium">{b.label}</div>
                    <div class="text-xs text-slate-500 mt-0.5">{b.desc}</div>
                  </div>
                </label>
              {/each}
            </div>
          </div>

          <!-- API 설정 + 헬스 체크 -->
          <div class="flex flex-col gap-4">
            <div>
              <div class="text-sm text-slate-300 mb-2">API 서버 URL
                <span class="text-xs text-slate-500 ml-1">(백엔드 = API 일 때 사용)</span>
              </div>
              {#if editingApiUrl}
                <div class="flex gap-2">
                  <input
                    bind:value={apiUrlDraft}
                    onkeydown={(e) => { if (e.key === 'Enter') saveApiUrl(); if (e.key === 'Escape') editingApiUrl = false; }}
                    class="flex-1 bg-slate-700 border border-blue-500/50 rounded px-3 py-1.5 text-slate-200 text-sm font-mono focus:outline-none focus:border-blue-400"
                    placeholder="http://localhost:8766"
                  />
                  <button onclick={saveApiUrl}
                    class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors shrink-0">저장</button>
                  <button onclick={() => { editingApiUrl = false; apiUrlDraft = ctrl?.slm_api_url ?? ''; }}
                    class="text-slate-500 hover:text-slate-300 text-sm px-2 py-1.5 rounded transition-colors shrink-0">취소</button>
                </div>
              {:else}
                <div class="flex items-center gap-2">
                  <span class="font-mono text-sm text-slate-300 bg-slate-700 border border-slate-600 rounded px-3 py-1.5 flex-1 min-w-0 truncate">{ctrl.slm_api_url}</span>
                  <button onclick={() => { apiUrlDraft = ctrl?.slm_api_url ?? ''; editingApiUrl = true; }}
                    class="text-slate-500 hover:text-slate-300 text-sm px-2 py-1.5 rounded transition-colors shrink-0">편집</button>
                </div>
              {/if}
            </div>

            <!-- 헬스 체크 버튼 + 결과 -->
            <div>
              <button
                onclick={checkSlmHealth}
                disabled={slmHealthLoading}
                class="bg-slate-700 hover:bg-slate-600 border border-slate-600 disabled:opacity-50 text-slate-200 text-sm px-4 py-2 rounded transition-colors flex items-center gap-2"
              >
                {#if slmHealthLoading}
                  <span class="w-3 h-3 rounded-full border-2 border-slate-400 border-t-transparent animate-spin"></span>
                  확인 중…
                {:else}
                  🔌 API 연결 확인
                {/if}
              </button>

              {#if slmHealth}
                <div class={`mt-3 rounded-lg p-3 text-xs border
                  ${slmHealth.status === 'ok'
                    ? 'bg-green-500/10 border-green-500/30 text-green-300'
                    : slmHealth.status === 'loading'
                    ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300'
                    : 'bg-red-500/10 border-red-500/30 text-red-300'}`}>
                  <div class="font-semibold mb-1">
                    {slmHealth.status === 'ok' ? '✓ 연결됨' : slmHealth.status === 'loading' ? '⏳ 모델 로딩 중' : '✗ 연결 실패'}
                  </div>
                  {#if slmHealth.model}
                    <div class="text-slate-400">모델: <span class="text-slate-300">{slmHealth.model}</span></div>
                  {/if}
                  {#if slmHealth.device}
                    <div class="text-slate-400">장치: <span class="text-slate-300">{slmHealth.device} / {slmHealth.dtype}</span></div>
                  {/if}
                  {#if slmHealth.error}
                    <div class="mt-1 text-red-400 break-all">{slmHealth.error}</div>
                  {/if}
                  {#if slmHealth.url}
                    <div class="text-slate-500 mt-1">{slmHealth.url}</div>
                  {/if}
                </div>
              {/if}
            </div>

            <!-- 참고 안내 -->
            <div class="text-xs text-slate-500 bg-slate-700/40 rounded p-3 leading-relaxed">
              <strong class="text-slate-400">백엔드 변경 안내</strong><br />
              API 모드: 학습 서버(WSL2)에서 <code class="bg-slate-700 px-1 rounded">start_slm_services.sh</code> 실행 후 SSH 터널 연결 필요.<br />
              백엔드 변경은 제어 파일에 즉시 저장되며 다음 스캔부터 반영됩니다.
            </div>
          </div>
        </div>
      </div>

      <!-- ③ 허용목록 -->      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 lg:col-span-2">
        <div class="text-xs text-slate-500 uppercase mb-4">허용목록 (Allowlist)</div>
        <div class="flex gap-2 mb-4">
          <input bind:value={newAlRule} placeholder="규칙 (예: kr_rrn, * = 전체)"
            class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-sm text-slate-200 w-44 placeholder:text-slate-500" />
          <input bind:value={newAlValue} placeholder="패턴 값"
            onkeydown={(e) => e.key === 'Enter' && addAllowlist()}
            class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-sm text-slate-200 flex-1 placeholder:text-slate-500" />
          <button onclick={addAllowlist} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 rounded transition-colors shrink-0">추가</button>
        </div>
        {#if ctrl.allowlist.length === 0}
          <div class="text-slate-600 text-sm">허용목록 없음</div>
        {:else}
          <table class="w-full text-sm">
            <thead>
              <tr class="text-xs text-slate-500 border-b border-slate-700">
                <th class="pb-2 text-left font-normal">규칙</th>
                <th class="pb-2 text-left font-normal">값</th>
                <th class="pb-2 text-right font-normal">삭제</th>
              </tr>
            </thead>
            <tbody>
              {#each ctrl.allowlist as al, i}
                <tr class="border-b border-slate-800/80">
                  <td class="py-2 text-slate-400 pr-4">{al.rule}</td>
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

      <!-- ④ 데이터 초기화 -->
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 lg:col-span-2">
        <div class="text-xs text-slate-500 uppercase mb-4">데이터 초기화</div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">

          <!-- 엔진 로그 초기화 -->
          <div class="border border-slate-700 rounded-lg p-4 flex flex-col gap-3">
            <div>
              <div class="text-sm text-slate-200 font-medium">엔진 로그 초기화</div>
              <div class="text-xs text-slate-500 mt-0.5">DB에 저장된 엔진 로그를 모두 삭제합니다.</div>
            </div>
            {#if clearConfirm === 'logs'}
              <div class="flex gap-2 items-center">
                <span class="text-xs text-yellow-400">정말 삭제할까요?</span>
                <button onclick={() => doClear('logs')} class="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1 rounded transition-colors">삭제</button>
                <button onclick={() => clearConfirm = null} class="text-slate-500 hover:text-slate-300 text-xs px-2 py-1 rounded transition-colors">취소</button>
              </div>
            {:else}
              <button onclick={() => clearConfirm = 'logs'} class="self-start bg-slate-700 hover:bg-slate-600 border border-slate-600 text-slate-300 text-sm px-4 py-1.5 rounded transition-colors">
                로그 초기화
              </button>
            {/if}
          </div>

          <!-- 트래픽 기록 초기화 -->
          <div class="border border-slate-700 rounded-lg p-4 flex flex-col gap-3">
            <div>
              <div class="text-sm text-slate-200 font-medium">트래픽 기록 초기화</div>
              <div class="text-xs text-slate-500 mt-0.5">저장된 요청 기록과 탐지 결과를 모두 삭제합니다.</div>
            </div>
            {#if clearConfirm === 'traffic'}
              <div class="flex gap-2 items-center">
                <span class="text-xs text-yellow-400">정말 삭제할까요?</span>
                <button onclick={() => doClear('traffic')} class="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1 rounded transition-colors">삭제</button>
                <button onclick={() => clearConfirm = null} class="text-slate-500 hover:text-slate-300 text-xs px-2 py-1 rounded transition-colors">취소</button>
              </div>
            {:else}
              <button onclick={() => clearConfirm = 'traffic'} class="self-start bg-slate-700 hover:bg-slate-600 border border-slate-600 text-slate-300 text-sm px-4 py-1.5 rounded transition-colors">
                트래픽 초기화
              </button>
            {/if}
          </div>

        </div>
      </div>

    </div>
  {/if}
</div>
