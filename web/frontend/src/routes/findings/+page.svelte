<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import SevBadge from '$lib/components/SevBadge.svelte';
  import ActionBadge from '$lib/components/ActionBadge.svelte';

  type Finding = {
    id: number; request_id: string; ts: string;
    rule: string; severity: string; confidence: number;
    suppressed: boolean; suppressed_reason: string;
    match_text: string; stage: string; field_path: string;
    role?: string;
    metadata?: Record<string, unknown> | null;
    prompt_excerpt?: string;
    dlp_applied?: string;
    policy_effective: boolean;
    policy_reason?: string;
    confidence_threshold?: number;
  };

  type TrafficDetail = {
    id?: number;
    request_id: string;
    ts: string;
    provider?: string;
    model?: string;
    pipeline_action?: string;
    dlp_applied?: string;
    raw_finding_count?: number;
    effective_finding_count?: number;
    elapsed_ms?: number;
    prompt_excerpt?: string;
    findings?: Finding[];
  };

  type RuleStat = { rule: string; total: number; effective: number; suppressed_count: number; avg_confidence: number; };

  let findings = $state<Finding[]>([]);
  let ruleStats = $state<RuleStat[]>([]);
  let filterRule = $state('');
  let filterSev  = $state('');
  let filterStatus = $state<string>('all');
  let loading = $state(true);
  let detailLoading = $state(false);
  let selectedFinding = $state<Finding | null>(null);
  let selectedRequest = $state<TrafficDetail | null>(null);

  async function load() {
    loading = true;
    try {
      const params: Record<string, string | boolean> = { limit: 300 };
      if (filterRule) params.rule = filterRule;
      if (filterSev)  params.severity = filterSev;
      if (filterStatus !== 'all') params.status = filterStatus;

      const [data, stats] = await Promise.all([
        api.findings.list(params),
        api.findings.byRule(),
      ]);
      findings = data as Finding[];
      ruleStats = stats as RuleStat[];
      if (selectedFinding && !findings.some((f) => f.id === selectedFinding?.id)) {
        selectedFinding = null;
        selectedRequest = null;
      }
    } finally {
      loading = false;
    }
  }

  function fmt(ts: string) { return ts ? ts.slice(0, 19) : ''; }

  function fmtMs(ms?: number) {
    if (!ms) return '—';
    return `${Math.round(ms)}ms`;
  }

  function statusReason(f: Finding) {
    if (f.policy_effective) return '정책 액션 계산 포함';
    if (f.policy_reason === 'below_threshold') return `신뢰도 기준 미달 (${f.confidence_threshold?.toFixed(2) ?? '0.50'})`;
    if (f.policy_reason === 'ml_fp_filter') return 'ML 오탐 필터';
    if (f.policy_reason === 'nms') return '중복 탐지 정리';
    if (f.policy_reason === 'allowlist') return '허용목록';
    return f.policy_reason || f.suppressed_reason || '정책 제외';
  }

  async function selectFinding(f: Finding) {
    if (selectedFinding?.id === f.id) {
      selectedFinding = null;
      selectedRequest = null;
      return;
    }

    selectedFinding = f;
    detailLoading = true;
    try {
      selectedRequest = await api.traffic.get(String(f.request_id)) as TrafficDetail;
    } catch {
      selectedRequest = null;
    } finally {
      detailLoading = false;
    }
  }

  onMount(load);
</script>

<div class="flex flex-col h-full">
  <div class="flex items-center justify-between px-6 py-4 border-b border-slate-700">
    <h1 class="text-lg font-semibold text-slate-100">🔍 탐지 목록</h1>
    <button onclick={load} class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button>
  </div>

  <!-- 필터 바 -->
  <div class="flex items-center gap-3 px-6 py-3 border-b border-slate-800 text-sm">
    <input
      bind:value={filterRule} placeholder="규칙 검색…"
      class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm w-40"
    />
    <select bind:value={filterSev} class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm">
      <option value="">심각도 전체</option>
      <option value="critical">CRITICAL</option>
      <option value="high">HIGH</option>
      <option value="medium">MEDIUM</option>
      <option value="low">LOW</option>
    </select>
    <select bind:value={filterStatus} class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm">
      <option value="all">전체</option>
      <option value="effective">정책 대상(유효)</option>
      <option value="suppressed">정책 제외(억제)</option>
      <option value="below_threshold">신뢰도 미달</option>
    </select>
    <button onclick={load} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">검색</button>
  </div>

  <div class="flex flex-1 overflow-hidden">
    <!-- 탐지 테이블 -->
    <div class="flex-1 overflow-auto min-w-0">
      {#if loading}
        <div class="flex items-center justify-center h-40 text-slate-500">로딩 중…</div>
      {:else}
        <table class="w-full text-sm">
          <thead class="sticky top-0 bg-slate-900 border-b border-slate-700 z-10">
            <tr class="text-left text-xs text-slate-500 uppercase">
              <th class="px-4 py-2">시각</th>
              <th class="px-4 py-2">규칙</th>
              <th class="px-4 py-2">심각도</th>
              <th class="px-4 py-2 text-right">신뢰도</th>
              <th class="px-4 py-2">스테이지</th>
              <th class="px-4 py-2">DLP 처리</th>
              <th class="px-4 py-2">탐지 판정</th>
              <th class="px-4 py-2">프롬프트 문맥</th>
              <th class="px-4 py-2">매치 원문</th>
            </tr>
          </thead>
          <tbody>
            {#each findings as f (f.id)}
              <tr
                onclick={() => selectFinding(f)}
                class={`border-b border-slate-800 cursor-pointer transition-colors
                  ${!f.policy_effective ? 'opacity-60' : ''}
                  ${selectedFinding?.id === f.id ? 'bg-blue-500/10 border-blue-500/30' : 'hover:bg-slate-800/40'}`}
              >
                <td class="px-4 py-2 text-slate-400 font-mono text-xs">{fmt(f.ts)}</td>
                <td class="px-4 py-2 text-slate-200 font-medium">{f.rule}</td>
                <td class="px-4 py-2"><SevBadge severity={f.severity} /></td>
                <td class="px-4 py-2 text-right font-mono text-xs text-slate-300">{f.confidence?.toFixed(2)}</td>
                <td class="px-4 py-2 text-xs">{f.stage ?? '—'}</td>
                <td class="px-4 py-2 text-xs">
                  {#if !f.dlp_applied || f.dlp_applied === 'pass'}
                    <span class="text-slate-500">통과</span>
                  {:else if f.dlp_applied === 'masked'}
                    <span class="bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded text-xs">마스킹</span>
                  {:else if f.dlp_applied === 'blocked'}
                    <span class="bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded text-xs">차단</span>
                  {:else}
                    <span class="text-slate-400">{f.dlp_applied}</span>
                  {/if}
                </td>
                <td class="px-4 py-2 text-xs">
                  {#if f.policy_effective}
                    <div class="flex flex-col gap-0.5">
                      <span class="text-green-400">정책 대상(유효)</span>
                      <span class="text-[11px] text-slate-600">{statusReason(f)}</span>
                    </div>
                  {:else if f.suppressed}
                    <div class="flex flex-col gap-0.5">
                      <span class="text-slate-500">정책 제외(억제)</span>
                      <span class="text-[11px] text-slate-600">{statusReason(f)}</span>
                    </div>
                  {:else}
                    <div class="flex flex-col gap-0.5">
                      <span class="text-amber-300">정책 제외(신뢰도)</span>
                      <span class="text-[11px] text-slate-600">{statusReason(f)}</span>
                    </div>
                  {/if}
                </td>
                <td class="px-4 py-2 text-xs text-slate-400 max-w-72 truncate">{f.prompt_excerpt ?? '—'}</td>
                <td class="px-4 py-2 font-mono text-xs text-slate-400 max-w-48 truncate">{f.match_text ?? '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if findings.length === 0}
          <div class="text-center py-16 text-slate-500">탐지 결과 없음</div>
        {/if}
      {/if}
    </div>

    <!-- 탐지 상세 패널 -->
    {#if selectedFinding || detailLoading}
      <div class="w-[30rem] border-l border-slate-700 flex flex-col overflow-hidden shrink-0">
        <div class="flex items-center justify-between px-4 py-3 border-b border-slate-700 bg-slate-900">
          <span class="text-sm font-semibold text-slate-200">탐지 상세</span>
          <button
            onclick={() => { selectedFinding = null; selectedRequest = null; }}
            class="text-slate-500 hover:text-slate-300 text-lg leading-none"
          >✕</button>
        </div>
        {#if detailLoading}
          <div class="flex items-center justify-center h-40 text-slate-500 text-sm">로딩 중…</div>
        {:else if selectedFinding}
          <div class="overflow-auto flex-1 p-4 text-sm space-y-4">
            <div class="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span class="text-slate-500">Request ID</span><br />
                <span class="text-slate-300 font-mono break-all">{selectedFinding.request_id}</span>
              </div>
              <div>
                <span class="text-slate-500">시각</span><br />
                <span class="text-slate-300">{selectedFinding.ts}</span>
              </div>
              <div>
                <span class="text-slate-500">제공자</span><br />
                <span class="text-slate-300">{selectedRequest?.provider ?? '—'}</span>
              </div>
              <div>
                <span class="text-slate-500">모델</span><br />
                <span class="text-slate-300 break-all">{selectedRequest?.model ?? '—'}</span>
              </div>
              <div>
                <span class="text-slate-500">요청 액션</span><br />
                <ActionBadge action={selectedRequest?.pipeline_action ?? 'pass'} />
              </div>
              <div>
                <span class="text-slate-500">응답 시간</span><br />
                <span class="text-slate-300">{fmtMs(selectedRequest?.elapsed_ms)}</span>
              </div>
              <div>
                <span class="text-slate-500">규칙</span><br />
                <span class="text-slate-200 font-medium">{selectedFinding.rule ?? '—'}</span>
              </div>
              <div>
                <span class="text-slate-500">심각도/신뢰도</span><br />
                <span class="text-slate-300">{selectedFinding.severity?.toUpperCase() ?? '—'} / {selectedFinding.confidence?.toFixed(2) ?? '0.00'}</span>
              </div>
              <div>
                <span class="text-slate-500">스테이지</span><br />
                <span class="text-slate-300">{selectedFinding.stage ?? '—'}</span>
              </div>
              <div>
                <span class="text-slate-500">역할</span><br />
                <span class="text-slate-300">{selectedFinding.role ?? '—'}</span>
              </div>
              <div class="col-span-2">
                <span class="text-slate-500">탐지 판정</span><br />
                <span class={selectedFinding.policy_effective ? 'text-green-400' : 'text-amber-300'}>
                  {selectedFinding.policy_effective ? '정책 대상(유효)' : '정책 제외'}
                </span>
                <span class="text-slate-500 text-xs"> · {statusReason(selectedFinding)}</span>
              </div>
              <div class="col-span-2">
                <span class="text-slate-500">필드 경로</span><br />
                <span class="text-slate-300 font-mono break-all">{selectedFinding.field_path ?? '—'}</span>
              </div>
              <div class="col-span-2">
                <span class="text-slate-500">프롬프트 문맥</span><br />
                <span class="text-slate-300 whitespace-pre-wrap break-words">{selectedFinding.prompt_excerpt ?? selectedRequest?.prompt_excerpt ?? '—'}</span>
              </div>
            </div>

            <div>
              <div class="text-xs text-slate-500 uppercase mb-2">매치 원문</div>
              <div class="font-mono text-xs bg-slate-900 rounded px-3 py-2 text-slate-300 whitespace-pre-wrap break-all">
                {selectedFinding.match_text ?? '—'}
              </div>
            </div>

            {#if selectedRequest?.findings && selectedRequest.findings.length > 0}
              <div>
                <div class="text-xs text-slate-500 uppercase mb-2">동일 요청 탐지 ({selectedRequest.findings.length}건)</div>
                <div class="space-y-2">
                  {#each selectedRequest.findings as rf}
                    <div class="rounded border border-slate-700 bg-slate-800/40 p-2 text-xs">
                      <div class="flex items-center gap-2 flex-wrap">
                        <SevBadge severity={rf.severity} />
                        <span class="text-slate-200">{rf.rule}</span>
                        <span class="text-slate-500">conf={rf.confidence?.toFixed(2)}</span>
                      </div>
                      <div class="mt-1 text-slate-400 font-mono break-all whitespace-pre-wrap">{rf.match_text ?? '—'}</div>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/if}

    <!-- 룰별 통계 사이드 -->
    <div class="w-64 border-l border-slate-700 overflow-auto shrink-0 p-4">
      <div class="text-xs text-slate-500 uppercase mb-3">룰별 통계</div>
      {#each ruleStats as s}
        <div class="mb-3 bg-slate-800 rounded p-3 text-xs space-y-1">
          <div class="text-slate-200 font-medium truncate">{s.rule}</div>
          <div class="flex justify-between text-slate-500">
            <span>총 탐지</span><span class="text-slate-300">{s.total}</span>
          </div>
          <div class="flex justify-between text-slate-500">
            <span>유효</span><span class="text-green-400">{s.effective}</span>
          </div>
          <div class="flex justify-between text-slate-500">
            <span>억제</span><span class="text-amber-400">{s.suppressed_count}</span>
          </div>
          <div class="flex justify-between text-slate-500">
            <span>평균 신뢰도</span><span class="text-slate-300">{s.avg_confidence?.toFixed(2)}</span>
          </div>
          <!-- 억제율 바 -->
          <div class="w-full bg-slate-700 rounded-full h-1.5 mt-1">
            <div
              class="bg-amber-500 h-1.5 rounded-full"
              style={`width: ${s.total > 0 ? Math.round(s.suppressed_count / s.total * 100) : 0}%`}
            ></div>
          </div>
        </div>
      {/each}
    </div>
  </div>
</div>
