<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';

  type Entry = {
    _idx: number; rule: string; value: string;
    added_at?: string; expires_at?: string; _expired: boolean;
  };

  let entries = $state<Entry[]>([]);
  let filterRule = $state('');
  let showExpired = $state<string>('active'); // all / active / expired
  let toast = $state('');
  let saving = $state(false);

  // 추가 폼
  let newRule  = $state('*');
  let newValue = $state('');
  let newExpiry = $state('');
  let formError = $state('');

  // 마스킹 템플릿
  let templates = $state<Record<string, string>>({});
  let templateSaving = $state(false);
  let templateToast = $state('');
  let newTplKey = $state('');
  let newTplVal = $state('');

  async function load() {
    const p: Record<string, string> = {};
    if (filterRule) p.rule = filterRule;
    if (showExpired === 'active')   p.expired = 'false';
    if (showExpired === 'expired')  p.expired = 'true';
    entries = await api.allowlist.list(p) as Entry[];
  }

  async function loadTemplates() {
    const ctrl = await api.control.get() as { mask_templates: Record<string, string> };
    templates = { ...ctrl.mask_templates };
  }

  async function addEntry() {
    formError = '';
    if (!newValue.trim()) { formError = '값 필수'; return; }
    saving = true;
    try {
      const body: Record<string, string> = { rule: newRule || '*', value: newValue.trim() };
      if (newExpiry) body.expires_at = new Date(newExpiry).toISOString();
      await api.allowlist.add(body);
      newValue = ''; newExpiry = '';
      showToast('추가됨');
      await load();
    } catch (e: unknown) {
      formError = (e as { message?: string })?.message ?? String(e);
    } finally { saving = false; }
  }

  async function remove(idx: number) {
    await api.allowlist.remove(idx);
    await load();
    showToast('삭제됨');
  }

  async function purgeExpired() {
    const r = await api.allowlist.purgeExpired() as { removed: number };
    showToast(`만료 항목 ${r.removed}건 삭제됨`);
    await load();
  }

  // 마스킹 템플릿 저장
  async function saveTpl(key: string, val: string) {
    templateSaving = true;
    try {
      await api.control.put({ mask_templates: { ...templates, [key]: val } });
      templates = { ...templates, [key]: val };
      setTplToast('저장됨');
    } finally { templateSaving = false; }
  }

  async function addTpl() {
    if (!newTplKey.trim() || !newTplVal.trim()) return;
    await saveTpl(newTplKey.trim(), newTplVal.trim());
    newTplKey = ''; newTplVal = '';
  }

  async function deleteTpl(key: string) {
    const next = { ...templates };
    delete next[key];
    templateSaving = true;
    try {
      await api.control.put({ mask_templates: next });
      templates = next;
      setTplToast('삭제됨');
    } finally { templateSaving = false; }
  }

  function showToast(msg: string) { toast = msg; setTimeout(() => toast = '', 2500); }
  function setTplToast(msg: string) { templateToast = msg; setTimeout(() => templateToast = '', 2500); }
  function fmtDate(s?: string) { return s ? s.slice(0, 10) : '—'; }

  onMount(() => { load(); loadTemplates(); });
</script>

<div class="flex flex-col h-full overflow-auto p-6 gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">✅ 허용목록 &amp; 마스킹 템플릿</h1>
    {#if toast}<span class="text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded px-3 py-1">{toast}</span>{/if}
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">

    <!-- ── 허용목록 ── -->
    <div class="flex flex-col gap-4">
      <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 space-y-4">
        <div class="flex items-center justify-between">
          <span class="text-sm font-semibold text-slate-200">허용목록 (Allowlist)</span>
          <button onclick={purgeExpired} class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 rounded px-3 py-1 transition-colors">만료 항목 삭제</button>
        </div>

        <!-- 필터 -->
        <div class="flex gap-2 text-sm">
          <input bind:value={filterRule} placeholder="규칙 필터 (예: kr_rrn)"
            class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 flex-1 text-sm" />
          <select bind:value={showExpired} onchange={load}
            class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm">
            <option value="active">유효만</option>
            <option value="expired">만료만</option>
            <option value="all">전체</option>
          </select>
          <button onclick={load} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors">검색</button>
        </div>

        <!-- 추가 폼 -->
        <div class="border border-dashed border-slate-600 rounded-lg p-3 space-y-2">
          <div class="text-xs text-slate-500 mb-2">항목 추가</div>
          {#if formError}
            <div class="text-xs text-red-400">{formError}</div>
          {/if}
          <div class="grid grid-cols-2 gap-2">
            <input bind:value={newRule} placeholder="규칙 (* = 전체)"
              class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm" />
            <input bind:value={newValue} placeholder="허용할 값 (정확히 일치)"
              class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm" />
          </div>
          <div class="flex gap-2">
            <div class="flex-1">
              <label class="text-xs text-slate-500 block mb-1">만료일 (선택)</label>
              <input type="datetime-local" bind:value={newExpiry}
                class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm" />
            </div>
            <button onclick={addEntry} disabled={saving}
              class="self-end bg-green-600 hover:bg-green-500 text-white text-sm px-4 py-1.5 rounded transition-colors disabled:opacity-50 whitespace-nowrap">
              {saving ? '추가 중…' : '추가'}
            </button>
          </div>
        </div>

        <!-- 목록 -->
        <div class="space-y-2 max-h-96 overflow-auto">
          {#each entries as e}
            <div class={`flex items-center gap-3 rounded-lg px-3 py-2 border text-xs
              ${e._expired ? 'border-red-500/20 bg-red-500/5 opacity-60' : 'border-slate-700 bg-slate-900/40'}`}>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <span class="text-slate-500 shrink-0">{e.rule}</span>
                  <span class="text-slate-300 font-mono truncate">{e.value}</span>
                  {#if e._expired}<span class="text-red-400 shrink-0">만료됨</span>{/if}
                </div>
                <div class="text-slate-600 mt-0.5">
                  추가: {fmtDate(e.added_at)}
                  {#if e.expires_at} · 만료: {fmtDate(e.expires_at)}{/if}
                </div>
              </div>
              <button onclick={() => remove(e._idx)} class="text-red-400 hover:text-red-300 shrink-0 text-sm">✕</button>
            </div>
          {:else}
            <div class="text-center py-8 text-slate-600">허용목록 없음</div>
          {/each}
        </div>
      </div>
    </div>

    <!-- ── 마스킹 템플릿 ── -->
    <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 flex flex-col gap-4">
      <div class="flex items-center justify-between">
        <span class="text-sm font-semibold text-slate-200">마스킹 템플릿</span>
        {#if templateToast}<span class="text-xs text-green-400">{templateToast}</span>{/if}
      </div>
      <div class="text-xs text-slate-500">탐지된 PII를 대체할 플레이스홀더 문자열을 룰별로 지정합니다.</div>

      <!-- 추가 -->
      <div class="flex gap-2 text-sm">
        <input bind:value={newTplKey} placeholder="룰 이름 (예: kr_rrn)"
          class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 w-36 text-xs font-mono" />
        <input bind:value={newTplVal} placeholder="플레이스홀더 (예: [주민번호])"
          class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 flex-1 text-xs" />
        <button onclick={addTpl} disabled={templateSaving}
          class="bg-blue-600 hover:bg-blue-500 text-white text-xs px-3 py-1.5 rounded transition-colors disabled:opacity-50 whitespace-nowrap">추가</button>
      </div>

      <!-- 템플릿 목록 -->
      <div class="space-y-1.5 overflow-auto flex-1">
        {#each Object.entries(templates) as [key, val]}
          <div class="flex items-center gap-2 group">
            <span class="text-slate-500 font-mono text-xs w-36 shrink-0 truncate">{key}</span>
            <input
              value={val}
              onblur={(e) => saveTpl(key, (e.target as HTMLInputElement).value)}
              class="flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-slate-200 text-xs font-mono"
            />
            <button onclick={() => deleteTpl(key)} class="text-red-400 hover:text-red-300 text-xs opacity-0 group-hover:opacity-100 transition-opacity">✕</button>
          </div>
        {:else}
          <div class="text-center py-6 text-slate-600 text-sm">템플릿 없음 (기본값 사용 중)</div>
        {/each}
      </div>
    </div>

  </div>
</div>
