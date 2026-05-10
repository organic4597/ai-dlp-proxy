<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import SevBadge from '$lib/components/SevBadge.svelte';

  type BuiltinRule = { name: string; severity: string; description: string; builtin: true; enabled: boolean };
  type CustomRule  = { id: string; name: string; pattern: string; severity: string; description: string; builtin: false; enabled: boolean };

  let builtins = $state<BuiltinRule[]>([]);
  let customs  = $state<CustomRule[]>([]);
  let toast = $state('');
  let showForm = $state(false);
  let editTarget = $state<CustomRule | null>(null);

  // 폼 상태
  let form = $state({ name: '', pattern: '', severity: 'high', description: '' });
  let formError = $state('');
  let saving = $state(false);

  async function load() {
    const data = await api.rules.list();
    builtins = data.builtin as BuiltinRule[];
    customs  = data.custom  as CustomRule[];
  }

  async function toggleBuiltin(name: string) {
    const r = await api.rules.toggle(name);
    builtins = builtins.map(b => b.name === name ? { ...b, enabled: r.enabled } : b);
    showToast(r.enabled ? `${name} 활성화` : `${name} 비활성화`);
  }

  async function toggleCustom(name: string) {
    const r = await api.rules.toggle(name);
    customs = customs.map(c => c.name === name ? { ...c, enabled: r.enabled } : c);
    showToast(r.enabled ? `${name} 활성화` : `${name} 비활성화`);
  }

  function openCreate() {
    editTarget = null;
    form = { name: '', pattern: '', severity: 'high', description: '' };
    formError = '';
    showForm = true;
  }

  function openEdit(rule: CustomRule) {
    editTarget = rule;
    form = { name: rule.name, pattern: rule.pattern, severity: rule.severity, description: rule.description };
    formError = '';
    showForm = true;
  }

  async function submitForm() {
    formError = '';
    if (!form.name.trim() && !editTarget) { formError = 'name 필수'; return; }
    if (!form.pattern.trim()) { formError = 'pattern 필수'; return; }
    // 클라이언트 측 정규식 검증
    try { new RegExp(form.pattern); } catch (e) { formError = `정규식 오류: ${e}`; return; }

    saving = true;
    try {
      if (editTarget) {
        await api.rules.update(editTarget.name, {
          name: editTarget.name, pattern: form.pattern,
          severity: form.severity, description: form.description,
        });
        showToast('룰 수정됨');
      } else {
        await api.rules.create({
          name: form.name.trim(), pattern: form.pattern,
          severity: form.severity, description: form.description,
        });
        showToast('룰 추가됨');
      }
      showForm = false;
      await load();
    } catch (e: unknown) {
      const err = e as { message?: string };
      formError = err?.message ?? String(e);
    } finally { saving = false; }
  }

  async function deleteCustom(name: string) {
    if (!confirm(`'${name}' 룰을 삭제하시겠습니까?`)) return;
    await api.rules.delete(name);
    customs = customs.filter(c => c.name !== name);
    showToast('삭제됨');
  }

  function showToast(msg: string) { toast = msg; setTimeout(() => toast = '', 2500); }

  onMount(load);
</script>

<div class="flex flex-col h-full overflow-auto p-6 gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">📏 탐지 룰 관리</h1>
    <div class="flex items-center gap-2">
      {#if toast}<span class="text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded px-3 py-1">{toast}</span>{/if}
      <button onclick={openCreate} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">+ 커스텀 룰 추가</button>
    </div>
  </div>

  <!-- 커스텀 룰 폼 모달 -->
  {#if showForm}
    <div class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-600 rounded-xl w-full max-w-lg p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-slate-100 font-semibold">{editTarget ? '룰 수정' : '커스텀 룰 추가'}</h2>
          <button onclick={() => showForm = false} class="text-slate-500 hover:text-slate-300 text-xl">✕</button>
        </div>
        {#if formError}
          <div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded p-3">{formError}</div>
        {/if}
        <div class="space-y-3 text-sm">
          {#if !editTarget}
            <div>
              <label class="text-slate-400 block mb-1">룰 이름 <span class="text-slate-600">(소문자·숫자·언더스코어)</span></label>
              <input bind:value={form.name} placeholder="예: my_custom_id"
                class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500" />
            </div>
          {/if}
          <div>
            <label class="text-slate-400 block mb-1">정규식 패턴</label>
            <input bind:value={form.pattern} placeholder="예: \b\d{6}-\d{7}\b"
              class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500 font-mono" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-slate-400 block mb-1">심각도</label>
              <select bind:value={form.severity} class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200">
                <option value="critical">CRITICAL</option>
                <option value="high">HIGH</option>
                <option value="medium">MEDIUM</option>
                <option value="low">LOW</option>
              </select>
            </div>
            <div>
              <label class="text-slate-400 block mb-1">설명 (선택)</label>
              <input bind:value={form.description} placeholder="룰 설명"
                class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500" />
            </div>
          </div>
        </div>
        <div class="flex gap-2 justify-end pt-2">
          <button onclick={() => showForm = false} class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm px-4 py-2 rounded transition-colors">취소</button>
          <button onclick={submitForm} disabled={saving}
            class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded transition-colors disabled:opacity-50">
            {saving ? '저장 중…' : (editTarget ? '수정' : '추가')}
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- 커스텀 룰 -->
  {#if customs.length > 0}
    <div class="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
      <div class="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
        <span class="text-sm font-semibold text-slate-200">커스텀 룰</span>
        <span class="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full">{customs.length}</span>
      </div>
      <table class="w-full text-sm">
        <thead><tr class="text-xs text-slate-500 border-b border-slate-700 uppercase">
          <th class="px-4 py-2 text-left">이름</th>
          <th class="px-4 py-2 text-left">패턴</th>
          <th class="px-4 py-2 text-left">심각도</th>
          <th class="px-4 py-2 text-left">설명</th>
          <th class="px-4 py-2 text-center">활성</th>
          <th class="px-4 py-2 text-right">작업</th>
        </tr></thead>
        <tbody>
          {#each customs as r}
            <tr class={`border-b border-slate-800 ${r.enabled ? '' : 'opacity-50'}`}>
              <td class="px-4 py-2 text-slate-200 font-mono text-xs">{r.name}</td>
              <td class="px-4 py-2 text-slate-400 font-mono text-xs max-w-48 truncate">{r.pattern}</td>
              <td class="px-4 py-2"><SevBadge severity={r.severity} /></td>
              <td class="px-4 py-2 text-slate-400 text-xs">{r.description || '—'}</td>
              <td class="px-4 py-2 text-center">
                <button onclick={() => toggleCustom(r.name)}
                  class={`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? 'bg-blue-500' : 'bg-slate-600'}`}>
                  <span class={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? 'left-5' : 'left-0.5'}`}></span>
                </button>
              </td>
              <td class="px-4 py-2 text-right flex items-center gap-2 justify-end">
                <button onclick={() => openEdit(r)} class="text-blue-400 hover:text-blue-300 text-xs">수정</button>
                <button onclick={() => deleteCustom(r.name)} class="text-red-400 hover:text-red-300 text-xs">삭제</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- 내장 룰 -->
  <div class="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
    <div class="px-4 py-3 border-b border-slate-700">
      <span class="text-sm font-semibold text-slate-200">내장 룰</span>
      <span class="text-xs text-slate-500 ml-2">활성화/비활성화 가능 (패턴은 변경 불가)</span>
    </div>
    <table class="w-full text-sm">
      <thead><tr class="text-xs text-slate-500 border-b border-slate-700 uppercase">
        <th class="px-4 py-2 text-left">이름</th>
        <th class="px-4 py-2 text-left">설명</th>
        <th class="px-4 py-2 text-left">심각도</th>
        <th class="px-4 py-2 text-center">활성</th>
      </tr></thead>
      <tbody>
        {#each builtins as r}
          <tr class={`border-b border-slate-800 ${r.enabled ? '' : 'opacity-50'}`}>
            <td class="px-4 py-2 text-slate-300 font-mono text-xs">{r.name}</td>
            <td class="px-4 py-2 text-slate-400 text-xs">{r.description}</td>
            <td class="px-4 py-2"><SevBadge severity={r.severity} /></td>
            <td class="px-4 py-2 text-center">
              <button onclick={() => toggleBuiltin(r.name)}
                class={`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? 'bg-blue-500' : 'bg-slate-600'}`}>
                <span class={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? 'left-5' : 'left-0.5'}`}></span>
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
