<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import SevBadge from '$lib/components/SevBadge.svelte';

  type Asset = {
    id: string; name: string; severity: string;
    keywords: string[]; examples: string[];
    embedding_threshold: number;
  };

  let assets = $state<Asset[]>([]);
  let toast = $state('');
  let showForm = $state(false);
  let editTarget = $state<Asset | null>(null);
  let saving = $state(false);
  let formError = $state('');

  // 폼 상태
  let form = $state({
    name: '', severity: 'high',
    keywords: '', examples: '',
    embedding_threshold: 0.83,
  });

  async function load() {
    assets = await api.assets.list() as Asset[];
  }

  function openCreate() {
    editTarget = null;
    form = { name: '', severity: 'high', keywords: '', examples: '', embedding_threshold: 0.83 };
    formError = '';
    showForm = true;
  }

  function openEdit(a: Asset) {
    editTarget = a;
    form = {
      name: a.name,
      severity: a.severity,
      keywords: a.keywords.join('\n'),
      examples: a.examples.join('\n'),
      embedding_threshold: a.embedding_threshold,
    };
    formError = '';
    showForm = true;
  }

  async function submitForm() {
    formError = '';
    if (!form.name.trim()) { formError = '이름 필수'; return; }
    saving = true;
    const body = {
      name: form.name.trim(),
      severity: form.severity,
      keywords: form.keywords.split('\n').map(s => s.trim()).filter(Boolean),
      examples: form.examples.split('\n').map(s => s.trim()).filter(Boolean),
      embedding_threshold: form.embedding_threshold,
    };
    try {
      if (editTarget) {
        await api.assets.update(editTarget.id, body);
        showToast('자산 수정됨');
      } else {
        await api.assets.create(body);
        showToast('자산 추가됨');
      }
      showForm = false;
      await load();
    } catch (e: unknown) {
      formError = (e as { message?: string })?.message ?? String(e);
    } finally { saving = false; }
  }

  async function deleteAsset(id: string, name: string) {
    if (!confirm(`'${name}' 자산을 삭제하시겠습니까?`)) return;
    await api.assets.delete(id);
    assets = assets.filter(a => a.id !== id);
    showToast('삭제됨');
  }

  async function resetDefaults() {
    const r = await api.assets.resetDefaults() as { added: number };
    showToast(`기본 자산 ${r.added}건 복원됨`);
    await load();
  }

  function showToast(msg: string) { toast = msg; setTimeout(() => toast = '', 2500); }

  const SEV_COLORS: Record<string, string> = {
    critical: 'border-red-500/30 bg-red-500/5',
    high:     'border-orange-500/30 bg-orange-500/5',
    medium:   'border-amber-500/30 bg-amber-500/5',
    low:      'border-slate-600 bg-slate-800/40',
  };

  onMount(load);
</script>

<div class="flex flex-col h-full overflow-auto p-6 gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-lg font-semibold text-slate-100">🛡 보호 자산 관리</h1>
    <div class="flex items-center gap-2">
      {#if toast}<span class="text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded px-3 py-1">{toast}</span>{/if}
      <button onclick={resetDefaults} class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm px-3 py-1.5 rounded transition-colors">기본값 복원</button>
      <button onclick={openCreate} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">+ 자산 추가</button>
    </div>
  </div>

  <!-- 모달 폼 -->
  {#if showForm}
    <div class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-600 rounded-xl w-full max-w-2xl p-6 space-y-4 overflow-auto max-h-[90vh]">
        <div class="flex items-center justify-between">
          <h2 class="text-slate-100 font-semibold">{editTarget ? '자산 수정' : '보호 자산 추가'}</h2>
          <button onclick={() => showForm = false} class="text-slate-500 hover:text-slate-300 text-xl">✕</button>
        </div>
        {#if formError}
          <div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded p-3">{formError}</div>
        {/if}
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div class="col-span-2">
            <label class="text-slate-400 block mb-1">자산 이름 <span class="text-red-400">*</span></label>
            <input bind:value={form.name} placeholder="예: GitHub 소스코드"
              class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500" />
          </div>
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
            <label class="text-slate-400 block mb-1">임베딩 임계값 ({form.embedding_threshold})</label>
            <input type="range" min="0.5" max="1.0" step="0.01"
              bind:value={form.embedding_threshold}
              class="w-full accent-blue-500 mt-2" />
            <div class="flex justify-between text-xs text-slate-600 mt-1"><span>0.5 (넓게)</span><span>1.0 (정확히)</span></div>
          </div>
          <div class="col-span-2">
            <label class="text-slate-400 block mb-1">키워드 <span class="text-slate-600">(한 줄에 하나씩)</span></label>
            <textarea bind:value={form.keywords} rows={4} placeholder=".ssh&#10;id_rsa&#10;authorized_keys"
              class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500 font-mono text-xs resize-none"></textarea>
          </div>
          <div class="col-span-2">
            <label class="text-slate-400 block mb-1">예시 문장 <span class="text-slate-600">(한 줄에 하나씩, 임베딩 유사도 학습용)</span></label>
            <textarea bind:value={form.examples} rows={4} placeholder="SSH 개인키를 전달드립니다&#10;id_rsa 파일을 첨부합니다"
              class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder:text-slate-500 text-xs resize-none"></textarea>
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

  <!-- 자산 그리드 -->
  {#if assets.length === 0}
    <div class="text-center py-20 text-slate-500">자산 없음 — "기본값 복원"으로 시드 자산 추가</div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {#each assets as a}
        <div class={`rounded-lg border p-4 flex flex-col gap-3 ${SEV_COLORS[a.severity] ?? 'border-slate-700 bg-slate-800'}`}>
          <div class="flex items-start justify-between gap-2">
            <div>
              <div class="text-slate-100 font-semibold text-sm">{a.name}</div>
              <div class="text-slate-500 text-xs font-mono mt-0.5">{a.id}</div>
            </div>
            <SevBadge severity={a.severity} />
          </div>

          <!-- 키워드 -->
          {#if a.keywords.length > 0}
            <div>
              <div class="text-xs text-slate-500 mb-1">키워드</div>
              <div class="flex flex-wrap gap-1">
                {#each a.keywords as kw}
                  <span class="text-xs bg-slate-700 text-slate-300 rounded px-2 py-0.5 font-mono">{kw}</span>
                {/each}
              </div>
            </div>
          {/if}

          <!-- 임계값 -->
          <div class="flex items-center gap-2 text-xs text-slate-500">
            <span>임베딩 임계값</span>
            <div class="flex-1 bg-slate-700 rounded-full h-1.5">
              <div class="h-1.5 rounded-full bg-blue-500" style={`width:${(a.embedding_threshold - 0.5) / 0.5 * 100}%`}></div>
            </div>
            <span class="text-slate-300 font-mono">{a.embedding_threshold}</span>
          </div>

          <!-- 예시 -->
          {#if a.examples.length > 0}
            <div class="text-xs text-slate-500 italic truncate">예: {a.examples[0]}</div>
          {/if}

          <div class="flex gap-2 mt-auto">
            <button onclick={() => openEdit(a)}
              class="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs py-1.5 rounded transition-colors">수정</button>
            <button onclick={() => deleteAsset(a.id, a.name)}
              class="flex-1 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 text-red-400 text-xs py-1.5 rounded transition-colors">삭제</button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
