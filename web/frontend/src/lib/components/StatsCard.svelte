<script lang="ts">
  let {
    title   = '',
    value   = '',
    sub     = '',
    accent  = false,
    color   = '',
  }: { title: string; value: string | number; sub?: string; accent?: boolean; color?: string } = $props();
</script>

<div class="bg-slate-800 border border-slate-700 rounded-lg p-4 flex flex-col gap-1">
  <div class="text-xs text-slate-400 uppercase tracking-wide">{title}</div>
  <div class={`text-2xl font-bold ${color || (accent ? 'text-blue-400' : 'text-slate-100')}`}>
    {value}
  </div>
  {#if sub}
    <div class="text-xs text-slate-500">{sub}</div>
  {/if}
</div>
