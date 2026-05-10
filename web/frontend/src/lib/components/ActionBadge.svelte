<script lang="ts">
  const STYLES: Record<string, string> = {
    pass:  'bg-green-500/20 text-green-400 border border-green-500/30',
    alert: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    mask:  'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    block: 'bg-red-500/20 text-red-400 border border-red-500/30',
  };
  const LABELS: Record<string, string> = {
    pass: 'PASS', alert: 'ALERT', mask: 'MASK', block: 'BLOCK',
  };
  let { action = 'pass' }: { action: string } = $props();
</script>

<span class={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide ${STYLES[action] ?? 'bg-slate-700 text-slate-300'}`}>
  {LABELS[action] ?? action.toUpperCase()}
</span>
