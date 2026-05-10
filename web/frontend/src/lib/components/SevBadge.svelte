<script lang="ts">
  const STYLES: Record<string, string> = {
    critical: 'text-red-400',
    high:     'text-orange-400',
    medium:   'text-amber-400',
    low:      'text-slate-400',
  };
  let { severity = 'medium' }: { severity: string } = $props();
</script>
<span class={`text-xs font-semibold uppercase ${STYLES[severity] ?? 'text-slate-400'}`}>
  {severity}
</span>
