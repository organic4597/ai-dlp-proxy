<script lang="ts">
  import '../app.css';
  import { sse } from '$lib/stores/events.svelte';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';

  const { children } = $props();

  onMount(() => { sse.connect(); });

  const navItems = [
    { href: '/traffic',   icon: '📡', label: '트래픽' },
    { href: '/findings',  icon: '🔍', label: '탐지 목록' },
    { href: '/pipeline',  icon: '🔗', label: '파이프라인' },
    { href: '/settings',  icon: '⚙️',  label: '제어 & 설정' },
    { href: '/rules',     icon: '📏', label: '탐지 룰' },
    { href: '/assets',    icon: '🛡',  label: '보호 자산' },
    { href: '/allowlist', icon: '✅', label: '허용목록' },
    { href: '/audit',     icon: '📋', label: '감사 로그' },
    { href: '/logs',      icon: '📜', label: '엔진 로그' },
    { href: '/process',   icon: '🖥',  label: '프로세스' },
  ];
</script>

<div class="flex h-screen overflow-hidden bg-[#0f172a] text-slate-200">
  <!-- 사이드바 -->
  <aside class="w-52 shrink-0 flex flex-col border-r border-slate-700 bg-slate-900">
    <!-- 로고 -->
    <div class="h-14 flex items-center px-4 border-b border-slate-700">
      <span class="text-sm font-bold text-blue-400 tracking-tight">🛡 AI-DLP</span>
      <span class="ml-1 text-sm font-bold text-slate-200">Dashboard</span>
    </div>
    <!-- 네비게이션 -->
    <nav class="flex-1 py-2 overflow-y-auto">
      {#each navItems as item}
        {@const active = $page.url.pathname.startsWith(item.href)}
        <a
          href={item.href}
          class={`flex items-center gap-3 px-4 py-2.5 text-sm transition-colors
            ${active
              ? 'bg-blue-500/15 text-blue-400 border-r-2 border-blue-500'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
        >
          <span class="text-base w-5 text-center">{item.icon}</span>
          <span>{item.label}</span>
        </a>
      {/each}
    </nav>
    <!-- SSE 상태 -->
    <div class="p-3 border-t border-slate-700">
      <div class="flex items-center gap-2 text-xs">
        <span class={`w-2 h-2 rounded-full ${sse.connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></span>
        <span class="text-slate-500">{sse.connected ? '실시간 연결됨' : '연결 끊김'}</span>
      </div>
    </div>
  </aside>

  <!-- 메인 콘텐츠 -->
  <main class="flex-1 overflow-auto">
    {@render children()}
  </main>
</div>
