import { g as getContext, e as ensure_array_like, s as store_get, a as attr, b as attr_class, c as escape_html, u as unsubscribe_stores } from "../../chunks/renderer.js";
import { s as sse } from "../../chunks/events.svelte.js";
import "clsx";
import "@sveltejs/kit/internal";
import "../../chunks/exports.js";
import "../../chunks/utils.js";
import "@sveltejs/kit/internal/server";
import "../../chunks/root.js";
import "../../chunks/state.svelte.js";
const getStores = () => {
  const stores$1 = getContext("__svelte__");
  return {
    /** @type {typeof page} */
    page: {
      subscribe: stores$1.page.subscribe
    },
    /** @type {typeof navigating} */
    navigating: {
      subscribe: stores$1.navigating.subscribe
    },
    /** @type {typeof updated} */
    updated: stores$1.updated
  };
};
const page = {
  subscribe(fn) {
    const store = getStores().page;
    return store.subscribe(fn);
  }
};
function _layout($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    var $$store_subs;
    const { children } = $$props;
    const navItems = [
      { href: "/traffic", icon: "📡", label: "트래픽" },
      { href: "/findings", icon: "🔍", label: "탐지 목록" },
      { href: "/pipeline", icon: "🔗", label: "파이프라인" },
      { href: "/settings", icon: "⚙️", label: "제어 & 설정" },
      { href: "/rules", icon: "📏", label: "탐지 룰" },
      { href: "/assets", icon: "🛡", label: "보호 자산" },
      { href: "/allowlist", icon: "✅", label: "허용목록" },
      { href: "/audit", icon: "📋", label: "감사 로그" },
      { href: "/logs", icon: "📜", label: "엔진 로그" },
      { href: "/process", icon: "🖥", label: "프로세스" }
    ];
    $$renderer2.push(`<div class="flex h-screen overflow-hidden bg-[#0f172a] text-slate-200"><aside class="w-52 shrink-0 flex flex-col border-r border-slate-700 bg-slate-900"><div class="h-14 flex items-center px-4 border-b border-slate-700"><span class="text-sm font-bold text-blue-400 tracking-tight">🛡 AI-DLP</span> <span class="ml-1 text-sm font-bold text-slate-200">Dashboard</span></div> <nav class="flex-1 py-2 overflow-y-auto"><!--[-->`);
    const each_array = ensure_array_like(navItems);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let item = each_array[$$index];
      const active = store_get($$store_subs ??= {}, "$page", page).url.pathname.startsWith(item.href);
      $$renderer2.push(`<a${attr("href", item.href)}${attr_class(`flex items-center gap-3 px-4 py-2.5 text-sm transition-colors
            ${active ? "bg-blue-500/15 text-blue-400 border-r-2 border-blue-500" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`)}><span class="text-base w-5 text-center">${escape_html(item.icon)}</span> <span>${escape_html(item.label)}</span></a>`);
    }
    $$renderer2.push(`<!--]--></nav> <div class="p-3 border-t border-slate-700"><div class="flex items-center gap-2 text-xs"><span${attr_class(`w-2 h-2 rounded-full ${sse.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`)}></span> <span class="text-slate-500">${escape_html(sse.connected ? "실시간 연결됨" : "연결 끊김")}</span></div></div></aside> <main class="flex-1 overflow-auto">`);
    children($$renderer2);
    $$renderer2.push(`<!----></main></div>`);
    if ($$store_subs) unsubscribe_stores($$store_subs);
  });
}
export {
  _layout as default
};
