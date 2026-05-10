import { c as escape_html, e as ensure_array_like, b as attr_class } from "../../../chunks/renderer.js";
import { S as SevBadge } from "../../../chunks/SevBadge.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let builtins = [];
    let customs = [];
    $$renderer2.push(`<div class="flex flex-col h-full overflow-auto p-6 gap-6"><div class="flex items-center justify-between"><h1 class="text-lg font-semibold text-slate-100">📏 탐지 룰 관리</h1> <div class="flex items-center gap-2">`);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <button class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">+ 커스텀 룰 추가</button></div></div> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (customs.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden"><div class="px-4 py-3 border-b border-slate-700 flex items-center gap-2"><span class="text-sm font-semibold text-slate-200">커스텀 룰</span> <span class="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full">${escape_html(customs.length)}</span></div> <table class="w-full text-sm"><thead><tr class="text-xs text-slate-500 border-b border-slate-700 uppercase"><th class="px-4 py-2 text-left">이름</th><th class="px-4 py-2 text-left">패턴</th><th class="px-4 py-2 text-left">심각도</th><th class="px-4 py-2 text-left">설명</th><th class="px-4 py-2 text-center">활성</th><th class="px-4 py-2 text-right">작업</th></tr></thead><tbody><!--[-->`);
      const each_array = ensure_array_like(customs);
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let r = each_array[$$index];
        $$renderer2.push(`<tr${attr_class(`border-b border-slate-800 ${r.enabled ? "" : "opacity-50"}`)}><td class="px-4 py-2 text-slate-200 font-mono text-xs">${escape_html(r.name)}</td><td class="px-4 py-2 text-slate-400 font-mono text-xs max-w-48 truncate">${escape_html(r.pattern)}</td><td class="px-4 py-2">`);
        SevBadge($$renderer2, { severity: r.severity });
        $$renderer2.push(`<!----></td><td class="px-4 py-2 text-slate-400 text-xs">${escape_html(r.description || "—")}</td><td class="px-4 py-2 text-center"><button${attr_class(`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? "bg-blue-500" : "bg-slate-600"}`)}><span${attr_class(`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? "left-5" : "left-0.5"}`)}></span></button></td><td class="px-4 py-2 text-right flex items-center gap-2 justify-end"><button class="text-blue-400 hover:text-blue-300 text-xs">수정</button> <button class="text-red-400 hover:text-red-300 text-xs">삭제</button></td></tr>`);
      }
      $$renderer2.push(`<!--]--></tbody></table></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <div class="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden"><div class="px-4 py-3 border-b border-slate-700"><span class="text-sm font-semibold text-slate-200">내장 룰</span> <span class="text-xs text-slate-500 ml-2">활성화/비활성화 가능 (패턴은 변경 불가)</span></div> <table class="w-full text-sm"><thead><tr class="text-xs text-slate-500 border-b border-slate-700 uppercase"><th class="px-4 py-2 text-left">이름</th><th class="px-4 py-2 text-left">설명</th><th class="px-4 py-2 text-left">심각도</th><th class="px-4 py-2 text-center">활성</th></tr></thead><tbody><!--[-->`);
    const each_array_1 = ensure_array_like(builtins);
    for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
      let r = each_array_1[$$index_1];
      $$renderer2.push(`<tr${attr_class(`border-b border-slate-800 ${r.enabled ? "" : "opacity-50"}`)}><td class="px-4 py-2 text-slate-300 font-mono text-xs">${escape_html(r.name)}</td><td class="px-4 py-2 text-slate-400 text-xs">${escape_html(r.description)}</td><td class="px-4 py-2">`);
      SevBadge($$renderer2, { severity: r.severity });
      $$renderer2.push(`<!----></td><td class="px-4 py-2 text-center"><button${attr_class(`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? "bg-blue-500" : "bg-slate-600"}`)}><span${attr_class(`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? "left-5" : "left-0.5"}`)}></span></button></td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table></div></div>`);
  });
}
export {
  _page as default
};
