import { e as ensure_array_like, b as attr_class, c as escape_html, f as attr_style } from "../../../chunks/renderer.js";
import { S as SevBadge } from "../../../chunks/SevBadge.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let assets = [];
    const SEV_COLORS = {
      critical: "border-red-500/30 bg-red-500/5",
      high: "border-orange-500/30 bg-orange-500/5",
      medium: "border-amber-500/30 bg-amber-500/5",
      low: "border-slate-600 bg-slate-800/40"
    };
    $$renderer2.push(`<div class="flex flex-col h-full overflow-auto p-6 gap-6"><div class="flex items-center justify-between"><h1 class="text-lg font-semibold text-slate-100">🛡 보호 자산 관리</h1> <div class="flex items-center gap-2">`);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <button class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm px-3 py-1.5 rounded transition-colors">기본값 복원</button> <button class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">+ 자산 추가</button></div></div> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (assets.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="text-center py-20 text-slate-500">자산 없음 — "기본값 복원"으로 시드 자산 추가</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"><!--[-->`);
      const each_array = ensure_array_like(assets);
      for (let $$index_1 = 0, $$length = each_array.length; $$index_1 < $$length; $$index_1++) {
        let a = each_array[$$index_1];
        $$renderer2.push(`<div${attr_class(`rounded-lg border p-4 flex flex-col gap-3 ${SEV_COLORS[a.severity] ?? "border-slate-700 bg-slate-800"}`)}><div class="flex items-start justify-between gap-2"><div><div class="text-slate-100 font-semibold text-sm">${escape_html(a.name)}</div> <div class="text-slate-500 text-xs font-mono mt-0.5">${escape_html(a.id)}</div></div> `);
        SevBadge($$renderer2, { severity: a.severity });
        $$renderer2.push(`<!----></div> `);
        if (a.keywords.length > 0) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<div><div class="text-xs text-slate-500 mb-1">키워드</div> <div class="flex flex-wrap gap-1"><!--[-->`);
          const each_array_1 = ensure_array_like(a.keywords);
          for (let $$index = 0, $$length2 = each_array_1.length; $$index < $$length2; $$index++) {
            let kw = each_array_1[$$index];
            $$renderer2.push(`<span class="text-xs bg-slate-700 text-slate-300 rounded px-2 py-0.5 font-mono">${escape_html(kw)}</span>`);
          }
          $$renderer2.push(`<!--]--></div></div>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--> <div class="flex items-center gap-2 text-xs text-slate-500"><span>임베딩 임계값</span> <div class="flex-1 bg-slate-700 rounded-full h-1.5"><div class="h-1.5 rounded-full bg-blue-500"${attr_style(`width:${(a.embedding_threshold - 0.5) / 0.5 * 100}%`)}></div></div> <span class="text-slate-300 font-mono">${escape_html(a.embedding_threshold)}</span></div> `);
        if (a.examples.length > 0) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<div class="text-xs text-slate-500 italic truncate">예: ${escape_html(a.examples[0])}</div>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--> <div class="flex gap-2 mt-auto"><button class="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs py-1.5 rounded transition-colors">수정</button> <button class="flex-1 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 text-red-400 text-xs py-1.5 rounded transition-colors">삭제</button></div></div>`);
      }
      $$renderer2.push(`<!--]--></div>`);
    }
    $$renderer2.push(`<!--]--></div>`);
  });
}
export {
  _page as default
};
