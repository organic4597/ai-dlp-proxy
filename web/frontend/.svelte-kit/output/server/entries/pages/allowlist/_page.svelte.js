import { a as attr, c as escape_html, e as ensure_array_like, b as attr_class } from "../../../chunks/renderer.js";
import { a as api } from "../../../chunks/api.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let entries = [];
    let filterRule = "";
    let showExpired = "active";
    let saving = false;
    let newRule = "*";
    let newValue = "";
    let newExpiry = "";
    let templates = {};
    let templateSaving = false;
    let newTplKey = "";
    let newTplVal = "";
    async function load() {
      const p = {};
      p.expired = "false";
      entries = await api.allowlist.list(p);
    }
    function fmtDate(s) {
      return s ? s.slice(0, 10) : "—";
    }
    $$renderer2.push(`<div class="flex flex-col h-full overflow-auto p-6 gap-6"><div class="flex items-center justify-between"><h1 class="text-lg font-semibold text-slate-100">✅ 허용목록 &amp; 마스킹 템플릿</h1> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> <div class="grid grid-cols-1 xl:grid-cols-2 gap-6"><div class="flex flex-col gap-4"><div class="bg-slate-800 border border-slate-700 rounded-lg p-5 space-y-4"><div class="flex items-center justify-between"><span class="text-sm font-semibold text-slate-200">허용목록 (Allowlist)</span> <button class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 rounded px-3 py-1 transition-colors">만료 항목 삭제</button></div> <div class="flex gap-2 text-sm"><input${attr("value", filterRule)} placeholder="규칙 필터 (예: kr_rrn)" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 flex-1 text-sm"/> `);
    $$renderer2.select(
      {
        value: showExpired,
        onchange: load,
        class: "bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "active" }, ($$renderer4) => {
          $$renderer4.push(`유효만`);
        });
        $$renderer3.option({ value: "expired" }, ($$renderer4) => {
          $$renderer4.push(`만료만`);
        });
        $$renderer3.option({ value: "all" }, ($$renderer4) => {
          $$renderer4.push(`전체`);
        });
      }
    );
    $$renderer2.push(` <button class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors">검색</button></div> <div class="border border-dashed border-slate-600 rounded-lg p-3 space-y-2"><div class="text-xs text-slate-500 mb-2">항목 추가</div> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <div class="grid grid-cols-2 gap-2"><input${attr("value", newRule)} placeholder="규칙 (* = 전체)" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm"/> <input${attr("value", newValue)} placeholder="허용할 값 (정확히 일치)" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm"/></div> <div class="flex gap-2"><div class="flex-1"><label class="text-xs text-slate-500 block mb-1">만료일 (선택)</label> <input type="datetime-local"${attr("value", newExpiry)} class="w-full bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"/></div> <button${attr("disabled", saving, true)} class="self-end bg-green-600 hover:bg-green-500 text-white text-sm px-4 py-1.5 rounded transition-colors disabled:opacity-50 whitespace-nowrap">${escape_html("추가")}</button></div></div> <div class="space-y-2 max-h-96 overflow-auto">`);
    const each_array = ensure_array_like(entries);
    if (each_array.length !== 0) {
      $$renderer2.push("<!--[-->");
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let e = each_array[$$index];
        $$renderer2.push(`<div${attr_class(`flex items-center gap-3 rounded-lg px-3 py-2 border text-xs
              ${e._expired ? "border-red-500/20 bg-red-500/5 opacity-60" : "border-slate-700 bg-slate-900/40"}`)}><div class="flex-1 min-w-0"><div class="flex items-center gap-2"><span class="text-slate-500 shrink-0">${escape_html(e.rule)}</span> <span class="text-slate-300 font-mono truncate">${escape_html(e.value)}</span> `);
        if (e._expired) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<span class="text-red-400 shrink-0">만료됨</span>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--></div> <div class="text-slate-600 mt-0.5">추가: ${escape_html(fmtDate(e.added_at))} `);
        if (e.expires_at) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`· 만료: ${escape_html(fmtDate(e.expires_at))}`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--></div></div> <button class="text-red-400 hover:text-red-300 shrink-0 text-sm">✕</button></div>`);
      }
    } else {
      $$renderer2.push("<!--[!-->");
      $$renderer2.push(`<div class="text-center py-8 text-slate-600">허용목록 없음</div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div> <div class="bg-slate-800 border border-slate-700 rounded-lg p-5 flex flex-col gap-4"><div class="flex items-center justify-between"><span class="text-sm font-semibold text-slate-200">마스킹 템플릿</span> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> <div class="text-xs text-slate-500">탐지된 PII를 대체할 플레이스홀더 문자열을 룰별로 지정합니다.</div> <div class="flex gap-2 text-sm"><input${attr("value", newTplKey)} placeholder="룰 이름 (예: kr_rrn)" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 w-36 text-xs font-mono"/> <input${attr("value", newTplVal)} placeholder="플레이스홀더 (예: [주민번호])" class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 flex-1 text-xs"/> <button${attr("disabled", templateSaving, true)} class="bg-blue-600 hover:bg-blue-500 text-white text-xs px-3 py-1.5 rounded transition-colors disabled:opacity-50 whitespace-nowrap">추가</button></div> <div class="space-y-1.5 overflow-auto flex-1">`);
    const each_array_1 = ensure_array_like(Object.entries(templates));
    if (each_array_1.length !== 0) {
      $$renderer2.push("<!--[-->");
      for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
        let [key, val] = each_array_1[$$index_1];
        $$renderer2.push(`<div class="flex items-center gap-2 group"><span class="text-slate-500 font-mono text-xs w-36 shrink-0 truncate">${escape_html(key)}</span> <input${attr("value", val)} class="flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-slate-200 text-xs font-mono"/> <button class="text-red-400 hover:text-red-300 text-xs opacity-0 group-hover:opacity-100 transition-opacity">✕</button></div>`);
      }
    } else {
      $$renderer2.push("<!--[!-->");
      $$renderer2.push(`<div class="text-center py-6 text-slate-600 text-sm">템플릿 없음 (기본값 사용 중)</div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div></div>`);
  });
}
export {
  _page as default
};
