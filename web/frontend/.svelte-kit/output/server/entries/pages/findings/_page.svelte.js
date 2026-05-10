import { a as attr, e as ensure_array_like, c as escape_html, f as attr_style } from "../../../chunks/renderer.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let ruleStats = [];
    let filterRule = "";
    let filterSev = "";
    let filterStatus = "all";
    $$renderer2.push(`<div class="flex flex-col h-full"><div class="flex items-center justify-between px-6 py-4 border-b border-slate-700"><h1 class="text-lg font-semibold text-slate-100">🔍 탐지 목록</h1> <button class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button></div> <div class="flex items-center gap-3 px-6 py-3 border-b border-slate-800 text-sm"><input${attr("value", filterRule)} placeholder="규칙 검색…" class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm w-40"/> `);
    $$renderer2.select(
      {
        value: filterSev,
        class: "bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`심각도 전체`);
        });
        $$renderer3.option({ value: "critical" }, ($$renderer4) => {
          $$renderer4.push(`CRITICAL`);
        });
        $$renderer3.option({ value: "high" }, ($$renderer4) => {
          $$renderer4.push(`HIGH`);
        });
        $$renderer3.option({ value: "medium" }, ($$renderer4) => {
          $$renderer4.push(`MEDIUM`);
        });
        $$renderer3.option({ value: "low" }, ($$renderer4) => {
          $$renderer4.push(`LOW`);
        });
      }
    );
    $$renderer2.push(` `);
    $$renderer2.select(
      {
        value: filterStatus,
        class: "bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "all" }, ($$renderer4) => {
          $$renderer4.push(`전체`);
        });
        $$renderer3.option({ value: "effective" }, ($$renderer4) => {
          $$renderer4.push(`정책 대상(유효)`);
        });
        $$renderer3.option({ value: "suppressed" }, ($$renderer4) => {
          $$renderer4.push(`정책 제외(억제)`);
        });
        $$renderer3.option({ value: "below_threshold" }, ($$renderer4) => {
          $$renderer4.push(`신뢰도 미달`);
        });
      }
    );
    $$renderer2.push(` <button class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">검색</button></div> <div class="flex flex-1 overflow-hidden"><div class="flex-1 overflow-auto">`);
    {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="flex items-center justify-center h-40 text-slate-500">로딩 중…</div>`);
    }
    $$renderer2.push(`<!--]--></div> <div class="w-64 border-l border-slate-700 overflow-auto shrink-0 p-4"><div class="text-xs text-slate-500 uppercase mb-3">룰별 통계</div> <!--[-->`);
    const each_array_1 = ensure_array_like(ruleStats);
    for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
      let s = each_array_1[$$index_1];
      $$renderer2.push(`<div class="mb-3 bg-slate-800 rounded p-3 text-xs space-y-1"><div class="text-slate-200 font-medium truncate">${escape_html(s.rule)}</div> <div class="flex justify-between text-slate-500"><span>총 탐지</span><span class="text-slate-300">${escape_html(s.total)}</span></div> <div class="flex justify-between text-slate-500"><span>유효</span><span class="text-green-400">${escape_html(s.effective)}</span></div> <div class="flex justify-between text-slate-500"><span>억제</span><span class="text-amber-400">${escape_html(s.suppressed_count)}</span></div> <div class="flex justify-between text-slate-500"><span>평균 신뢰도</span><span class="text-slate-300">${escape_html(s.avg_confidence?.toFixed(2))}</span></div> <div class="w-full bg-slate-700 rounded-full h-1.5 mt-1"><div class="bg-amber-500 h-1.5 rounded-full"${attr_style(`width: ${s.total > 0 ? Math.round(s.suppressed_count / s.total * 100) : 0}%`)}></div></div></div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div>`);
  });
}
export {
  _page as default
};
