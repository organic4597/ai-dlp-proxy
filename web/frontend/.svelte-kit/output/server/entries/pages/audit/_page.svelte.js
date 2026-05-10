import { a as attr, c as escape_html, b as attr_class } from "../../../chunks/renderer.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let filterAction = "";
    let filterRule = "";
    let dateFrom = "";
    let dateTo = "";
    let exportLoading = false;
    $$renderer2.push(`<div class="flex flex-col h-full"><div class="flex items-center justify-between px-6 py-4 border-b border-slate-700"><h1 class="text-lg font-semibold text-slate-100">📋 감사 로그</h1> <div class="flex items-center gap-2">`);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <button class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs px-3 py-1.5 rounded transition-colors">JSONL 마이그레이션</button> <button${attr("disabled", exportLoading, true)} class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded transition-colors disabled:opacity-50">${escape_html("CSV 내보내기")}</button></div></div> <div class="flex flex-wrap items-center gap-3 px-6 py-3 border-b border-slate-800 text-sm">`);
    $$renderer2.select(
      {
        value: filterAction,
        class: "bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`액션 전체`);
        });
        $$renderer3.option({ value: "pass" }, ($$renderer4) => {
          $$renderer4.push(`PASS`);
        });
        $$renderer3.option({ value: "alert" }, ($$renderer4) => {
          $$renderer4.push(`ALERT`);
        });
        $$renderer3.option({ value: "mask" }, ($$renderer4) => {
          $$renderer4.push(`MASK`);
        });
        $$renderer3.option({ value: "block" }, ($$renderer4) => {
          $$renderer4.push(`BLOCK`);
        });
      }
    );
    $$renderer2.push(` <input${attr("value", filterRule)} placeholder="규칙 검색…" class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 placeholder:text-slate-500 text-sm w-36"/> <input type="date"${attr("value", dateFrom)} class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"/> <span class="text-slate-600">~</span> <input type="date"${attr("value", dateTo)} class="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-slate-200 text-sm"/> <button class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-1.5 rounded transition-colors">검색</button></div> <div class="flex flex-1 overflow-hidden"><div${attr_class(`flex-1 overflow-auto transition-all ${""}`)}>`);
    {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="flex items-center justify-center h-40 text-slate-500">로딩 중…</div>`);
    }
    $$renderer2.push(`<!--]--></div> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></div>`);
  });
}
export {
  _page as default
};
