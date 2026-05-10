import { c as escape_html, b as attr_class, a as attr } from "../../../chunks/renderer.js";
import { o as onDestroy } from "../../../chunks/index-server.js";
import { s as sse } from "../../../chunks/events.svelte.js";
function StatsCard($$renderer, $$props) {
  let { title = "", value = "", sub = "", accent = false, color = "" } = $$props;
  $$renderer.push(`<div class="bg-slate-800 border border-slate-700 rounded-lg p-4 flex flex-col gap-1"><div class="text-xs text-slate-400 uppercase tracking-wide">${escape_html(title)}</div> <div${attr_class(`text-2xl font-bold ${color || (accent ? "text-blue-400" : "text-slate-100")}`)}>${escape_html(value)}</div> `);
  if (sub) {
    $$renderer.push("<!--[0-->");
    $$renderer.push(`<div class="text-xs text-slate-500">${escape_html(sub)}</div>`);
  } else {
    $$renderer.push("<!--[-1-->");
  }
  $$renderer.push(`<!--]--></div>`);
}
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let rows = [];
    let summary = {};
    let filterAction = "all";
    let autoScroll = true;
    function rowKey(row) {
      return String(row.request_id ?? row.id);
    }
    const unsub = sse.on("scan_result", (ev) => {
      const e = ev;
      const normalized = { ...e, request_id: String(e.request_id ?? e.id) };
      rows = [
        normalized,
        ...rows.filter((r) => rowKey(r) !== rowKey(normalized)).slice(0, 498)
      ];
      summary = {
        ...summary,
        total: (summary.total ?? 0) + 1,
        [`${e.pipeline_action}_count`]: (summary[`${e.pipeline_action}_count`] ?? 0) + 1,
        total_findings: (summary.total_findings ?? 0) + (e.raw_finding_count ?? 0)
      };
    });
    onDestroy(unsub);
    $$renderer2.push(`<div class="flex flex-col h-full"><div class="flex items-center justify-between px-6 py-4 border-b border-slate-700"><h1 class="text-lg font-semibold text-slate-100">📡 실시간 트래픽</h1> <div class="flex items-center gap-3">`);
    $$renderer2.select(
      {
        value: filterAction,
        class: "bg-slate-800 border border-slate-600 text-slate-200 text-sm rounded px-3 py-1.5"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "all" }, ($$renderer4) => {
          $$renderer4.push(`전체`);
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
    $$renderer2.push(` <label class="flex items-center gap-2 text-xs text-slate-400 cursor-pointer"><input type="checkbox"${attr("checked", autoScroll, true)} class="accent-blue-500"/> 자동 스크롤</label> <button class="bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm px-3 py-1.5 rounded transition-colors">새로고침</button></div></div> <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 px-6 py-4">`);
    StatsCard($$renderer2, { title: "총 스캔", value: summary.total ?? 0 });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "PASS",
      value: summary.pass_count ?? 0,
      color: "text-green-400"
    });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "ALERT",
      value: summary.alert_count ?? 0,
      color: "text-amber-400"
    });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "MASK",
      value: summary.mask_count ?? 0,
      color: "text-orange-400"
    });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "BLOCK",
      value: summary.block_count ?? 0,
      color: "text-red-400"
    });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "탐지 수",
      value: summary.total_findings ?? 0,
      color: "text-blue-400"
    });
    $$renderer2.push(`<!----> `);
    StatsCard($$renderer2, {
      title: "평균 응답",
      value: summary.avg_elapsed_ms ? `${Math.round(summary.avg_elapsed_ms)}ms` : "—"
    });
    $$renderer2.push(`<!----></div> <div class="flex flex-1 overflow-hidden gap-0"><div${attr_class(`flex flex-col overflow-hidden transition-all ${"w-full"}`)}>`);
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
