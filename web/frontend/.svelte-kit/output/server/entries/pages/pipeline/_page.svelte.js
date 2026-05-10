import { e as ensure_array_like, b as attr_class, c as escape_html, f as attr_style, ab as clsx, ac as stringify } from "../../../chunks/renderer.js";
import { o as onDestroy } from "../../../chunks/index-server.js";
import { a as api } from "../../../chunks/api.js";
import { s as sse } from "../../../chunks/events.svelte.js";
import { Chart, registerables } from "chart.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    Chart.register(...registerables);
    let stats = null;
    let ctrl = null;
    let snapshots = [];
    let rangeH = 1;
    async function load() {
      const [s, c, snaps] = await Promise.all([
        api.pipeline.stats(),
        api.control.get(),
        api.pipeline.snapshots(rangeH)
      ]);
      stats = s;
      ctrl = c;
      snapshots = snaps;
    }
    const unsub = sse.on("scan_result", () => load());
    function pct(a, b) {
      return a + b > 0 ? Math.round(a / (a + b) * 100) : 0;
    }
    onDestroy(() => {
      unsub();
    });
    $$renderer2.push(`<div class="flex flex-col h-full p-6 gap-6 overflow-auto"><div class="flex items-center justify-between"><h1 class="text-lg font-semibold text-slate-100">🔗 파이프라인</h1> <div class="flex items-center gap-2">`);
    $$renderer2.select(
      {
        value: rangeH,
        onchange: load,
        class: "bg-slate-800 border border-slate-600 text-slate-200 text-sm rounded px-3 py-1.5"
      },
      ($$renderer3) => {
        $$renderer3.option({ value: 1 }, ($$renderer4) => {
          $$renderer4.push(`1시간`);
        });
        $$renderer3.option({ value: 6 }, ($$renderer4) => {
          $$renderer4.push(`6시간`);
        });
        $$renderer3.option({ value: 24 }, ($$renderer4) => {
          $$renderer4.push(`24시간`);
        });
        $$renderer3.option({ value: 168 }, ($$renderer4) => {
          $$renderer4.push(`7일`);
        });
      }
    );
    $$renderer2.push(` <button class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button></div></div> <div class="grid grid-cols-1 lg:grid-cols-3 gap-6"><div class="lg:col-span-2 bg-slate-800 border border-slate-700 rounded-lg p-5"><div class="text-xs text-slate-500 uppercase mb-4">파이프라인 플로우</div> <div class="flex flex-col items-center gap-0 text-sm"><div class="text-slate-400 text-xs mb-1">LLM API 요청</div> <div class="w-px h-4 bg-slate-600"></div> <!--[-->`);
    const each_array = ensure_array_like([
      {
        icon: "🔍",
        name: "RegexStage",
        on: ctrl?.regex_enabled ?? true,
        color: "blue"
      },
      {
        icon: "🤖",
        name: `ML FP Filter (thr=${ctrl?.ml_filter_threshold?.toFixed(2) ?? "0.40"})`,
        on: ctrl?.ml_filter_enabled ?? false,
        color: "purple"
      }
    ]);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let stage = each_array[$$index];
      $$renderer2.push(`<div${attr_class(`w-full max-w-sm rounded-lg border px-4 py-2.5 flex items-center justify-between
            ${stage.on ? "border-blue-500/40 bg-blue-500/5" : "border-slate-600 bg-slate-900/40 opacity-60"}`)}><span class="font-medium text-slate-200">${escape_html(stage.icon)} ${escape_html(stage.name)}</span> <span${attr_class(`text-xs font-semibold ${stage.on ? "text-green-400" : "text-slate-500"}`)}>${escape_html(stage.on ? "ON" : "OFF")}</span></div> <div class="w-px h-3 bg-slate-600"></div>`);
    }
    $$renderer2.push(`<!--]--> <div class="w-full max-w-sm border border-dashed border-amber-500/30 rounded px-3 py-1.5 text-center text-xs text-amber-400/70">✂ NMS 중첩제거</div> <div class="w-px h-3 bg-slate-600"></div> <!--[-->`);
    const each_array_1 = ensure_array_like([
      {
        icon: "🛡",
        name: "AssetStage",
        on: ctrl?.asset_enabled ?? true
      },
      {
        icon: "🔬",
        name: "SLM Stage (Gemma 4 2B)",
        on: ctrl?.slm_enabled ?? false
      }
    ]);
    for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
      let stage = each_array_1[$$index_1];
      $$renderer2.push(`<div${attr_class(`w-full max-w-sm rounded-lg border px-4 py-2.5 flex items-center justify-between
            ${stage.on ? "border-blue-500/40 bg-blue-500/5" : "border-slate-600 bg-slate-900/40 opacity-60"}`)}><span class="font-medium text-slate-200">${escape_html(stage.icon)} ${escape_html(stage.name)}</span> <span${attr_class(`text-xs font-semibold ${stage.on ? "text-green-400" : "text-slate-500"}`)}>${escape_html(stage.on ? "ON" : "OFF")}</span></div> <div class="w-px h-3 bg-slate-600"></div>`);
    }
    $$renderer2.push(`<!--]--> <div class="w-full max-w-sm rounded-lg border border-slate-600 bg-slate-900/60 px-4 py-2.5 text-center text-slate-300 text-xs">⚖ decide_action  threshold=${escape_html(ctrl?.confidence_threshold?.toFixed(2) ?? "0.50")}</div></div></div> <div class="flex flex-col gap-4"><div class="bg-slate-800 border border-slate-700 rounded-lg p-4"><div class="text-xs text-slate-500 uppercase mb-3">엔진 캐시</div> `);
    if (stats?.cache) {
      $$renderer2.push("<!--[0-->");
      const c = stats.cache;
      const rate = pct(c.hits, c.misses);
      $$renderer2.push(`<div class="flex items-center gap-4 mb-2"><div${attr_class(`text-3xl font-bold ${stringify(rate >= 80 ? "text-green-400" : rate >= 50 ? "text-amber-400" : "text-slate-400")}`)}>${escape_html(rate)}%</div> <div class="text-xs text-slate-500 space-y-0.5"><div>히트: <span class="text-slate-300">${escape_html(c.hits)}</span></div> <div>미스: <span class="text-slate-300">${escape_html(c.misses)}</span></div> <div>크기: <span class="text-slate-300">${escape_html(c.size)}건</span></div></div></div> <div class="w-full bg-slate-700 rounded-full h-2"><div${attr_class(`h-2 rounded-full ${stringify(rate >= 80 ? "bg-green-500" : rate >= 50 ? "bg-amber-500" : "bg-slate-500")}`)}${attr_style(`width: ${rate}%`)}></div></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="text-slate-600 text-xs">데이터 없음</div>`);
    }
    $$renderer2.push(`<!--]--></div> <div class="bg-slate-800 border border-slate-700 rounded-lg p-4"><div class="text-xs text-slate-500 uppercase mb-3">SLM 추론 통계</div> `);
    if (stats?.slm?.total_calls) {
      $$renderer2.push("<!--[0-->");
      const s = stats.slm;
      $$renderer2.push(`<div class="space-y-1.5 text-xs"><div class="flex justify-between"><span class="text-slate-500">추론 횟수</span><span class="text-slate-200">${escape_html(s.total_calls)}회</span></div> <div class="flex justify-between"><span class="text-slate-500">탐지 건수</span><span class="text-slate-200">${escape_html(s.total_findings)}건</span></div> <div class="flex justify-between"><span class="text-slate-500">평균 응답</span> <span${attr_class(clsx(s.avg_ms < 500 ? "text-green-400" : s.avg_ms < 3e3 ? "text-amber-400" : "text-red-400"))}>${escape_html(s.avg_ms)}ms</span></div> <div class="flex justify-between"><span class="text-slate-500">p95 응답</span><span class="text-slate-400">${escape_html(s.p95_ms)}ms</span></div> `);
      if (s.errors > 0) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<div class="flex justify-between"><span class="text-slate-500">오류</span><span class="text-red-400">${escape_html(s.errors)}건</span></div>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="text-slate-600 text-xs">SLM 추론 기록 없음</div>`);
    }
    $$renderer2.push(`<!--]--></div> <div class="bg-slate-800 border border-slate-700 rounded-lg p-4"><div class="text-xs text-slate-500 uppercase mb-3">Suppress 분류</div> `);
    if (stats) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="space-y-2 text-xs"><!--[-->`);
      const each_array_2 = ensure_array_like([
        {
          label: "NMS 중첩제거",
          key: "nms_suppressed",
          color: "text-amber-400"
        },
        {
          label: "ML FP 필터",
          key: "ml_suppressed",
          color: "text-purple-400"
        },
        { label: "허용목록", key: "al_suppressed", color: "text-green-400" }
      ]);
      for (let $$index_2 = 0, $$length = each_array_2.length; $$index_2 < $$length; $$index_2++) {
        let item = each_array_2[$$index_2];
        $$renderer2.push(`<div class="flex justify-between items-center"><span class="text-slate-500">${escape_html(item.label)}</span> <span${attr_class(clsx(item.color))}>${escape_html(stats[item.key] ?? 0)}건</span></div>`);
      }
      $$renderer2.push(`<!--]--></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="text-slate-600 text-xs">데이터 없음</div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div> <div class="bg-slate-800 border border-slate-700 rounded-lg p-5"><div class="text-xs text-slate-500 uppercase mb-4">액션별 요청 추이 (최근 ${escape_html(rangeH)}시간)</div> <div class="h-48">`);
    if (snapshots.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<canvas></canvas>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="flex items-center justify-center h-full text-slate-600 text-sm">스냅샷 데이터 없음 (엔진 가동 후 수집 시작)</div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div>`);
  });
}
export {
  _page as default
};
