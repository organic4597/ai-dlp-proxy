import "clsx";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    $$renderer2.push(`<div class="p-6 flex flex-col gap-6"><div class="flex items-center justify-between"><h1 class="text-lg font-semibold text-slate-100">🖥 프로세스 상태</h1> <button class="bg-slate-700 hover:bg-slate-600 text-sm px-3 py-1.5 rounded text-slate-200 transition-colors">새로고침</button></div> `);
    {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="text-slate-500 text-sm">로딩 중…</div>`);
    }
    $$renderer2.push(`<!--]--></div>`);
  });
}
export {
  _page as default
};
