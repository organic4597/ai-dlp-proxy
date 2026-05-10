import { b as attr_class, c as escape_html } from "./renderer.js";
function SevBadge($$renderer, $$props) {
  const STYLES = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-amber-400",
    low: "text-slate-400"
  };
  let { severity = "medium" } = $$props;
  $$renderer.push(`<span${attr_class(`text-xs font-semibold uppercase ${STYLES[severity] ?? "text-slate-400"}`)}>${escape_html(severity)}</span>`);
}
export {
  SevBadge as S
};
