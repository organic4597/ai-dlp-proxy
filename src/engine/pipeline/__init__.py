"""
DLP Pipeline — 스테이지를 순차 실행하는 러너.

메시지 해시 캐시:
  AI Agent는 매 턴마다 이전 대화를 포함하여 전송하므로
  동일 메시지를 반복 스캔하지 않도록 (role+content) 해시 기반 캐시 적용.
  캐시 히트 시 이전 findings를 재사용하여 Regex/SLM 스캔 생략.
"""
from __future__ import annotations
import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..api.base import DLPTarget
from .base import Stage, Finding, Action, Severity, PipelineResult
from .control import DEFAULT_CONTROL_PATH, load_control
from .regex_stage import RegexStage
from .asset_stage import AssetStage
from .slm_stage import SLMStage
from .ml_filter import FalsePositiveFilter, load_filter, get_filter_status

log = logging.getLogger(__name__)

# ── 메시지 해시 캐시 ─────────────────────────────────────────────────────────

CACHE_TTL = 300  # 캐시 유효 시간 (초)
CACHE_MAX = 500  # 최대 캐시 항목 수
SLM_SKIP_ROLES: frozenset[str] = frozenset({"system", "assistant", "tool_def"})
SLM_COVERED_STAGES: frozenset[str] = frozenset({"regex", "asset"})
SLM_MIN_WINDOW_CHARS = 40
SLM_SKIP_COVERAGE_RATIO = 0.80
SLM_SKIP_REMAINING_CHARS = 120


@dataclass
class _CacheEntry:
    findings: list[Finding]
    ts: float  # time.monotonic()


_msg_cache: dict[str, _CacheEntry] = {}
_slm_cache: dict[str, _CacheEntry] = {}
_cache_stats = {"hits": 0, "misses": 0}
_slm_cache_stats = {"hits": 0, "misses": 0}


def _cache_key(field_path: str, role: str, text: str, control_tag: str) -> str:
    """(field_path + role + content + control_tag) → SHA256 해시.

    control_tag는 제어 파일 내용의 MD5 해시(압축)로, 설정이
    변경되면 캐시 키가 달라져 자동으로 미스가 된다.
    mtime 보다 안정적 — 동시 mtime + 다른 내용도 정확히 구분한다.
    """
    raw = f"{field_path}\x00{role}\x00{text}\x00{control_tag}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_gc() -> None:
    """만료 항목 제거 + 최대 크기 초과 시 오래된 항목 삭제."""
    now = time.monotonic()
    for cache in (_msg_cache, _slm_cache):
        expired = [k for k, v in cache.items() if now - v.ts > CACHE_TTL]
        for k in expired:
            del cache[k]
        # 여전히 초과하면 오래된 순 삭제
        if len(cache) > CACHE_MAX:
            by_age = sorted(cache.items(), key=lambda x: x[1].ts)
            for k, _ in by_age[: len(cache) - CACHE_MAX]:
                del cache[k]


def get_cache_stats() -> dict:
    """외부(engine_server)에서 캐시 통계 조회."""
    return {
        **_cache_stats,
        "size": len(_msg_cache),
        "slm_hits": _slm_cache_stats["hits"],
        "slm_misses": _slm_cache_stats["misses"],
        "slm_size": len(_slm_cache),
    }


def _should_skip_slm_target(target) -> bool:
    return getattr(target, "role", "") in SLM_SKIP_ROLES


def get_slm_stats() -> dict:
    """SLM 추론 통계 조회 (TUI/모니터링용)."""
    return SLMStage.get_stats()


def get_runtime_warning_lines() -> list[str]:
    warnings: list[str] = []
    warnings.extend(_asset_stage.runtime_warning_lines())
    warnings.extend(_slm_stage.runtime_warning_lines())
    if _fp_filter is None and Path(
        __file__
    ).parent.joinpath("ml_filter", "models", "fp_filter_xgb.pkl").exists():
        warnings.append("[ML Filter] 모델 파일은 존재하지만 로드 실패 — ML 필터 비활성화 상태")
    return warnings


def _overlaps(a: Finding, b: Finding) -> bool:
    """두 finding의 span이 겹치는지 확인 (동일 field_path 기준)."""
    return a.field_path == b.field_path and a.match_start < b.match_end and b.match_start < a.match_end


def _suppress_overlapping(findings: list[Finding]) -> list[Finding]:
    """Non-Maximum Suppression: 같은 구간에 겹치는 finding 중 우선순위 낮은 것은
    suppressed=True로 표시한다. 리포트에는 남겨 감사 추적 가능.

    우선순위: Severity(높을수록) > Confidence(높을수록) > Length(길수록)
    """
    sorted_f = sorted(
        findings,
        key=lambda f: (-f.severity.value, -f.confidence, -(f.match_end - f.match_start)),
    )
    keep: list[Finding] = []
    result: list[Finding] = []
    for f in sorted_f:
        overlapped = next((k for k in keep if _overlaps(f, k)), None)
        if overlapped is not None:
            if not f.suppressed:
                meta = dict(f.metadata or {})
                meta.update({
                    "suppressed_reason": "nms",
                    "suppressed_by_rule": overlapped.rule,
                    "suppressed_by_stage": overlapped.stage,
                    "suppressed_by_confidence": overlapped.confidence,
                    "suppressed_by_match_text": overlapped.match_text,
                })
                f.metadata = meta
            f.suppressed = True
            result.append(f)
        else:
            keep.append(f)
            result.append(f)
    # 원래 순서(match_start 기준)로 복원
    result.sort(key=lambda f: (f.field_path, f.match_start))
    return result


def _decide_action(findings: list[Finding], threshold: float = 0.5) -> Action:
    """threshold 이상이며 suppressed가 아닌 finding만 action에 반영."""
    effective = [
        finding
        for finding in findings
        if finding.confidence >= threshold and not finding.suppressed
    ]
    if not effective:
        return Action.PASS
    max_sev = max(f.severity.value for f in effective)
    if max_sev >= Severity.CRITICAL.value:
        return Action.MASK
    if max_sev >= Severity.HIGH.value:
        return Action.ALERT
    return Action.ALERT


# 싱글톤 스테이지 인스턴스
_regex_stage = RegexStage()
_asset_stage = AssetStage()
_slm_stage   = SLMStage()   # 지연 로드 — 첫 scan() 호출 시 모델 로드

# ML FP 필터 싱글톤 (모델 파일 없으면 None)
_fp_filter: FalsePositiveFilter | None = load_filter()


def reload_ml_filter(threshold: float | None = None) -> bool:
    """ML 필터 모델 재로드 (모델 파일 교체 후 hot-reload용).

    Returns True if loaded successfully, False if unavailable.
    """
    global _fp_filter
    _fp_filter = load_filter(threshold=threshold)
    return _fp_filter is not None


def get_ml_filter_stats() -> dict:
    """ML 필터 런타임 통계 조회."""
    if _fp_filter is None:
        return {**get_filter_status(), "enabled": False, "loaded": False}
    return {**_fp_filter.get_stats(), **get_filter_status(), "enabled": True, "loaded": True}


def _apply_ml_filter(
    findings: list[Finding],
    targets: list,
    control,
) -> list[Finding]:
    """Regex Finding에 ML FP 필터 적용.

    - stage == "regex" 인 finding만 대상 (Asset / SLM finding 보호)
    - suppressed=True 이미 된 finding은 건너뜀
    - 모델 없거나 ml_filter_enabled=False이면 no-op
    """
    if not control.ml_filter_enabled or _fp_filter is None:
        return findings

    # field_path → 원문 텍스트 조회 맵
    text_lookup: dict[str, str] = {t.field_path: t.text for t in targets}

    for f in findings:
        if f.stage != "regex" or f.suppressed:
            continue
        full_text = text_lookup.get(f.field_path, "")
        keep, prob_tp = _fp_filter.predict(f, full_text)
        if not keep:
            meta = dict(f.metadata or {})
            meta["suppressed_reason"] = "ml_fp_filter"
            meta["ml_prob_tp"]        = round(prob_tp, 4)
            meta["ml_prob_fp"]        = round(1.0 - prob_tp, 4)
            meta["ml_threshold"]      = _fp_filter.threshold
            f.metadata   = meta
            f.suppressed = True

    return findings


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if end <= start:
            continue
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def _covered_spans_for_slm(
    findings: list[Finding],
    field_path: str,
    text_len: int,
) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for finding in findings:
        if finding.field_path != field_path:
            continue
        if finding.stage not in SLM_COVERED_STAGES:
            continue
        start = max(0, min(text_len, finding.match_start))
        end = max(0, min(text_len, finding.match_end))
        if end > start:
            spans.append((start, end))
    return _merge_spans(spans)


def _invert_spans(text_len: int, covered_spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if text_len <= 0:
        return []
    if not covered_spans:
        return [(0, text_len)]

    unresolved: list[tuple[int, int]] = []
    cursor = 0
    for start, end in covered_spans:
        if cursor < start:
            unresolved.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < text_len:
        unresolved.append((cursor, text_len))
    return unresolved


def _build_slm_targets_for_target(
    target: DLPTarget,
    effective_findings: list[Finding],
) -> list[DLPTarget]:
    text = getattr(target, "text", "") or ""
    if not text.strip():
        return []

    text_len = len(text)
    covered_spans = _covered_spans_for_slm(effective_findings, target.field_path, text_len)
    covered_chars = sum(end - start for start, end in covered_spans)
    remaining_chars = max(0, text_len - covered_chars)
    coverage_ratio = covered_chars / text_len if text_len else 0.0

    if covered_spans and coverage_ratio >= SLM_SKIP_COVERAGE_RATIO and remaining_chars < SLM_SKIP_REMAINING_CHARS:
        return []

    unresolved_spans = _invert_spans(text_len, covered_spans)
    if not covered_spans:
        return [target]

    windows = [
        (start, end)
        for start, end in unresolved_spans
        if end - start >= SLM_MIN_WINDOW_CHARS
    ]
    if not windows:
        return []

    return [
        DLPTarget(
            field_path=target.field_path,
            role=target.role,
            text=text[start:end],
            history=getattr(target, "history", False),
            base_offset=start,
        )
        for start, end in windows
    ]


def run_pipeline(
    targets: list,
    stages: list[Stage] | None = None,
    slm_enabled: bool = False,
) -> PipelineResult:
    """
    DLP 파이프라인 실행.

    Parameters
    ----------
    targets     : list[DLPTarget] — 추출된 텍스트 대상
    stages      : 실행할 스테이지 목록 (None이면 자동 결정)
    slm_enabled : True이면 RegexStage 뒤에 SLMStage 추가 실행

    메시지 해시 캐시:
      각 target의 (field_path + role + text)를 SHA256 해시로 캐시.
      이전 턴에서 동일 메시지가 있으면 Regex/SLM 스캔 생략, 캐시된 findings 재사용.
    """
    t0 = time.monotonic()
    control = load_control()

    # 제어 파일 내용 해시를 캐시 키에 포함 — disabled_rules 등 설정이 바뀌면 자동 캐시 미스
    try:
        ctrl_bytes = Path(DEFAULT_CONTROL_PATH).read_bytes()
        control_tag = hashlib.md5(ctrl_bytes).hexdigest()[:16]  # noqa: S324
    except OSError:
        control_tag = "0"

    # 캐시 GC (매 호출마다 가볍게)
    _cache_gc()

    # ── 1단계: Regex Stage (캐시 적용) ────────────────────────────────────────
    new_targets: list[DLPTarget] = []
    cached_findings: list[Finding] = []
    regex_new_findings: list[Finding] = []
    if control.regex_enabled:
        for target in targets:
            key = _cache_key(target.field_path, target.role, target.text, control_tag)
            entry = _msg_cache.get(key)
            if entry and (time.monotonic() - entry.ts) < CACHE_TTL:
                _cache_stats["hits"] += 1
                cached_findings.extend(entry.findings)
            else:
                _cache_stats["misses"] += 1
                new_targets.append(target)

        # 캐시 미스 타깃만 Regex 스캔
        if new_targets:
            try:
                regex_new_findings = _regex_stage.scan(new_targets, [])
            except Exception as e:
                log.error("[pipeline] regex 스테이지 오류: %s", e)

            # 새 findings를 타깃별로 캐시에 저장
            now = time.monotonic()
            for target in new_targets:
                key = _cache_key(target.field_path, target.role, target.text, control_tag)
                target_findings = [
                    f for f in regex_new_findings if f.field_path == target.field_path
                ]
                _msg_cache[key] = _CacheEntry(findings=target_findings, ts=now)

    all_findings = cached_findings + regex_new_findings

    # ── 1-1단계: ML FP 필터 (Regex 직후, Asset 이전) ────────────────────────
    # stage=="regex" findings만 대상, suppressed=True인 것 스킵
    # 모델 없거나 ml_filter_enabled=False이면 no-op (fallback 안전)
    if control.ml_filter_enabled:
        all_findings = _apply_ml_filter(all_findings, targets, control)

    # ── 1-2단계: Asset Stage (Regex 이후, SLM 이전) ─────────────────────────
    if control.asset_enabled:
        try:
            asset_findings = _asset_stage.scan(targets, all_findings)
            all_findings.extend(asset_findings)
        except Exception as e:
            log.error("[pipeline] asset 스테이지 오류: %s", e)

    # ── NMS: 겹치는 finding 제거 ────────────────────────────────────────────
    if len(all_findings) > 1:
        all_findings = _suppress_overlapping(all_findings)

    # ── 2단계: SLM Stage (Regex/Asset 미처리 window만 전달) ──────────────────
    if slm_enabled:
        try:
            effective_findings = [
                finding
                for finding in all_findings
                if finding.confidence >= control.confidence_threshold and not finding.suppressed
            ]
            slm_entries: list[tuple[DLPTarget, str]] = []
            cached_slm_findings: list[Finding] = []
            slm_tag = f"{control_tag}:slm"
            slm_targets_before = 0
            slm_targets_after = 0
            slm_chars_before = 0
            slm_chars_after = 0
            for target in targets:
                if _should_skip_slm_target(target):
                    continue
                slm_targets_before += 1
                slm_chars_before += len(target.text)
                for prepared_target in _build_slm_targets_for_target(target, effective_findings):
                    key = _cache_key(
                        f"{prepared_target.field_path}:{prepared_target.base_offset}",
                        prepared_target.role,
                        prepared_target.text,
                        slm_tag,
                    )
                    slm_chars_after += len(prepared_target.text)
                    slm_targets_after += 1
                    entry = _slm_cache.get(key)
                    if entry and (time.monotonic() - entry.ts) < CACHE_TTL:
                        _slm_cache_stats["hits"] += 1
                        cached_slm_findings.extend(entry.findings)
                        continue
                    _slm_cache_stats["misses"] += 1
                    slm_entries.append((prepared_target, key))

            if slm_targets_before:
                log.debug(
                    "[pipeline] slm windows before=%d (%d chars), after=%d (%d chars), uncached=%d",
                    slm_targets_before,
                    slm_chars_before,
                    slm_targets_after,
                    slm_chars_after,
                    len(slm_entries),
                )

            slm_targets = [target for target, _ in slm_entries]
            slm_findings = _slm_stage.scan(slm_targets, effective_findings) if slm_targets else []
            now = time.monotonic()
            for prepared_target, key in slm_entries:
                window_start = prepared_target.base_offset
                window_end = window_start + len(prepared_target.text)
                target_findings = [
                    finding
                    for finding in slm_findings
                    if finding.field_path == prepared_target.field_path
                    and window_start <= finding.match_start < window_end
                    and window_start < finding.match_end <= window_end
                ]
                _slm_cache[key] = _CacheEntry(findings=target_findings, ts=now)
            all_findings.extend(cached_slm_findings)
            all_findings.extend(slm_findings)
        except Exception as e:
            log.error("[pipeline] slm 스테이지 오류: %s", e)

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    current_findings = [finding for finding in all_findings if not finding.history]
    action = _decide_action(current_findings, control.confidence_threshold)

    cache_hit_count = len(cached_findings)
    if cache_hit_count > 0 or len(new_targets) > 0:
        log.debug(
            "[pipeline] targets=%d, cache_hit=%d, new_scan=%d, findings=%d (%.1fms)",
            len(targets), len(targets) - len(new_targets),
            len(new_targets), len(all_findings), elapsed,
        )

    return PipelineResult(
        action=action,
        findings=all_findings,
        elapsed_ms=elapsed,
    )

