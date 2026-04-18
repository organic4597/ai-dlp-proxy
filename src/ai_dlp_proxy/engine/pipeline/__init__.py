"""
DLP Pipeline — 스테이지를 순차 실행하는 러너.

메시지 해시 캐시:
  AI Agent는 매 턴마다 이전 대화를 포함하여 전송하므로
  동일 메시지를 반복 스캔하지 않도록 (role+content) 해시 기반 캐시 적용.
  캐시 히트 시 이전 findings를 재사용하여 Regex/SLM 스캔 생략.
"""
from __future__ import annotations
import copy
import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from .base import Stage, Finding, Action, Severity, PipelineResult
from .control import DEFAULT_CONTROL_PATH, load_control
from .regex_stage import RegexStage
from .asset_stage import AssetStage
from .slm_stage import SLMStage

log = logging.getLogger(__name__)

# ── 메시지 해시 캐시 ─────────────────────────────────────────────────────────

CACHE_TTL = 300  # 캐시 유효 시간 (초)
CACHE_MAX = 500  # 최대 캐시 항목 수


@dataclass
class _CacheEntry:
    findings: list[Finding]
    ts: float  # time.monotonic()


_msg_cache: dict[str, _CacheEntry] = {}
_cache_stats = {"hits": 0, "misses": 0}


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
    expired = [k for k, v in _msg_cache.items() if now - v.ts > CACHE_TTL]
    for k in expired:
        del _msg_cache[k]
    # 여전히 초과하면 오래된 순 삭제
    if len(_msg_cache) > CACHE_MAX:
        by_age = sorted(_msg_cache.items(), key=lambda x: x[1].ts)
        for k, _ in by_age[: len(_msg_cache) - CACHE_MAX]:
            del _msg_cache[k]


def get_cache_stats() -> dict:
    """외부(engine_server)에서 캐시 통계 조회."""
    return {**_cache_stats, "size": len(_msg_cache)}


def get_runtime_warning_lines() -> list[str]:
    warnings: list[str] = []
    warnings.extend(_asset_stage.runtime_warning_lines())
    warnings.extend(_slm_stage.runtime_warning_lines())
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


def _mask_text_for_slm(
    text: str,
    findings: list[Finding],
    field_path: str,
    mask_templates: dict[str, str],
) -> str:
    """effective findings를 SLM 입력 전에 마스킹한다.

    Asset 임베딩 매치는 마스킹하지 않아 SLM에게 문맥을 보존한다.
    Asset 키워드 매치는 [보호자산] 라벨로 교체한다.
    """
    relevant = sorted(
        [f for f in findings if f.field_path == field_path],
        key=lambda f: f.match_start, reverse=True,
    )
    masked = text
    for f in relevant:
        # Asset 임베딩 매치는 마스킹 생략 (SLM 문맥 보존)
        if f.stage == "asset" and f.metadata.get("match_type") == "embedding":
            continue
        # Asset 키워드 매치 → [보호자산]
        if f.stage == "asset":
            label = "[보호자산]"
        else:
            label = mask_templates.get(f.rule, "[REDACTED]")
        if 0 <= f.match_start < f.match_end <= len(masked):
            masked = masked[:f.match_start] + label + masked[f.match_end:]
    return masked


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

    # ── 2단계: SLM Stage (Regex 마스킹된 텍스트 전달) ─────────────────────────
    if slm_enabled:
        try:
            effective_findings = [
                finding
                for finding in all_findings
                if finding.confidence >= control.confidence_threshold and not finding.suppressed
            ]
            # SLM에는 Regex+Asset이 마스킹한 텍스트를 전달하여
            # 이미 잡힌 PII/자산은 건너뛰고, 못 잡은 것(이름/주소 등)에 집중
            from ..api.base import DLPTarget
            slm_targets = []
            for target in targets:
                masked_text = _mask_text_for_slm(
                    target.text,
                    effective_findings,
                    target.field_path,
                    control.mask_templates,
                )
                slm_targets.append(DLPTarget(
                    field_path=target.field_path,
                    role=target.role,
                    text=masked_text,
                ))
            slm_findings = _slm_stage.scan(slm_targets, effective_findings)
            all_findings.extend(slm_findings)
        except Exception as e:
            log.error("[pipeline] slm 스테이지 오류: %s", e)

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    action = _decide_action(all_findings, control.confidence_threshold)

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

