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

from .base import Stage, Finding, Action, Severity, PipelineResult
from .regex_stage import RegexStage
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


def _cache_key(field_path: str, role: str, text: str) -> str:
    """(field_path + role + content) → SHA256 해시."""
    raw = f"{field_path}\x00{role}\x00{text}"
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


def _decide_action(findings: list[Finding]) -> Action:
    """findings에서 최종 액션 결정."""
    if not findings:
        return Action.PASS
    max_sev = max(f.severity.value for f in findings)
    if max_sev >= Severity.CRITICAL.value:
        return Action.MASK
    if max_sev >= Severity.HIGH.value:
        return Action.ALERT
    return Action.ALERT


# 싱글톤 스테이지 인스턴스
_regex_stage = RegexStage()
_slm_stage   = SLMStage()   # 지연 로드 — 첫 scan() 호출 시 모델 로드


def _mask_text_for_slm(text: str, findings: list[Finding], field_path: str) -> str:
    """Regex findings로 텍스트를 마스킹한 사본 생성 (SLM 입력용)."""
    MASK_LABELS = {
        "kr_rrn": "[주민등록번호]", "kr_phone": "[전화번호]",
        "credit_card": "[카드번호]", "us_ssn": "[SSN]",
        "email": "[이메일]", "kr_passport": "[여권번호]",
        "kr_driver_license": "[운전면허]", "aws_access_key": "[AWS_KEY]",
        "api_key_assignment": "[API_KEY]", "pem_private_key": "[PRIVATE_KEY]",
        "jwt_token": "[JWT]", "github_pat": "[GH_TOKEN]",
    }
    relevant = sorted(
        [f for f in findings if f.field_path == field_path],
        key=lambda f: f.match_start, reverse=True,
    )
    masked = text
    for f in relevant:
        label = MASK_LABELS.get(f.rule, "[REDACTED]")
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

    # 캐시 GC (매 호출마다 가볍게)
    _cache_gc()

    # ── 1단계: Regex Stage (캐시 적용) ────────────────────────────────────────
    new_targets = []  # 캐시 미스 → 실제 스캔 필요
    cached_findings: list[Finding] = []

    for target in targets:
        key = _cache_key(target.field_path, target.role, target.text)
        entry = _msg_cache.get(key)
        if entry and (time.monotonic() - entry.ts) < CACHE_TTL:
            _cache_stats["hits"] += 1
            cached_findings.extend(entry.findings)
        else:
            _cache_stats["misses"] += 1
            new_targets.append(target)

    # 캐시 미스 타깃만 Regex 스캔
    regex_new_findings: list[Finding] = []
    if new_targets:
        try:
            regex_new_findings = _regex_stage.scan(new_targets, [])
        except Exception as e:
            log.error("[pipeline] regex 스테이지 오류: %s", e)

        # 새 findings를 타깃별로 캐시에 저장
        now = time.monotonic()
        for target in new_targets:
            key = _cache_key(target.field_path, target.role, target.text)
            target_findings = [
                f for f in regex_new_findings if f.field_path == target.field_path
            ]
            _msg_cache[key] = _CacheEntry(findings=target_findings, ts=now)

    all_findings = cached_findings + regex_new_findings

    # ── 2단계: SLM Stage (Regex 마스킹된 텍스트 전달) ─────────────────────────
    if slm_enabled:
        try:
            # SLM에는 Regex가 마스킹한 텍스트를 전달하여
            # 이미 잡힌 PII는 건너뛰고, 못 잡은 것(이름/주소 등)에 집중
            from ..api.base import DLPTarget
            slm_targets = []
            for target in targets:
                masked_text = _mask_text_for_slm(
                    target.text, all_findings, target.field_path,
                )
                slm_targets.append(DLPTarget(
                    field_path=target.field_path,
                    role=target.role,
                    text=masked_text,
                ))
            slm_findings = _slm_stage.scan(slm_targets, all_findings)
            all_findings.extend(slm_findings)
        except Exception as e:
            log.error("[pipeline] slm 스테이지 오류: %s", e)

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    action = _decide_action(all_findings)

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

