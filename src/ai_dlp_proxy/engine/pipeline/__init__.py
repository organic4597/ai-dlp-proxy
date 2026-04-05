"""
DLP Pipeline — 스테이지를 순차 실행하는 러너.
"""
from __future__ import annotations
import logging
import time

from .base import Stage, Finding, Action, Severity, PipelineResult
from .regex_stage import RegexStage
from .slm_stage import SLMStage

log = logging.getLogger(__name__)

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
    """
    if stages is None:
        stages = [_regex_stage]
        if slm_enabled:
            stages.append(_slm_stage)

    t0 = time.monotonic()
    all_findings: list[Finding] = []

    for stage in stages:
        try:
            new = stage.scan(targets, all_findings)
            all_findings.extend(new)
        except Exception as e:
            log.error("[pipeline] %s 스테이지 오류: %s", stage.name, e)

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    action = _decide_action(all_findings)

    return PipelineResult(
        action=action,
        findings=all_findings,
        elapsed_ms=elapsed,
    )

