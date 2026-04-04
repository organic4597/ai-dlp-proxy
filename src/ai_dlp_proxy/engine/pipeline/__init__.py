"""
DLP Pipeline — 스테이지를 순차 실행하는 러너.
"""
from __future__ import annotations
import time

from .base import Stage, Finding, Action, Severity, PipelineResult
from .regex_stage import RegexStage


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


# 기본 파이프라인 스테이지 목록
_DEFAULT_STAGES: list[Stage] = [
    RegexStage(),
    # 향후: SLMStage(),
]


def run_pipeline(targets: list, stages: list[Stage] | None = None) -> PipelineResult:
    """
    DLP 파이프라인 실행.

    Parameters
    ----------
    targets : list[DLPTarget] — 추출된 텍스트 대상
    stages  : 실행할 스테이지 목록 (None이면 기본 스테이지)

    Returns
    -------
    PipelineResult
    """
    if stages is None:
        stages = _DEFAULT_STAGES

    t0 = time.monotonic()
    all_findings: list[Finding] = []

    for stage in stages:
        new = stage.scan(targets, all_findings)
        all_findings.extend(new)

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    action = _decide_action(all_findings)

    return PipelineResult(
        action=action,
        findings=all_findings,
        elapsed_ms=elapsed,
    )
