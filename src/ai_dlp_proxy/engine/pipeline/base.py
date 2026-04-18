"""
DLP Pipeline 기본 데이터 구조 및 Stage 인터페이스.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """탐지 심각도 (순서 비교 가능)."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Action(Enum):
    """파이프라인 최종 결정."""
    PASS = "pass"       # 이상 없음
    ALERT = "alert"     # 경고만 (통과)
    MASK = "mask"       # 마스킹 후 전송 (Phase 2)
    BLOCK = "block"     # 전송 차단 (Phase 3)


@dataclass
class Finding:
    """
    단일 탐지 결과.
    """
    stage: str              # "regex", "slm", ...
    rule: str               # "kr_rrn", "us_ssn", "api_key", ...
    severity: Severity
    field_path: str         # DLPTarget.field_path
    role: str               # DLPTarget.role
    match_text: str         # 매치된 텍스트 (마스킹 대상)
    match_start: int        # target.text 내 시작 offset
    match_end: int          # target.text 내 끝 offset
    context_before: str     # 매치 앞 컨텍스트 (최대 100자, 겹침 제외)
    context_after: str      # 매치 뒤 컨텍스트 (최대 100자, 겹침 제외)
    confidence: float = 1.0 # 0.0~1.0 (regex=1.0, sLM=모델 확신도)
    suppressed: bool = False
    history: bool = False   # True이면 이전 턴 히스토리 (마스킹은 하되 탐지 카운트 제외)
    metadata: dict = field(default_factory=dict)

    def context_window(self) -> str:
        """sLM에 전달할 컨텍스트 창: [before][MATCH][after]"""
        return f"{self.context_before}<<<{self.match_text}>>>{self.context_after}"


@dataclass
class PipelineResult:
    """파이프라인 전체 실행 결과."""
    action: Action = Action.PASS
    findings: list[Finding] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def effective_findings(self, threshold: float) -> list[Finding]:
        return [
            finding
            for finding in self.findings
            if finding.confidence >= threshold and not finding.suppressed
        ]

    def findings_by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def summary(self) -> dict:
        return {
            "action": self.action.value,
            "finding_count": len(self.findings),
            "elapsed_ms": self.elapsed_ms,
            "by_severity": {
                s.label: len(self.findings_by_severity(s))
                for s in Severity if self.findings_by_severity(s)
            },
            "rules_hit": list({f.rule for f in self.findings}),
        }


class Stage(ABC):
    """파이프라인 스테이지 인터페이스."""

    @property
    @abstractmethod
    def name(self) -> str:
        """스테이지 이름 (예: 'regex', 'slm')."""
        ...

    @abstractmethod
    def scan(self, targets: list, findings: list[Finding]) -> list[Finding]:
        """
        DLP targets를 스캔하여 Finding 목록 반환.

        Parameters
        ----------
        targets  : list[DLPTarget] — 추출된 텍스트 대상
        findings : list[Finding]   — 이전 스테이지의 findings (참조용)

        Returns
        -------
        새로 발견된 Finding 리스트 (이전 findings 미포함)
        """
        ...
