"""
DLP 엔진 공통 데이터 구조
모든 API 파서가 반환하는 정규화된 타입.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class DLPTarget:
    """
    DLP 검사 대상 텍스트 단위.
    field_path를 통해 원본 JSON body에서 마스킹 위치를 역참조.
    """
    field_path: str   # "messages[2].content", "system", "tools[0].function.description"
    role: str         # "system" | "user" | "assistant" | "tool_call" | "tool_result" | "tool_def" | "metadata"
    text: str         # 실제 검사·마스킹 대상 텍스트
    history: bool = False  # True이면 이전 턴 히스토리 (마스킹은 하되 탐지 카운트 제외)
    base_offset: int = 0   # windowed target일 때 원문 target.text 내 시작 오프셋

    def __repr__(self) -> str:
        preview = self.text[:80].replace("\n", "↵")
        return f"DLPTarget({self.role} @ {self.field_path!r}: {preview!r})"


@dataclass
class ParsedRequest:
    """
    엔진이 mitmproxy flow에서 추출한 정규화된 요청 구조.
    - targets: DLP 검사 대상 (텍스트 + 위치 정보)
    - raw_body: 원본 JSON body (마스킹 후 재조립용)
    """
    provider: str                          # "GitHub Copilot", "OpenAI", "Anthropic", "Gemini" …
    url: str
    model: str
    stream: bool
    targets: list[DLPTarget] = field(default_factory=list)
    raw_body: dict = field(default_factory=dict)

    @property
    def total_text_len(self) -> int:
        return sum(len(t.text) for t in self.targets)

    def targets_by_role(self, *roles: str) -> list[DLPTarget]:
        return [t for t in self.targets if t.role in roles]

    def summary(self) -> str:
        role_counts: dict[str, int] = {}
        for t in self.targets:
            role_counts[t.role] = role_counts.get(t.role, 0) + 1
        parts = [f"{r}×{c}" for r, c in sorted(role_counts.items())]
        return (
            f"{self.provider} | {self.model} | stream={self.stream} | "
            f"{len(self.targets)} targets ({', '.join(parts)}) | "
            f"{self.total_text_len:,} chars"
        )
