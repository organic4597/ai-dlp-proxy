"""
ML FP 필터 — 학습/추론 공유 feature 추출 모듈 (Single Source of Truth).

tests/build_ml_dataset.py와 동일 로직을 공유하여
학습-추론 feature 불일치 문제를 원천 방지한다.
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.pipeline.base import Finding

# ── feature 컬럼 순서 (학습·추론 공통) ────────────────────────────────────────

FEATURE_COLS: list[str] = [
    "rule_name",          # 문자열 → FalsePositiveFilter에서 ordinal 변환
    "severity_level",     # int: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
    "match_length",
    "match_digit_ratio",
    "match_alpha_ratio",
    "match_special_ratio",
    "match_entropy",
    "ctx_before_len",
    "ctx_after_len",
    "pii_keyword_hits",
    "code_signal_strong",
    "code_signal_weak",
    "is_in_quotes",
    "is_assignment_rhs",
    "is_in_url",
    "text_total_length",
    "current_confidence",
]

# 모델에 실제로 입력되는 순서 (rule_name_ord 포함, rule_name 제외)
NUMERIC_FEATURE_ORDER: list[str] = [
    "rule_name_ord",
    "severity_level",
    "match_length",
    "match_digit_ratio",
    "match_alpha_ratio",
    "match_special_ratio",
    "match_entropy",
    "ctx_before_len",
    "ctx_after_len",
    "pii_keyword_hits",
    "code_signal_strong",
    "code_signal_weak",
    "is_in_quotes",
    "is_assignment_rhs",
    "is_in_url",
    "text_total_length",
    "current_confidence",
]


# ── 내부 헬퍼 ────────────────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    """Shannon entropy (문자 단위)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


# ── 공개 API ─────────────────────────────────────────────────────────────────

def extract_features(finding: "Finding", full_text: str) -> dict:
    """Finding + 원문 텍스트 → feature dict.

    rule_name은 문자열로 반환.
    숫자 변환(ordinal encoding)은 호출 측(FalsePositiveFilter / build_ml_dataset)에서 처리.

    Parameters
    ----------
    finding   : RegexStage가 생성한 Finding 객체
    full_text : finding이 속한 DLPTarget.text (match offset 계산용)
    """
    # 지연 import — 순환 방지 (이 모듈은 regex_stage 하위에 위치)
    from engine.pipeline.regex_stage import (  # type: ignore[import]
        _PII_CONTEXT_WORDS,
        _STRONG_CODE_RE,
        _WEAK_CODE_RE,
    )

    mt = finding.match_text
    n = max(len(mt), 1)

    digit_ratio   = sum(c.isdigit()                                       for c in mt) / n
    alpha_ratio   = sum(c.isalpha()                                       for c in mt) / n
    special_ratio = sum(not c.isalnum() and not c.isspace()               for c in mt) / n

    ctx_b  = finding.context_before
    ctx_a  = finding.context_after
    window = ctx_b + ctx_a

    keywords = _PII_CONTEXT_WORDS.get(finding.rule, set())
    kw_hits  = sum(1 for kw in keywords if kw in window.lower())

    strong = len(_STRONG_CODE_RE.findall(window))
    weak   = len(_WEAK_CODE_RE.findall(window))

    # 매치 텍스트가 따옴표 안에 있는지
    start       = finding.match_start
    before_char = full_text[start - 1] if start > 0            else ""
    end         = finding.match_end
    after_char  = full_text[end]        if end < len(full_text) else ""
    is_in_quotes      = int(before_char in ('"', "'", "`") or after_char in ('"', "'", "`"))

    # 대입문 우변인지 (=, : 로 끝나는 컨텍스트)
    stripped          = ctx_b.rstrip()
    is_assignment_rhs = int(stripped.endswith("=") or stripped.endswith(":"))

    # URL 안에 있는지
    is_in_url = int("://" in ctx_b or ctx_b.rstrip().endswith("/"))

    severity_map   = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severity_level = severity_map.get(finding.severity.name, 2)

    return {
        "rule_name":          finding.rule,
        "severity_level":     severity_level,
        "match_length":       len(mt),
        "match_digit_ratio":  round(digit_ratio,   4),
        "match_alpha_ratio":  round(alpha_ratio,   4),
        "match_special_ratio":round(special_ratio, 4),
        "match_entropy":      round(_entropy(mt),  4),
        "ctx_before_len":     len(ctx_b),
        "ctx_after_len":      len(ctx_a),
        "pii_keyword_hits":   kw_hits,
        "code_signal_strong": strong,
        "code_signal_weak":   weak,
        "is_in_quotes":       is_in_quotes,
        "is_assignment_rhs":  is_assignment_rhs,
        "is_in_url":          is_in_url,
        "text_total_length":  len(full_text),
        "current_confidence": round(finding.confidence, 4),
    }
