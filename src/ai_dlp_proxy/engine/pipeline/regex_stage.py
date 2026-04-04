"""
Regex Stage — 정규표현식 기반 민감정보 탐지.

탐지 대상:
  - 한국 주민등록번호 (KR RRN)
  - 한국 여권번호
  - 한국 운전면허번호
  - 한국 전화번호
  - US Social Security Number (SSN)
  - 신용카드번호 (Luhn 검증)
  - API 키 / 시크릿 패턴
  - 이메일 주소
  - Private Key (PEM)
  - AWS Access Key
  - JWT 토큰

컨텍스트 규칙:
  - match 앞뒤 최대 100자
  - 컨텍스트 범위 내에 다른 match가 있으면 해당 match 직전까지만 포함
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from .base import Stage, Finding, Severity


# ── 룰 정의 ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RegexRule:
    name: str
    pattern: re.Pattern
    severity: Severity
    validator: callable | None = None  # float 반환: 0.0=필터링, 0.0<x<1.0=낮은확신, 1.0=확실
    description: str = ""


def _luhn_check(digits: str) -> bool:
    """Luhn 알고리즘으로 카드번호 검증."""
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _validate_kr_rrn(match_text: str) -> float:
    """주민등록번호 체크섬 + 생년월일 유효성 검증. 통과=1.0, 실패=0.0."""
    digits = re.sub(r"[^0-9]", "", match_text)
    if len(digits) != 13:
        return 0.0
    # 올-제로 등 무의미 패턴 제외
    if len(set(digits)) <= 2:
        return 0.0
    # 생년월일 유효성 검사 (YYMMDD)
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    if not (1 <= mm <= 12):
        return 0.0
    if not (1 <= dd <= 31):
        return 0.0
    # 성별코드 유효성 (1~4, 9)
    gender = int(digits[6])
    if gender not in (1, 2, 3, 4, 9):
        return 0.0
    # 체크섬 검증
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10
    if check != int(digits[12]):
        return 0.0  # 체크섬 불일치 → 필터링
    return 1.0


def _validate_card(match_text: str) -> float:
    """카드번호 Luhn 검증. 올-제로/반복 패턴 제외."""
    digits_only = re.sub(r"[^0-9]", "", match_text)
    # 올-제로, 단일 숫자 반복 제외 (000000-0000000, 1111111111111 등)
    if len(set(digits_only)) <= 2:
        return 0.0
    if _luhn_check(match_text):
        return 1.0
    return 0.0


# ── 룰 목록 ──────────────────────────────────────────────────────────────────

RULES: list[RegexRule] = [
    # 한국 주민등록번호: 6자리-7자리 (뒷자리 1~4로 시작)
    # (?<!\d)/(?!\d) → 한글 등 유니코드 앞뒤에서도 경계 처리
    RegexRule(
        name="kr_rrn",
        pattern=re.compile(
            r"(?<!\d)(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))"
            r"[-\s]?"
            r"([1-4]\d{6})(?!\d)"
        ),
        severity=Severity.CRITICAL,
        validator=_validate_kr_rrn,
        description="한국 주민등록번호",
    ),
    # 한국 여권번호: M12345678
    RegexRule(
        name="kr_passport",
        pattern=re.compile(r"\b[A-Z]{1,2}\d{7,8}\b"),
        severity=Severity.HIGH,
        description="한국 여권번호",
    ),
    # 한국 운전면허번호: 12-34-567890-12
    RegexRule(
        name="kr_driver_license",
        pattern=re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)"),
        severity=Severity.HIGH,
        description="한국 운전면허번호",
    ),
    # 한국 전화번호
    RegexRule(
        name="kr_phone",
        pattern=re.compile(
            r"(?<!\d)(?:010|011|016|017|018|019)"
            r"[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"
        ),
        severity=Severity.MEDIUM,
        description="한국 휴대전화번호",
    ),
    # US SSN: 123-45-6789
    RegexRule(
        name="us_ssn",
        pattern=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}"
            r"[-\s]"
            r"(?!00)\d{2}"
            r"[-\s]"
            r"(?!0000)\d{4}\b"
        ),
        severity=Severity.CRITICAL,
        description="US Social Security Number",
    ),
    # 신용카드번호 (13~19자리, 공백/하이픈 허용)
    # (?<!\d) / (?!\d) 로 앞뒤 숫자 경계 처리 → 한글 등 유니코드 뒤에서도 동작
    RegexRule(
        name="credit_card",
        pattern=re.compile(
            r"(?<!\d)(?:\d[-\s]?){13,19}(?!\d)"
        ),
        severity=Severity.CRITICAL,
        validator=_validate_card,
        description="신용카드번호",
    ),
    # 이메일 주소
    RegexRule(
        name="email",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        severity=Severity.LOW,
        description="이메일 주소",
    ),
    # AWS Access Key ID
    RegexRule(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID",
    ),
    # Generic API Key / Secret 패턴
    RegexRule(
        name="api_key_assignment",
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"
            r"[\s]*[=:]\s*['\"]?"
            r"([A-Za-z0-9\-_./+=]{16,})"
            r"['\"]?"
        ),
        severity=Severity.HIGH,
        description="API 키/시크릿 할당문",
    ),
    # PEM Private Key
    RegexRule(
        name="pem_private_key",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
            r"[\s\S]{20,}"
            r"-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        ),
        severity=Severity.CRITICAL,
        description="PEM Private Key",
    ),
    # JWT 토큰 (3-part base64)
    RegexRule(
        name="jwt_token",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        severity=Severity.HIGH,
        description="JWT 토큰",
    ),
    # GitHub Personal Access Token
    RegexRule(
        name="github_pat",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token",
    ),
]


# ── 컨텍스트 추출 ─────────────────────────────────────────────────────────────

def _extract_context(
    text: str,
    match_start: int,
    match_end: int,
    all_spans: list[tuple[int, int]],
    context_len: int = 100,
) -> tuple[str, str]:
    """
    match 앞뒤 context_len 글자를 추출하되,
    범위 내에 다른 match가 있으면 그 match 직전까지만 포함.

    Parameters
    ----------
    text        : 전체 텍스트
    match_start : 현재 매치 시작 offset
    match_end   : 현재 매치 끝 offset
    all_spans   : 모든 매치의 (start, end) 리스트 (정렬됨)
    context_len : 컨텍스트 최대 길이 (기본 100)

    Returns
    -------
    (context_before, context_after)
    """
    # ── before ────────────────────────────────────────────────────────────
    ctx_start = max(0, match_start - context_len)
    # 다른 match가 ctx_start ~ match_start 범위에 있으면 그 match의 end 이후부터
    for s, e in all_spans:
        if s == match_start and e == match_end:
            continue  # 자기 자신 스킵
        # 이 match의 범위가 context before 영역과 겹치면
        if e > ctx_start and e <= match_start:
            ctx_start = max(ctx_start, e)  # 겹치는 match 뒤부터 시작
        if s >= ctx_start and s < match_start:
            # 다른 match가 context 안에 있음 → 그 match 직전까지만
            # 가장 가까운 match의 start를 찾되, 그 match의 전체를 제외
            pass  # e > ctx_start 케이스에서 이미 처리됨

    # 좀 더 보수적으로: context 영역에 포함되는 다른 match가 있으면
    # 그 중 현재에 가장 가까운 match의 end를 ctx_start로
    for s, e in reversed(all_spans):
        if s == match_start and e == match_end:
            continue
        if ctx_start <= s < match_start:
            # 다른 match가 before context에 있음 → 그 match 직전에서 자름
            ctx_start = s
            break

    context_before = text[ctx_start:match_start]

    # ── after ─────────────────────────────────────────────────────────────
    ctx_end = min(len(text), match_end + context_len)
    # 다른 match가 match_end ~ ctx_end 범위에 있으면 그 match의 start 직전까지
    for s, e in all_spans:
        if s == match_start and e == match_end:
            continue
        if match_end <= s < ctx_end:
            ctx_end = s
            break

    context_after = text[match_end:ctx_end]

    return context_before, context_after


# ── Regex Stage ───────────────────────────────────────────────────────────────

class RegexStage(Stage):
    """disabled_rules: 제어 파일(/tmp/dlp-control.json)의 'disabled_rules' 목록에 있는 규칙은 스킵."""

    _CONTROL_FILE = "/tmp/dlp-control.json"

    def _disabled_rules(self) -> set[str]:
        """제어 파일에서 비활성화 규칙 목록을 읽어 반환."""
        import json as _json
        try:
            data = _json.loads(open(self._CONTROL_FILE).read())
            return set(data.get("disabled_rules", []))
        except Exception:
            return set()

    @property
    def name(self) -> str:
        return "regex"

    def scan(self, targets: list, findings: list[Finding]) -> list[Finding]:
        """모든 target 텍스트에 regex 룰 적용."""
        new_findings: list[Finding] = []
        disabled = self._disabled_rules()

        for target in targets:
            text = target.text
            if not text or len(text) < 5:
                continue

            # 모든 룰에 대해 매치 수집
            raw_matches: list[tuple[RegexRule, re.Match, float]] = []
            for rule in RULES:
                if rule.name in disabled:
                    continue
                for m in rule.pattern.finditer(text):
                    if rule.validator:
                        conf = rule.validator(m.group())
                        if conf <= 0.0:  # 0.0이면 완전 필터링
                            continue
                    else:
                        conf = 1.0
                    raw_matches.append((rule, m, conf))

            if not raw_matches:
                continue

            # 모든 매치 span 정렬 (컨텍스트 추출용)
            all_spans = sorted([(m.start(), m.end()) for _, m, _ in raw_matches])

            for rule, m, conf in raw_matches:
                ctx_before, ctx_after = _extract_context(
                    text, m.start(), m.end(), all_spans,
                )
                new_findings.append(Finding(
                    stage=self.name,
                    rule=rule.name,
                    severity=rule.severity,
                    field_path=target.field_path,
                    role=target.role,
                    match_text=m.group(),
                    match_start=m.start(),
                    match_end=m.end(),
                    context_before=ctx_before,
                    context_after=ctx_after,
                    confidence=conf,
                    metadata={"description": rule.description},
                ))

        return new_findings
