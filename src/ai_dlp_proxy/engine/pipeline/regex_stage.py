"""
Regex Stage — 계획서의 Phase 1 문맥 보정 로직을 반영한 정규식 탐지.

동작 순서:
1. 패턴 매칭 + validator 검증
2. 이미 마스킹된 플레이스홀더 재탐지 차단 (B-3)
3. 코드 문맥 감지 + validator floor 약화 (A-1)
4. 룰별 PII 키워드 배율 적용 (줄 단위 컨텍스트, A-2)
5. allowlist 일치 시 suppressed 처리
6. 커스텀 룰 (control.custom_rules) 적용
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Finding, Severity, Stage
from .control import DEFAULT_CONTROL_PATH, is_allowlisted, load_control

# ── B-3: 이미 마스킹된 플레이스홀더 패턴 ────────────────────────────────────
# control.mask_templates 값이 변경돼도 기본 세트를 항상 포함
_BUILTIN_PLACEHOLDERS: frozenset[str] = frozenset({
    "[주민등록번호]", "[전화번호]", "[카드번호]", "[SSN]", "[이메일]",
    "[여권번호]", "[운전면허]", "[AWS_KEY]", "[API_KEY]", "[PRIVATE_KEY]",
    "[JWT]", "[GH_TOKEN]", "[이름]", "[주소]", "[기관]", "[생년월일]",
    "[계좌번호]", "[IP주소]", "[기기ID]", "[의료정보]", "[생체정보]",
    "[개인정보]", "[MASKED]", "[REDACTED]",
})
_PLACEHOLDER_RE = re.compile(r"\[[^\]\[\n]{1,30}\]")


@dataclass(frozen=True)
class RegexRule:
    name: str
    pattern: re.Pattern
    severity: Severity
    validator: callable | None = None
    description: str = ""
    finding_group: int | None = None
    value_group: int | None = None


_STRONG_CODE_RE = re.compile(
    r"\b(?:import|from|def|class|function)\b"
    r"|\brequire\s*\("
    r"|\bconsole\."
    r"|#include\b",
    re.IGNORECASE | re.ASCII,
)

_WEAK_CODE_RE = re.compile(
    r"\breturn\b"
    r"|\bprint\s*\("
    r"|\blog\s*\("
    r"|=>|->"
    r"|\(\)\s*\{"
    r"|\};"
    r"|://localhost"
    r"|\b0x[0-9a-f]"
    r"|\\x[0-9a-f]"
    r"|\bhashlib\b"
    r"|\bbase64\b"
    r"|\.py\b|\.js\b"
    r"|\b(?:var|const|let)\s",
    re.IGNORECASE | re.ASCII,
)

_PII_CONTEXT_WORDS: dict[str, set[str]] = {
    "kr_rrn": {"주민", "등록", "생년", "신분", "본인확인", "resident", "identification", "birth"},
    "credit_card": {"카드", "결제", "신용", "승인", "명세", "card", "payment", "credit", "billing"},
    "kr_phone": {"전화", "연락", "핸드폰", "모바일", "통화", "phone", "mobile", "contact", "call"},
    "email": {"메일", "연락처", "이메일", "보내기", "수신", "mail", "inbox", "send", "recipient"},
    "kr_passport": {"여권", "출국", "입국", "비자", "공항", "passport", "departure", "visa", "airport"},
    "kr_driver_license": {"면허", "운전", "발급", "경찰", "license", "driving", "police"},
    "us_ssn": {"사회보장", "세금", "납세", "social security", "tax", "taxpayer",
               "고객", "ssn", "미국"},
    "api_key_assignment": {"발급받은", "발급된", "외부", "연동", "서비스키", "issued", "external", "integration",
                           "코드", "리뷰", "키", "key"},
    "aws_access_key": {"클라우드", "배포", "인프라", "계정", "cloud", "deploy", "infra", "account",
                       "설정", "aws", "액세스"},
    "jwt_token": {"로그인", "세션", "인가", "bearer", "login", "session", "auth",
                  "토큰", "token", "디코딩", "decode"},
    "github_pat": {"커밋", "푸시", "리포", "깃허브", "commit", "push", "repo", "github",
                   "깃헙", "토큰", "token"},
    "pem_private_key": {"인증서", "발급", "갱신", "ssl", "certificate", "renew", "private key",
                        "키", "서명", "개인키", "key"},
}

# 코드 문맥 패널티 면제 룰: 소스코드 내 하드코딩 탐지가 목적이므로
# import/def 등 코드 시그널이 있어도 패널티를 적용하지 않는다.
_CODE_PENALTY_EXEMPT: frozenset[str] = frozenset({
    "api_key_assignment",
})

_VALIDATOR_FLOOR = {
    "kr_rrn": 0.8,
    "credit_card": 0.6,
}


def _luhn_check(digits: str) -> bool:
    nums = [int(char) for char in digits if char.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    for index, number in enumerate(reversed(nums)):
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _validate_kr_rrn(match_text: str) -> float:
    digits = re.sub(r"[^0-9]", "", match_text)
    if len(digits) != 13:
        return 0.0
    if len(set(digits)) <= 2:
        return 0.0

    mm = int(digits[2:4])
    dd = int(digits[4:6])
    if not 1 <= mm <= 12:
        return 0.0
    if not 1 <= dd <= 31:
        return 0.0

    gender = int(digits[6])
    if gender not in (1, 2, 3, 4, 9):
        return 0.0

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits[index]) * weights[index] for index in range(12))
    check = (11 - (total % 11)) % 10
    if check != int(digits[12]):
        return 0.0
    return 1.0


def _validate_card(match_text: str) -> float:
    digits = re.sub(r"[^0-9]", "", match_text)
    if len(set(digits)) <= 2:
        return 0.0
    return 1.0 if _luhn_check(match_text) else 0.0


def _is_code_context(ctx_before: str, ctx_after: str) -> bool:
    window = ctx_before + ctx_after
    strong = len(_STRONG_CODE_RE.findall(window))
    weak = len(_WEAK_CODE_RE.findall(window))
    return strong >= 1 or weak >= 2


def _context_multiplier(rule_name: str, ctx_before: str, ctx_after: str) -> float:
    keywords = _PII_CONTEXT_WORDS.get(rule_name)
    if keywords is None:
        return 0.7
    window = (ctx_before + ctx_after).lower()
    hits = sum(1 for keyword in keywords if keyword in window)
    if hits >= 2:
        return 1.3
    if hits == 1:
        return 1.0
    return 0.4


def _select_match_span(match: re.Match, group: int | None = None) -> tuple[str, int, int]:
    if group is None:
        return match.group(), match.start(), match.end()
    value = match.group(group)
    if value is None:
        return match.group(), match.start(), match.end()
    return value, match.start(group), match.end(group)


def _extract_candidate_value(match: re.Match, group: int | None = None) -> str:
    if group is None:
        return match.group()
    value = match.group(group)
    return value if value is not None else match.group()


def _extract_context(
    text: str,
    match_start: int,
    match_end: int,
    all_spans: list[tuple[int, int]],
    context_len: int = 100,
) -> tuple[str, str]:
    ctx_start = max(0, match_start - context_len)
    ctx_end = min(len(text), match_end + context_len)

    for start, end in reversed(all_spans):
        if (start, end) == (match_start, match_end):
            continue
        if ctx_start <= start < match_start:
            ctx_start = start
            break

    for start, end in all_spans:
        if (start, end) == (match_start, match_end):
            continue
        if match_end <= start < ctx_end:
            ctx_end = start
            break

    return text[ctx_start:match_start], text[match_end:ctx_end]


RULES: list[RegexRule] = [
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
    RegexRule(
        name="kr_passport",
        pattern=re.compile(r"\b[A-Z]{1,2}\d{7,8}\b"),
        severity=Severity.HIGH,
        description="한국 여권번호",
    ),
    RegexRule(
        name="kr_driver_license",
        pattern=re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)"),
        severity=Severity.HIGH,
        description="한국 운전면허번호",
    ),
    RegexRule(
        name="kr_phone",
        pattern=re.compile(r"(?<!\d)(?:010|011|016|017|018|019)[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
        severity=Severity.MEDIUM,
        description="한국 휴대전화번호",
    ),
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
    RegexRule(
        name="credit_card",
        pattern=re.compile(r"(?<!\d)(?:\d[-\s]?){13,19}(?!\d)"),
        severity=Severity.CRITICAL,
        validator=_validate_card,
        description="신용카드번호",
    ),
    RegexRule(
        name="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        severity=Severity.LOW,
        description="이메일 주소",
    ),
    RegexRule(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID",
    ),
    RegexRule(
        name="api_key_assignment",
        pattern=re.compile(
            r"(?i)(?:['\"])?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(?:['\"])?"
            r"[\s]*[=:]\s*['\"]?"
            r"([A-Za-z0-9\-_./+=]{16,})"
            r"['\"]?"
        ),
        severity=Severity.HIGH,
        description="API 키/시크릿 할당문",
        value_group=1,
    ),
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
    RegexRule(
        name="jwt_token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.HIGH,
        description="JWT 토큰",
    ),
    RegexRule(
        name="github_pat",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token",
    ),
]


class RegexStage(Stage):
    def __init__(self, control_path: str = DEFAULT_CONTROL_PATH):
        self._control_path = control_path

    @property
    def name(self) -> str:
        return "regex"

    def scan(self, targets: list, findings: list[Finding]) -> list[Finding]:
        del findings
        control = load_control(self._control_path)
        disabled = set(control.disabled_rules)
        new_findings: list[Finding] = []

        # B-3: 현재 control에 등록된 모든 마스킹 토큰 집합 구성
        # (이미 마스킹된 플레이스홀더가 다음 턴에 재탐지되지 않도록)
        known_placeholders = _BUILTIN_PLACEHOLDERS | frozenset(control.mask_templates.values())

        # 빌트인 + 커스텀 규칙 통합
        all_rules = list(RULES)
        for crule in getattr(control, "custom_rules", []):
            if crule.name not in disabled:
                all_rules.append(crule)

        for target in targets:
            text = getattr(target, "text", "")
            if not text or len(text) < 4:
                continue

            raw_matches: list[tuple[RegexRule, str, str, int, int, float, bool]] = []
            for rule in all_rules:
                if rule.name in disabled:
                    continue
                for match in rule.pattern.finditer(text):
                    match_text_raw = match.group()
                    # B-3: 매치된 텍스트가 마스킹 플레이스홀더이면 건너뜀
                    if match_text_raw in known_placeholders or _PLACEHOLDER_RE.fullmatch(match_text_raw):
                        continue
                    has_validator = rule.validator is not None
                    confidence = rule.validator(match_text_raw) if has_validator else 1.0
                    if confidence <= 0.0:
                        continue
                    match_text, match_start, match_end = _select_match_span(match, rule.finding_group)
                    # B-3: span 확인 (finding_group 사용 시 span 값도 재검사)
                    if match_text in known_placeholders or _PLACEHOLDER_RE.fullmatch(match_text):
                        continue
                    candidate_value = _extract_candidate_value(match, rule.value_group)
                    raw_matches.append((
                        rule,
                        match_text,
                        candidate_value,
                        match_start,
                        match_end,
                        confidence,
                        has_validator,
                    ))

            if not raw_matches:
                continue

            all_spans = sorted((match_start, match_end) for _, _, _, match_start, match_end, _, _ in raw_matches)

            for rule, match_text, candidate_value, match_start, match_end, confidence, has_validator in raw_matches:
                ctx_before, ctx_after = _extract_context(text, match_start, match_end, all_spans)
                code_context = False
                multiplier = 1.0
                floor = None

                if control.context_penalty_enabled:
                    code_context = _is_code_context(ctx_before, ctx_after)
                    if code_context and rule.name not in _CODE_PENALTY_EXEMPT:
                        confidence *= 0.3
                    multiplier = _context_multiplier(rule.name, ctx_before, ctx_after)
                    confidence *= multiplier
                    if has_validator:
                        floor = _VALIDATOR_FLOOR.get(rule.name, 0.6)
                        # A-1: 코드 문맥에서는 floor를 대폭 약화
                        # (체크섬 통과만으로 임계값을 넘지 못하도록)
                        if code_context:
                            floor *= 0.35  # RRN 0.8→0.28, Card 0.6→0.21
                        if confidence < floor:
                            confidence = floor
                    confidence = min(confidence, 1.0)

                suppressed = is_allowlisted(rule.name, candidate_value, control.allowlist)
                new_findings.append(Finding(
                    stage=self.name,
                    rule=rule.name,
                    severity=rule.severity,
                    field_path=target.field_path,
                    role=target.role,
                    match_text=match_text,
                    match_start=match_start,
                    match_end=match_end,
                    context_before=ctx_before,
                    context_after=ctx_after,
                    confidence=confidence,
                    suppressed=suppressed,
                    history=getattr(target, "history", False),
                    metadata={
                        "description": rule.description,
                        "candidate_value": candidate_value,
                        "code_context": code_context,
                        "context_multiplier": multiplier,
                        "validator_floor": floor,
                        "allowlisted": suppressed,
                    },
                ))

        return new_findings
