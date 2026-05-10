---
title: "AI Agent DLP Proxy — Regex 파이프라인 구현 심층 분석"
date: 2026-04-19
tags: [dlp, regex, pipeline, pii, security]
draft: false
category: projects
subcategory: github
---

# Regex 파이프라인 구현 심층 분석

> Phase 1 완성 단계에서 구현된 `RegexStage` 전체 설계와 동작 원리를 다룬다.  
> 단순한 패턴 매칭을 넘어 **문맥 보정(Context Correction)** 과 **신뢰도 점수 시스템**을 결합한 구조다.

---

## 전체 파이프라인 아키텍처

```
mitmproxy addon (inspect_traffic.py)
        │ UDS /tmp/dlp-engine.sock
        ▼
  engine_server.py  ←→  DLPTarget 목록
        │
        ▼
  run_pipeline()
    ├─ 1단계: RegexStage   ← 이 문서의 주제
    ├─ 1-2단계: AssetStage  (보호 자산 키워드/임베딩)
    ├─ NMS                  (겹치는 finding 제거)
    └─ 2단계: SLMStage      (선택적, Gemma 2B)
```

파이프라인의 첫 번째이자 가장 빠른 스테이지가 **RegexStage**다. 밀리초 단위로 동작하며 구조화된 PII(주민등록번호, 카드번호, API 키 등)를 잡아낸다.

---

## DLPTarget — 스캔 입력 단위

```python
@dataclass
class DLPTarget:
    field_path: str   # 예: "messages[2].content"
    role: str         # "user" | "assistant" | "system" | "tool_def"
    text: str         # 실제 스캔할 텍스트
    history: bool     # True이면 이전 턴 메시지 (마스킹은 하되 카운트 제외)
```

API 파서(OpenAI/Anthropic/Gemini)가 HTTP 요청 바디에서 `messages` 배열을 파싱한 뒤, 각 메시지를 `DLPTarget`으로 변환해 파이프라인에 전달한다.  
`system`, `tool_def` 역할은 기본적으로 스킵된다(`DEFAULT_SKIP_ROLES`).

---

## Finding — 탐지 결과 단위

```python
@dataclass
class Finding:
    stage: str           # "regex"
    rule: str            # "kr_rrn", "credit_card", ...
    severity: Severity   # LOW / MEDIUM / HIGH / CRITICAL
    field_path: str
    role: str
    match_text: str      # 실제 매치된 문자열
    match_start: int     # target.text 내 시작 오프셋
    match_end: int
    context_before: str  # 매치 앞 최대 100자
    context_after: str   # 매치 뒤 최대 100자
    confidence: float    # 0.0~1.0
    suppressed: bool     # True이면 NMS/allowlist로 억제됨
    history: bool
    metadata: dict       # 디버깅용 부가 정보
```

`confidence`가 `PipelineControl.confidence_threshold`(기본 0.5) 이상이고 `suppressed=False`인 finding만 실제 마스킹/차단에 사용된다.

---

## RegexRule 구조

```python
@dataclass(frozen=True)
class RegexRule:
    name: str
    pattern: re.Pattern
    severity: Severity
    validator: callable | None = None   # 체크섬/구조 검증 함수
    description: str = ""
    finding_group: int | None = None    # 전체 매치 대신 특정 캡처 그룹이 finding
    value_group: int | None = None      # allowlist 비교 시 사용할 값 그룹
```

`finding_group`과 `value_group`을 분리한 이유:  
`api_key_assignment` 룰처럼 `key_name = "실제값"` 형태에서 **`finding_group`은 없고(전체 매치가 finding)** `value_group=1`(실제 키 값)만 allowlist 비교에 쓰는 경우가 있기 때문이다.

---

## 내장 규칙 12개

| 룰 이름 | 설명 | Severity | Validator |
|---|---|---|---|
| `kr_rrn` | 한국 주민등록번호 | CRITICAL | 체크섬 + 날짜 유효성 |
| `credit_card` | 신용카드번호 | CRITICAL | Luhn 알고리즘 |
| `us_ssn` | 미국 사회보장번호 | CRITICAL | 패턴(000/666/9xx 제외) |
| `aws_access_key` | AWS Access Key ID | CRITICAL | — |
| `pem_private_key` | PEM 개인키 블록 | CRITICAL | — |
| `github_pat` | GitHub PAT | CRITICAL | — |
| `kr_passport` | 한국 여권번호 | HIGH | — |
| `kr_driver_license` | 한국 운전면허번호 | HIGH | — |
| `jwt_token` | JWT 토큰 | HIGH | — |
| `api_key_assignment` | API 키/시크릿 할당문 | HIGH | — |
| `kr_phone` | 한국 휴대전화번호 | MEDIUM | — |
| `email` | 이메일 주소 | LOW | — |

---

## 핵심 알고리즘: 신뢰도 점수 계산

RegexStage의 핵심은 패턴 매칭 후 **신뢰도 점수를 다단계로 보정**하는 것이다.

### 1단계: 초기 confidence

```
validator 있음: confidence = validator(match_text)   → 0.0 또는 1.0
validator 없음: confidence = 1.0
```

validator가 0.0을 반환하면 즉시 skip (체크섬/날짜 불일치).

### 2단계: B-3 — 이미 마스킹된 플레이스홀더 재탐지 방지

```python
_BUILTIN_PLACEHOLDERS = frozenset({
    "[주민등록번호]", "[카드번호]", "[SSN]", "[API_KEY]", ...
})
```

이전 대화 턴에서 이미 마스킹된 텍스트(`[주민등록번호]` 등)가 다음 턴 히스토리로 들어올 때 다시 탐지되지 않도록 두 단계에서 차단한다:
- 패턴 매치 직후 → `match_text_raw in known_placeholders`
- `finding_group` span 보정 후 → `match_text in known_placeholders`

### 3단계: A-1 — 코드 문맥 감지 + 패널티

```python
# 강한 코드 시그널 (1개만 있어도 코드 문맥)
_STRONG_CODE_RE = re.compile(
    r"\b(?:import|from|def|class|function)\b"
    r"|\brequire\s*\("
    r"|\bconsole\."
    r"|#include\b",
)

# 약한 코드 시그널 (2개 이상이면 코드 문맥)
_WEAK_CODE_RE = re.compile(
    r"\breturn\b|\bprint\s*\(|\blog\s*\(|=>|->"
    r"|\(\)\s*\{|\};"
    r"|://localhost|\b0x[0-9a-f]|\\x[0-9a-f]"
    r"|\bhashlib\b|\bbase64\b|\.py\b|\.js\b"
    r"|\b(?:var|const|let)\s",
)
```

코드 문맥으로 판정되면:
```
confidence *= 0.3  (70% 페널티)
```

단, `api_key_assignment`는 **소스코드 하드코딩 탐지가 목적**이므로 `_CODE_PENALTY_EXEMPT`에 포함되어 페널티를 받지 않는다.

### 4단계: A-2 — PII 키워드 배율 (줄 단위 컨텍스트)

매치 전후 최대 100자의 컨텍스트에서 룰별 PII 키워드를 검색한다.

```python
_PII_CONTEXT_WORDS = {
    "kr_rrn": {"주민", "등록", "생년", "신분", "resident", ...},
    "credit_card": {"카드", "결제", "신용", "card", "payment", ...},
    "kr_phone": {"전화", "연락", "핸드폰", "phone", "mobile", ...},
    ...
}
```

| 키워드 히트 수 | 배율 |
|---|---|
| 2개 이상 | × 1.3 (PII 컨텍스트 강함) |
| 1개 | × 1.0 |
| 0개 | × 0.6 (컨텍스트 없음, 단독 입력) |

0-hit 배율을 0.4가 아닌 **0.6**으로 설정한 이유:  
0.4 × 1.0(validator) = 0.4 → threshold 0.5 미만이 되어 단독 입력된 전화번호도 탐지 실패.  
0.6으로 설정 시 코드 문맥 페널티(×0.3)와 조합하면 0.6 × 0.3 = 0.18 → 여전히 억제됨.

### 5단계: validator floor 적용

`kr_rrn`, `credit_card`는 체크섬을 통과하면 validator가 1.0을 반환하는데, 코드 문맥 + 컨텍스트 배율 페널티로 최종 confidence가 너무 낮아지는 것을 방지하기 위해 **최소 floor** 를 둔다.

```python
_VALIDATOR_FLOOR = {
    "kr_rrn": 0.8,
    "credit_card": 0.6,
}
```

단, **코드 문맥에서는 floor를 대폭 약화**시킨다:

```python
if code_context:
    floor *= 0.35  # kr_rrn: 0.8 → 0.28, credit_card: 0.6 → 0.21
```

코드 안에 박힌 랜덤 숫자가 우연히 체크섬을 통과해도 낮은 confidence로 억제되도록 하기 위함이다.

### 최종 신뢰도 공식 요약

```
confidence_final = min(
    max(
        initial_confidence
        × code_penalty          (0.3 if 코드문맥, else 1.0)
        × context_multiplier    (1.3 / 1.0 / 0.6),
        validator_floor         (코드문맥 시 × 0.35)
    ),
    1.0
)
```

---

## 컨텍스트 추출 알고리즘

단순히 `text[match_start - 100 : match_start]`를 자르는 게 아니다.  
**같은 텍스트에 여러 매치가 있을 때 컨텍스트가 서로 침범하지 않도록** 인접 매치 경계에서 잘라낸다.

```python
def _extract_context(text, match_start, match_end, all_spans, context_len=100):
    ctx_start = max(0, match_start - context_len)
    ctx_end = min(len(text), match_end + context_len)

    # 앞에 다른 매치가 있으면 그 매치 시작점에서 자름
    for start, end in reversed(all_spans):
        if (start, end) == (match_start, match_end): continue
        if ctx_start <= start < match_start:
            ctx_start = start  # 이 매치의 컨텍스트는 앞 매치 시작점부터
            break

    # 뒤에 다른 매치가 있으면 그 매치 시작점에서 자름
    for start, end in all_spans:
        if (start, end) == (match_start, match_end): continue
        if match_end <= start < ctx_end:
            ctx_end = start
            break

    return text[ctx_start:match_start], text[match_end:ctx_end]
```

이렇게 하면 `context_before`와 `context_after`가 다른 finding의 `match_text`와 중복되지 않아 SLM에 전달할 때 오염이 방지된다.

---

## Allowlist 시스템

```python
@dataclass(frozen=True)
class AllowlistEntry:
    rule: str        # "*" 이면 모든 룰에 적용
    value: str
    normalized: str  # 특수문자/대소문자 제거된 정규화 값
    added_at: str | None
    expires_at: str | None  # ISO 8601, 만료 시 자동 제외
```

정규화는 `re.sub(r"[\W_]+", "", value).casefold()` — 구분자(하이픈, 공백 등)와 대소문자 차이를 무시한다.

allowlist 매치 시 finding은 `suppressed=True`로 표시된다. 완전히 제거하지 않고 **감사 추적(audit trail)** 을 위해 결과에 남겨둔다.

---

## 커스텀 룰 시스템

`/tmp/dlp-control.json`의 `custom_rules` 배열에 룰을 추가하면 **런타임 반영**된다 (파일을 다시 읽기 때문).

```json
{
  "custom_rules": [
    {
      "name": "internal_employee_id",
      "pattern": "EMP-[0-9]{6}",
      "severity": "medium",
      "description": "사내 직원 ID"
    }
  ]
}
```

`_parse_custom_rules()`에서 `re.compile()` 실패 시 해당 룰만 조용히 스킵하여 전체 파이프라인이 멈추지 않는다.

---

## 메시지 캐시 시스템

AI Agent는 매 턴마다 이전 대화 전체를 포함해 전송한다. 10턴짜리 대화라면 마지막 요청에 10개 메시지가 모두 들어있다. 이를 매번 재스캔하면 낭비다.

```python
def _cache_key(field_path, role, text, control_tag) -> str:
    raw = f"{field_path}\x00{role}\x00{text}\x00{control_tag}"
    return hashlib.sha256(raw.encode()).hexdigest()
```

`control_tag`는 `/tmp/dlp-control.json`의 MD5(앞 16자). 룰 추가/삭제/allowlist 변경 시 자동으로 캐시 미스가 발생해 재스캔된다.

| 항목 | 값 |
|---|---|
| TTL | 300초 |
| 최대 크기 | 500 항목 |
| GC | 매 `run_pipeline()` 호출마다 경량 실행 |

---

## NMS (Non-Maximum Suppression)

같은 텍스트 구간에 여러 룰이 동시에 매치되는 경우(예: 전화번호가 카드번호 패턴에도 걸리는 경우) 우선순위가 낮은 finding을 `suppressed=True`로 표시한다.

우선순위: **Severity 높음 > Confidence 높음 > match 길이 긺**

NMS도 감사 추적을 위해 `suppressed_reason: "nms"` 메타데이터와 함께 결과에 남긴다.

---

## RegexStage.scan() 전체 흐름

```
입력: list[DLPTarget], list[Finding](이전 스테이지, 미사용)

1. load_control() — 제어 파일 읽기 (매 스캔마다)
2. BUILTIN_PLACEHOLDERS + control.mask_templates → known_placeholders
3. RULES + control.custom_rules → all_rules
4. 각 target에 대해:
   a. 모든 rule의 pattern.finditer(text)
   b. 매치 → B-3 플레이스홀더 검사 → validator 호출
   c. 모든 raw_matches 수집 + all_spans 정렬
   d. 각 raw_match에 대해:
      - _extract_context() (인접 매치 경계 인식)
      - _is_code_context() (STRONG/WEAK 시그널 검사)
      - code_penalty 적용 (× 0.3)
      - _context_multiplier() (키워드 배율)
      - validator_floor 적용 (코드문맥 시 × 0.35)
      - is_allowlisted() 검사
      - Finding 생성

출력: list[Finding]
```

---

## 주요 엣지케이스와 해결책

### 1. 연속 대화에서 마스킹된 텍스트 재탐지
**문제**: `[주민등록번호]`가 다음 턴에 히스토리로 들어오면 `[주...]` 패턴이 다시 매칭됨  
**해결**: B-3 — `_PLACEHOLDER_RE = re.compile(r"\[[^\]\[\n]{1,30}\]")` 로 모든 플레이스홀더 형태 차단

### 2. 코드 리뷰 요청 시 하드코딩된 전화번호 과탐
**문제**: `phone = "010-1234-5678"` 코드를 리뷰 요청 시 탐지 → 마스킹 후 코드 깨짐  
**해결**: A-1 코드 페널티(×0.3) + 컨텍스트 배율(×0.6) = 최종 0.18 → threshold 미달

### 3. 단독 전화번호 미탐
**문제**: `전화번호: 010-1234-5678` 에서 컨텍스트 키워드 0-hit → 배율 0.4 → 0.4 < 0.5 미탐  
**해결**: 0-hit 배율을 0.6으로 상향 → 0.6 ≥ 0.5 → 탐지됨

### 4. credit_card 코드 내 랜덤 숫자 체크섬 우연 통과
**문제**: 코드 안 숫자열이 Luhn 통과 → confidence=1.0 → 마스킹 오발동  
**해결**: 코드문맥에서 floor를 0.6 × 0.35 = 0.21로 약화 → 페널티 후 0.21 이상이어도 전체 confidence가 threshold 미달

### 5. `api_key_assignment` 코드 문맥 면제
**문제**: API 키 하드코딩 탐지가 목적인데 코드 문맥 페널티를 받으면 탐지 실패  
**해결**: `_CODE_PENALTY_EXEMPT = frozenset({"api_key_assignment"})` — 페널티 적용 제외

---

## 테스트 구조

`tests/run_proto_regex_tests.py` 에서 7개 구역으로 테스트:

1. **기본 정탐(TP) 데이터셋** — 각 룰별 명확한 PII 입력
2. **기본 오탐(FP) 억제 데이터셋** — allowlist, 플레이스홀더 재탐지
3. **현실형 정탐 데이터셋** — 실제 대화 속 PII
4. **현실형 과탐 억제 데이터셋** — 코드 리뷰, 테스트 데이터
5. **미탐 위험(FN Risk) 데이터셋** — 경계값 케이스
6. **과탐 위험(OD Risk) 데이터셋** — 유사 패턴
7. **제어/롤백 회귀 테스트** — `disabled_rules`, `allowlist`, `custom_rules`

```bash
python tests/run_proto_regex_tests.py
```

---

## 성능 특성

| 항목 | 수치 |
|---|---|
| 단일 메시지 스캔 | ~0.2~2 ms (CPU) |
| 캐시 히트 시 | ~0.01 ms 미만 |
| 패턴 수 | 12개 (빌트인) + 커스텀 |
| 컨텍스트 창 | 매치 전후 각 100자 |

---

## 다음 단계 (Phase 2 연계)

RegexStage가 놓치는 **문맥 의존적 PII**(비구조화된 이름, 주소, 직책+소속 조합)는 다음 스테이지에서 보완한다:

- **AssetStage**: 보호 자산 키워드 + 임베딩 유사도 탐지 (이미 구현됨)
- **SLMStage**: Gemma 2B-IT GGUF로 Regex 마스킹 후 텍스트 재검토 (이미 구현됨)

SLM 입력 시 RegexStage findings를 미리 마스킹(`_mask_text_for_slm()`)하여 이미 잡힌 PII는 SLM이 중복 처리하지 않도록 한다.
