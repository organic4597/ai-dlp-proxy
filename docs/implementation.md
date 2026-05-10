# AI DLP Proxy — 구현 상세 문서

> 작성일: 2026-04-18 · 최종 수정: 2026-05-10 (Copilot 파서·보호 finding 분리·대시보드 통합)  
> 대상: 개발자 · 유지보수 담당자

---

## 목차

1. [전체 아키텍처](#1-전체-아키텍처)
2. [DLP 파이프라인](#2-dlp-파이프라인)
3. [RegexStage 문맥 보정 로직](#3-regexstage-문맥-보정-로직)
4. [대화 히스토리 처리와 API 파서](#4-대화-히스토리-처리와-api-파서)
5. [마스킹 파이프라인](#5-마스킹-파이프라인)
6. [커스텀 탐지 규칙](#6-커스텀-탐지-규칙)
7. [제어 정책](#7-제어-정책)
8. [TUI 대시보드](#8-tui-대시보드)
9. [웹 대시보드](#9-웹-대시보드)
10. [성능 최적화](#10-성능-최적화)
11. [테스트 구조](#11-테스트-구조)
12. [알려진 제한사항 및 설계 결정](#12-알려진-제한사항-및-설계-결정)

---

## 1 전체 아키텍처

```
외부 PC / opencode (게이트웨이 경유)
    │  iptables PREROUTING → 서버:4001 (투명 프록시)
    ▼
mitmproxy :4001 transparent (inspect_traffic.py)
    │  HTTPS 복호화
    │  API 파서 (openai / anthropic / gemini / copilot)
    │  └─ DLPTarget 추출 (field_path, role, text, history)
    └─ DLP 엔진 요청 (UDS /tmp/dlp-engine.sock)

VS Code Remote extensionHost (root 프로세스)
    │  http.proxy = http://127.0.0.1:4002 (명시 프록시)
    ▼
mitmproxy :4002 regular (동일 inspect_traffic.py)
    │  HTTPS 복호화
    │  GitHub Copilot 전용 파서 (copilot.py)
    │   ├─ /models/session → 데이터 있으면 스캔, 없으면 skip
    │   ├─ /chat/completions 제목 wrapper → 실제 사용자 요청만 로그/요약
    │   ├─ progress/tool-summary 보조 → sidecar 프롬프트 제외, 데이터만 보호
    │   └─ /v1/messages → Anthropic 파서 위임
    └─ DLP 엔진 요청 (동일 UDS)

engine_server.py
    │  NDJSON 프로토콜 (비동기 asyncio)
    │  UDS /tmp/dlp-engine.sock
    └─ DLP Pipeline
         ├─ RegexStage  ─ 12개 빌트인 + 사용자 정의 규칙
         ├─ AssetStage  ─ 보호 자산 키워드/임베딩 탐지
         ├─ SLMStage    ─ 문맥의존 PII (Gemma 4 2B, 선택적)
         └─ MLFilter    ─ XGBoost FP 억제 (선택적)

tui.py (Textual TUI) — 로컬 터미널 대시보드
    └─ 7탭 실시간 대시보드 · 제어판

web/ (FastAPI + SvelteKit 웹 대시보드) — 포트 8765/5173
    └─ 10페이지 브라우저 대시보드 · 원격 접근 가능
```

### 데이터 흐름

```
HTTP 요청
  → inspect_traffic.py (mitmproxy addon)
    → API 파서 (openai/anthropic/gemini/copilot)
      → DLPTarget 리스트 (field_path, role, text, history)
        → engine_server.scan()
          → run_pipeline(scan_targets)
            → RegexStage.scan()  → Finding 리스트
            → AssetStage.scan()  → Finding 리스트 추가
            → NMS(겹침 제거)
            → [SLMStage.scan()]  → Finding 리스트 추가
          → PipelineResult (action, findings, elapsed_ms)
        → engine_server 응답
            findings[]            — 이번 턴 신규 (history=False) 전용: 대시보드 카운트/DB
            protection_findings[] — 모든 finding (history 포함): 실제 마스킹 결정
            pipeline_action       — 신규 finding 기준 판정
            protection_action     — 전체 finding 기준 판정 (마스킹 드라이버)
      → inspect_traffic: 마스킹 적용 (protection_action + protection_findings)
        → flow.request.content 교체
  → LLM 서버 전달
```

---

## 2 DLP 파이프라인

### 2-1. 스테이지 구성

| 스테이지 | 파일 | 역할 |
|---|---|---|
| `RegexStage` | `engine/pipeline/regex_stage.py` | 패턴 매칭 + 문맥 보정 |
| `AssetStage` | `engine/pipeline/asset_stage.py` | 보호 자산 탐지 (키워드/임베딩) |
| `SLMStage` | `engine/pipeline/slm_stage.py` | 문맥의존 PII, 선택적 활성화 (Gemma 4 2B) |
| `MLFilter` | `engine/pipeline/ml_filter.py` | XGBoost 기반 False Positive 억제, 선택적 |

### 2-2. Finding 데이터구조

`src/ai_dlp_proxy/engine/pipeline/base.py`

```python
@dataclass
class Finding:
    stage: str           # "regex" | "asset" | "slm"
    rule: str            # 규칙 이름
    severity: Severity   # CRITICAL / HIGH / MEDIUM / LOW
    field_path: str      # "messages[2].content" 등 원본 JSON 경로
    role: str            # "user" | "tool_result" | "tool_call" 등
    match_text: str      # 매칭된 원본 텍스트 (마스킹 대상)
    match_start: int     # target.text 내 시작 오프셋
    match_end: int       # target.text 내 끝 오프셋
    context_before: str  # 매치 앞 최대 100자
    context_after: str   # 매치 뒤 최대 100자
    confidence: float    # 0.0 ~ 1.0
    suppressed: bool     # NMS 또는 allowlist에 의해 억제됨
    history: bool        # True = 이전 턴 히스토리 (마스킹 적용, 카운트 제외)
    metadata: dict       # 부가 정보 (code_context, candidate_value 등)
```

### 2-3. 메시지 해시 캐시

`engine/pipeline/__init__.py`

- 각 `DLPTarget`의 `(field_path + role + text + control_tag)` → SHA-256 캐시 키
- **캐시 히트**: 이전 스캔 결과 재사용, RegexStage 생략
- **캐시 미스**: 새로 스캔 후 저장
- `control_tag`: 제어 파일 내용의 MD5 해시 — 설정 변경 시 자동 캐시 무효화
- TTL: 300초, 최대 500항목

```python
# 캐시 키 생성
def _cache_key(field_path, role, text, control_tag) -> str:
    raw = f"{field_path}\x00{role}\x00{text}\x00{control_tag}"
    return hashlib.sha256(raw.encode()).hexdigest()
```

### 2-4. NMS (Non-Maximum Suppression)

- 같은 `field_path`에서 매칭 span이 **겹치는** finding 중 낮은 우선순위는 `suppressed=True`
- 우선순위: `Severity(높음) > Confidence(높음) > 매칭 길이(김)`
- 억제된 finding도 리포트에 남아 감사 추적 가능

### 2-5. Action 결정

```python
def _decide_action(findings, threshold=0.5) -> Action:
    effective = [f for f in findings if f.confidence >= threshold and not f.suppressed]
    if not effective:
        return Action.PASS
    max_sev = max(f.severity.value for f in effective)
    if max_sev >= Severity.CRITICAL.value:
        return Action.MASK
    if max_sev >= Severity.HIGH.value:
        return Action.ALERT
    return Action.ALERT
```

> **중요**: 이 함수는 두 곳에서 호출됩니다.  
> - `pipeline_action` 결정 시: 신규 finding(`history=False`)만 전달 → 대시보드 카운트/표시용  
> - `protection_action` 결정 시: 히스토리 포함 전체 finding 전달 → 실제 마스킹 드라이버  
> `finding_count`/`effective_finding_count` 집계에는 신규 finding만 사용됩니다.

---

## 3 RegexStage 문맥 보정 로직

`src/ai_dlp_proxy/engine/pipeline/regex_stage.py`

### 3-1. 빌트인 규칙 (12개)

| 규칙 | 심각도 | validator | 설명 |
|---|---|---|---|
| `kr_rrn` | CRITICAL | mod-11 체크섬 + 날짜/성별코드 | 주민등록번호 |
| `credit_card` | CRITICAL | Luhn 알고리즘 | 신용카드번호 |
| `us_ssn` | CRITICAL | — | 미국 사회보장번호 |
| `aws_access_key` | CRITICAL | — | `AKIA/ABIA/ACCA/ASIA` 접두어 |
| `pem_private_key` | CRITICAL | — | BEGIN/END PRIVATE KEY 블록 |
| `github_pat` | CRITICAL | — | `ghp_/gho_/ghu_/ghs_/ghr_` 접두어, 36자+ |
| `kr_passport` | HIGH | — | 한국 여권번호 (1~2알파+7~8숫자) |
| `kr_driver_license` | HIGH | — | 운전면허 (`NN-NN-NNNNNN-NN`) |
| `jwt_token` | HIGH | — | 3-part base64 구조 (`eyJ...`) |
| `api_key_assignment` | HIGH | — | `api_key = "..."` 형태 할당문 |
| `kr_phone` | MEDIUM | — | 010/011/016/017/018/019 |
| `email` | LOW | — | RFC 5322 단순화 패턴 |

### 3-2. 문맥 보정 파이프라인

```
[패턴 매칭 결과]
    │
    ├─ [B-3] 플레이스홀더 재탐지 차단
    │        match_text ∈ known_placeholders → 스킵
    │
    ├─ [validator] 체크섬/Luhn 검증
    │        confidence = 0.0이면 제외
    │
    ├─ [A-1] 코드 문맥 감지
    │        Strong: import/def/class/require/console/#include → ×0.3
    │        Weak (2개 이상): return/print/log/=>/->/etc. → ×0.3
    │        예외: api_key_assignment (코드 내 하드코딩이 목적)
    │
    ├─ [컨텍스트 승수] PII 관련 키워드 수
    │        2+개 → ×1.3
    │        1개  → ×1.0
    │        0개  → ×0.4
    │
    └─ [validator floor] 체크섬 통과 시 하한 보장
             kr_rrn:      floor = 0.8 (코드 문맥 시 0.8 × 0.35 = 0.28)
             credit_card: floor = 0.6 (코드 문맥 시 0.6 × 0.35 = 0.21)
             기타:        floor = 0.6
```

**A-1 (코드 문맥 floor 약화)**  
코드 문맥에서 validator(체크섬/Luhn)가 통과했을 때 floor를 `×0.35`로 약화:
- `kr_rrn` 코드 문맥: `0.8 × 0.35 = 0.28` → threshold 0.5 미만 → pass
- 실제 PII 문맥: floor = 0.8, 컨텍스트 배율 적용 → threshold 초과 → 탐지

**B-3 (플레이스홀더 재탐지 차단)**  
```python
_BUILTIN_PLACEHOLDERS = frozenset({
    "[주민등록번호]", "[전화번호]", "[카드번호]", "[SSN]", ...
})
_PLACEHOLDER_RE = re.compile(r"\[[^\]\[\n]{1,30}\]")

# 스캔 시 체크
if match_text in known_placeholders or _PLACEHOLDER_RE.fullmatch(match_text):
    continue  # 이미 마스킹된 플레이스홀더 스킵
```
`known_placeholders = BUILTIN_PLACEHOLDERS ∪ control.mask_templates.values()`

### 3-3. 컨텍스트 윈도우 추출 (`_extract_context`)

- 매치 앞뒤 ±100자 추출
- 동일 텍스트의 다른 매치 위치에서 경계를 자름 (중복 컨텍스트 방지)

---

## 4 대화 히스토리 처리와 API 파서

### 4-1. 문제

LLM API는 매 요청마다 이전 대화를 `messages` 배열에 포함합니다.  
대화가 길어질수록 이전 턴의 user 메시지가 누적되어 매 요청마다 재탐지됩니다.

```
턴 1: [user: CSV(PII 71건)]               탐지: 71건 ✓
턴 2: [user: CSV][assistant][user: "안녕"] 탐지: 71건 (히스토리) + 0건 = 71건 중복
턴 3: ...                                  탐지: 142건 중복 (지수적 증가)
```

### 4-2. 해결책: history 플래그

**`DLPTarget.history: bool`** (base.py)  
- `True`: 이전 턴 히스토리 메시지 (마지막 assistant 이전)
- `False`: 현재 턴 새 메시지 (마지막 assistant 이후, 기본값)

마스킹은 모든 메시지에 적용, 카운트/ftable은 새 메시지만.

### 4-3. API 파서별 구현

**OpenAI** (`api/openai.py`)
```python
last_assistant_idx = -1
for i, msg in enumerate(messages):
    if msg.get("role") == "assistant":
        last_assistant_idx = i

for i, msg in enumerate(messages):
    is_hist = i <= last_assistant_idx
    # role이 assistant/system/tool이 아닌 경우에만 추출
    targets.append(DLPTarget(..., history=is_hist))
```

**Anthropic** (`api/anthropic.py`)
```python
last_assistant_idx = -1
for i, msg in enumerate(messages):
    if msg.get("role") == "assistant":
        last_assistant_idx = i

for i, msg in enumerate(messages):
    if msg.get("role") != "user":
        continue
    is_hist = i <= last_assistant_idx
    _extract_user_content(content, path, targets, history=is_hist)
```

**Gemini** (`api/gemini.py`)
```python
last_model_idx = -1
for i, content in enumerate(contents):
    if content.get("role") == "model":
        last_model_idx = i
# role == "model" (= assistant) 제외 + is_hist = i <= last_model_idx
```

**GitHub Copilot** (`api/copilot.py`) ← 신규 (2026-05-10)

VS Code Copilot은 실제 사용자 대화 외에 내부 보조 요청을 동일 API로 보낸다.  
이 파서는 요청 종류를 분류해 실제 사용자 데이터만 DLP 대상으로 전달한다.

| 요청 유형 | 판별 기준 | 처리 |
|---|---|---|
| 세션 메타데이터 | `/models/session` | 데이터 있으면 스캔, 없으면 skip |
| 제목 생성 | last user message: `Please write a brief title for the following request: <요청>` | wrapper 포함 전체를 마스킹 target으로, 로그/요약에는 내부 `<요청>`만 |
| progress 생성 | last user message: `Please generate exactly 10 unique progress messages…` | 보조 프롬프트 제외; 히스토리·tool_result 등 data target은 보호 유지 |
| tool group 요약 | `groups of tools` + `provide a name and summary` | 동일: 보조 프롬프트 제외 |
| 일반 대화 | 그 외 `/chat/completions` | OpenAI 파서 위임 |
| Anthropic 포맷 | `/v1/messages` 경로 | Anthropic 파서 위임 |

```python
# copilot.py 핵심 로직
def _openai_sidecar_target(provider, url, body) -> ParsedRequest | None:
    last = _last_user_message(body)  # 마지막 user 메시지 텍스트
    if last is None:
        return _openai.parse(...)    # user 없으면 OpenAI 파서

    # 이전 대화·tool_result 등 데이터 bearing target은 보존
    data_targets = [t for t in all_targets if t.history or t.role in ('tool_result','tool_call','metadata')]

    if _title_inner(text):           # 제목 wrapper → 전체 스캔 + data_targets
        return ParsedRequest(targets=[title_target, *data_targets])
    if _is_sidecar_prompt(text):     # progress/tool-summary → data_targets만
        return ParsedRequest(targets=data_targets) if data_targets else None
    return _openai.parse(...)        # 일반 대화 → OpenAI 파서
```

### 4-4. 스캔 범위 결정 (role 기준)

| Provider | 스캔 포함 | 스캔 제외 |
|---|---|---|
| OpenAI | `user`, `tool_call`, `tool_result` | `assistant`, `system`, `tool_def` |
| Anthropic | `user`, `tool_result` | `assistant`, `system`, `tool_def` |
| Gemini | `user`, `functionResponse` | `model`(=assistant), `systemInstruction`, `tool_def` |
| GitHub Copilot (chat) | `user`(현재턴), `tool_call`, `tool_result`, 히스토리 | sidecar 보조 프롬프트 텍스트 자체 |

`assistant` 제외 이유: LLM이 생성한 텍스트는 외부에서 제어할 수 없으며, 히스토리로 다시 포함될 때 이전 PII 분석 내용이 재탐지되는 것을 방지합니다.

### 4-5. engine_server의 finding 이중 분리

```python
# history finding 분리
new_findings       = [f for f in result.findings if not f.history]
protection_findings = list(result.findings)   # 히스토리 포함 전체

raw_finding_count       = len(new_findings)         # 대시보드 카운트 (신규만)
effective_finding_count = len([f for f in new_findings if not f.suppressed and f.confidence >= threshold])
history_finding_count   = len(protection_findings) - raw_finding_count

# engine_server 응답에 두 목록 모두 포함
{
  "findings":            [...],  # 대시보드/DB: 신규 finding만
  "protection_findings": [...],  # 마스킹: 히스토리 포함 전체
  "pipeline_action":     "pass", # 신규 finding 기준 판정
  "protection_action":   "alert",# 전체 finding 기준 판정 → 마스킹 드라이버
  "history_finding_count": 1,
  "protection_finding_count": 2,
}
```

### 4-6. 결과

```
턴 1: [user: CSV(PII 71건)]               탐지: 71건 ✓ 마스킹: 71건 ✓
턴 2: [user: CSV][assistant][user: "안녕"]
       CSV findings: history=True → DB/대시보드 카운트 제외, 마스킹 적용 ✓
       "안녕" findings: history=False → 탐지: 0건
       → 표시 탐지: 0건 ✓  보호: history finding → LLM에 전달되는 CSV 여전히 마스킹 ✓

Copilot progress 보조 요청 (사이드카):
       sidecar 프롬프트: 스캔 제외
       포함된 tool_result 010-1234-5678: 신규 finding → 탐지 + 마스킹 ✓
       포함된 이전 대화 PII: history finding → 마스킹은 적용, 카운트는 제외 ✓
```

---

## 5 마스킹 파이프라인

### 5-1. 마스킹 적용 위치

`scripts/inspect_traffic.py` — `_apply_mask()` 함수

```python
def _apply_mask(body_obj, findings, mask_templates) -> dict:
    # field_path 별 findings 그룹화
    # 각 field_path의 원본 텍스트를 역순(offset 내림차순)으로 치환
    # Content-Length 자동 재계산
```

### 5-2. 기본 마스킹 텍스트 (치환 레이블)

`src/ai_dlp_proxy/engine/pipeline/masking.py`

| 규칙 | 기본값 |
|---|---|
| `kr_rrn` | `[주민등록번호]` |
| `credit_card` | `[카드번호]` |
| `kr_phone` | `[전화번호]` |
| `email` | `[이메일]` |
| `kr_passport` | `[여권번호]` |
| `kr_driver_license` | `[운전면허]` |
| `aws_access_key` | `[AWS_KEY]` |
| `github_pat` | `[GH_TOKEN]` |
| `api_key_assignment` | `[API_KEY]` |
| `pem_private_key` | `[PRIVATE_KEY]` |
| `jwt_token` | `[JWT]` |
| `us_ssn` | `[SSN]` |

### 5-3. 마스킹 흐름

```
engine 응답에서:
  protection_action  ← "mask" | "alert" | "pass"
  protection_findings ← 히스토리 포함 전체 finding

inspect_traffic._apply_mask() 호출 조건:
  protection_action ≠ "pass"
  AND mask_on_detect = true
  AND protection_effective_findings 존재
    (= protection_findings에서 confidence≥threshold AND not suppressed)
    ↓
_apply_mask(body_obj, protection_effective_findings, mask_templates)
    ↓
masked_bytes = json.dumps(masked_body, ensure_ascii=False).encode()
flow.request.content = masked_bytes
flow.request.headers["content-length"] = str(len(masked_bytes))
    ↓
LLM 서버로 마스킹된 요청 전달
    ↓
엔진에 applied_result 전송 (dlp_applied 값: masked | passed | blocked)
```

> **요점**: `protection_findings`를 마스킹 기준으로 사용하기 때문에  
> 이전 턴 히스토리에 PII가 있으면 신규 탐지 카운트가 0이어도 해당 내용은 마스킹됩니다.

### 5-4. 마스킹 텍스트 우선순위

```
커스텀 규칙 mask_template > 사용자 설정(control.json) > 기본값
```

`merge_mask_templates(user_templates, allow_custom=True)`

---

## 6 커스텀 탐지 규칙

### 6-1. 구조

`control.json`의 `custom_rules` 배열에 정의:

```json
{
  "custom_rules": [
    {
      "name": "project_code",
      "pattern": "PRJ-[A-Z]{3}-\\d{4}",
      "severity": "high",
      "description": "내부 프로젝트 코드",
      "mask_template": "[프로젝트코드]"
    }
  ]
}
```

| 필드 | 필수 | 설명 |
|---|---|---|
| `name` | ✅ | 규칙 고유 이름 (중복 불가) |
| `pattern` | ✅ | Python 정규식 |
| `severity` | — | `critical/high/medium/low` (기본: `high`) |
| `description` | — | 설명 텍스트 |
| `mask_template` | — | 치환 레이블 (없으면 `[name]`) |

### 6-2. 파이프라인 통합

`regex_stage.py` 스캔 시:

```python
all_rules = list(RULES)  # 빌트인 12개
for crule in getattr(control, "custom_rules", []):
    if crule.name not in disabled:
        all_rules.append(crule)
```

### 6-3. TUI에서 관리

`🎭 마스킹 규칙` 카드에서 통합 관리:
- 빌트인 규칙과 커스텀 규칙이 같은 테이블에 표시 (커스텀은 `🔧` 배지)
- `➕ 커스텀` 버튼: 규칙 추가 (이름/패턴/심각도/설명/치환 텍스트 입력)
- `✏️ 편집` 버튼: 선택된 커스텀 규칙 수정
- `🗑` 버튼: 삭제 (빌트인 규칙에는 비활성)

---

## 7 제어 정책

기본 경로: `/tmp/dlp-control.json`  
TUI 제어탭 또는 직접 편집으로 실시간 반영 (엔진 재시작 불필요)

### 전체 스키마

```json
{
  "regex_enabled": true,
  "asset_enabled": true,
  "slm_enabled": false,
  "ml_filter_enabled": false,
  "ml_filter_threshold": 0.4,
  "context_penalty_enabled": true,
  "confidence_threshold": 0.5,
  "mask_on_detect": false,
  "block_on_alert": false,
  "block_on_mask": false,
  "disabled_rules": [],
  "skip_roles": ["system", "tool_def"],
  "mask_templates": {
    "kr_rrn": "[주민등록번호]"
  },
  "allowlist": [
    {
      "rule": "kr_rrn",
      "value": "000000-0000000",
      "normalized": "0000000000000",
      "added_at": "2026-04-01T00:00:00Z",
      "expires_at": null
    }
  ],
  "custom_rules": [
    {
      "name": "project_code",
      "pattern": "PRJ-[A-Z]{3}-\\d{4}",
      "severity": "high",
      "description": "내부 프로젝트 코드",
      "mask_template": "[프로젝트코드]"
    }
  ]
}
```

### 필드 설명

| 필드 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `regex_enabled` | bool | `true` | RegexStage 활성화 |
| `asset_enabled` | bool | `true` | AssetStage 활성화 |
| `slm_enabled` | bool | `false` | SLMStage 활성화 (Gemma 4 2B, GPU 권장) |
| `ml_filter_enabled` | bool | `false` | ML FP 필터 활성화 (XGBoost) |
| `ml_filter_threshold` | float | `0.4` | ML FP 필터 TP 확률 임계값 |
| `context_penalty_enabled` | bool | `true` | A-1 코드 문맥 패널티 활성화 |
| `confidence_threshold` | float | `0.5` | 이 값 이상의 finding만 유효 처리 |
| `mask_on_detect` | bool | `false` | 탐지 시 마스킹 후 통과 |
| `block_on_alert` | bool | `false` | ALERT 이상 탐지 시 403 차단 |
| `block_on_mask` | bool | `false` | MASK/BLOCK 탐지 시 403 차단 |
| `disabled_rules` | list | `[]` | 비활성화할 규칙 이름 목록 |
| `skip_roles` | list | `["system","tool_def"]` | 스캔에서 제외할 메시지 role |
| `mask_templates` | dict | 기본값 테이블 | 규칙별 치환 레이블 재정의 |
| `allowlist` | list | `[]` | 허용 목록 (false positive 억제) |
| `custom_rules` | list | `[]` | 사용자 정의 RegexRule |

### 정책 우선순위

```
mask_on_detect (우선) > block_on_mask / block_on_alert (차선)
```
`mask_on_detect=true`이면 block 정책은 무시됩니다.

### allowlist 동작

- `rule: "*"`: 모든 규칙에서 해당 값을 억제
- `rule: "kr_rrn"`: 해당 규칙에서만 억제
- `normalized`: 알파벳/숫자만 추출 + casefold → 포맷 차이 무관 매칭
- `expires_at`: 설정 시 해당 시각 이후 자동 만료

---

## 8 TUI 대시보드

`scripts/tui.py` — Textual 8.2.2 기반

### 8-1. 탭 구성

| 탭 (단축키) | 내용 |
|---|---|
| 트래픽 (`F1`) | 턴 테이블 + 요청 상세 (탐지정보/전송내용) |
| 탐지 목록 (`F2`) | finding 전체 목록 (최대 200건) + 상세 |
| 제어 (`F3`) | 정책 스위치 · 마스킹 규칙 · 자산 · 허용목록 |
| 프로세스 (`F4`) | engine/mitm 프로세스 상태 · 시작/중지/재시작 |
| 설정 (`F5`) | 포트 · 대상 도메인 설정 |
| 파이프라인 (`F6`) | 규칙별 탐지 횟수 · Regex/SLM 통계 |
| 엔진 로그 (`F7`) | 실시간 이벤트 스트림 |

### 8-2. 마스킹 규칙 카드

- `🎭 마스킹 규칙` 카드에 빌트인 + 커스텀 규칙 통합 표시
- 행 클릭: ON/OFF 즉시 토글 (disabled_rules 갱신)
- 커스텀 규칙: `🔧` 배지로 구분
- 단일 액션 행 (`mask-action-row`):
  ```
  [선택 규칙 치환 텍스트 입력] [저장] [기본값] [➕커스텀] [✏️편집] [🗑]
  ```

### 8-3. finding 표시 정책

| 항목 | 설명 |
|---|---|
| ftable 최대 행 | 200행 (초과 시 앞에서부터 제거) |
| history finding | ftable에 표시하지 않음 (이전 턴에서 이미 표시됨) |
| 마스킹 규칙 히트 카운트 | history finding 제외 |
| 턴 상세 `히스토리=N` | 히스토리 finding 건수 별도 표시 |

### 8-4. TUI 내부 성능 최적화

| 최적화 | 내용 |
|---|---|
| `ttable update_cell` | 기존 행 갱신 시 `remove+add` 대신 `update_cell()` — 커서 위치 유지 |
| `_finding_counter` | 단조증가 카운터로 row key 생성 (trim 후 중복 방지) |
| `batch_update()` | 히스토리 로딩 + 실시간 배치를 `with self.batch_update():` 내에서 처리 |
| 히스토리 2단계 로딩 | 1단계: 전 이벤트 turn/stats 계산 (ftable 제외), 2단계: 마지막 200개 finding만 ftable 삽입 |
| `RichLog max_lines` | dlog=500, dsent=300, fdetail=300, elog=2000 |
| `_bump_pending` | 마스킹 규칙 히트 카운트를 `call_later()` 배치로 처리 (매 finding마다 테이블 갱신 방지) |
| 중복 렌더 방지 | `_selected_turn_id` 캐시로 동일 턴 재선택 시 skip |

---

## 9 웹 대시보드

> 구현 완료: 2026-05-10 · 최종 수정: 2026-05-10 (/control 통합, 데이터 초기화 추가)  
> 위치: `ai-dlp-proxy/web/`

TUI와 동일한 기능을 브라우저에서 제공하는 실시간 웹 대시보드입니다. 원격 접근이 가능하며 TUI와 독립적으로 운영됩니다.

### 9-1. 기술 스택

| 구성요소 | 기술 | 비고 |
|---|---|---|
| 백엔드 API | FastAPI + uvicorn | 포트 8765, `web/backend/` |
| 데이터베이스 | SQLite WAL + aiosqlite | `~/.config/ai-dlp-proxy/db/dlp.db` |
| 프론트엔드 | SvelteKit 2 + Svelte 5 runes | 포트 5173 (dev) |
| 스타일 | Tailwind CSS v4 | 다크 테마 (`#0f172a` 배경) |
| 실시간 스트림 | SSE (Server-Sent Events) | `/api/events` 단방향 push |
| 차트 | Chart.js | 파이프라인 시계열, 히스토그램 |

### 9-2. 페이지 구성 (10개)

| 경로 | 설명 | 주요 기능 |
|---|---|---|
| `/traffic` | 실시간 트래픽 | SSE 행 prepend, 7개 통계 카드, 요청 상세 패널 |
| `/findings` | 탐지 목록 | 심각도/규칙/억제 필터, 룰별 통계 사이드바 |
| `/pipeline` | 파이프라인 현황 | 플로우 다이어그램, 캐시 히트율, SLM 통계, Chart.js 시계열 |
| `/settings` | **제어 & 설정 (통합)** | 5개 스테이지 토글, 3개 액션 토글, 임계값 슬라이더, Skip Roles, 허용목록 CRUD, 데이터 초기화 |
| `/rules` | 탐지 룰 관리 | 커스텀 룰 CRUD, 빌트인 룰 ON/OFF 토글 |
| `/assets` | 보호 자산 관리 | 자산 그리드, 모달 폼, 임베딩 임계값 슬라이더, 기본값 복원 |
| `/allowlist` | 허용목록 & 마스킹 | 예외값 CRUD, 만료일 관리, 마스킹 템플릿 편집 패널 |
| `/audit` | 감사 로그 | 날짜 범위 필터, CSV 내보내기, JSONL 마이그레이션 |
| `/logs` | 엔진 로그 | SSE 실시간 스트리밍, 레벨 필터, 일시정지, 자동 스크롤 |
| `/process` | 프로세스 관리 | engine/mitmproxy 상태 카드, 시작/중지 버튼 |

> `/control` 경로는 `/settings`로 자동 리다이렉트됩니다.

### 9-3. 백엔드 라우터 구조

```
web/backend/
  main.py              ← FastAPI 앱, CORS, 라우터 등록
  db.py                ← aiosqlite 연결·마이그레이션·자동 정리
  engine_client.py     ← Unix Socket /tmp/dlp-engine.sock 통신
  event_bus.py         ← SSE fan-out 브로드캐스터
  workers.py           ← 엔진 subscribe 루프, scan_applied → DB 업데이트
  models.py            ← Pydantic 스키마 (ControlIn/Out, RequestOut, FindingOut 등)
  settings.py          ← 환경변수 설정 (포트, DB 경로)
  routers/
    events.py          ← GET /api/events  (SSE 스트림)
    traffic.py         ← GET /api/traffic · DELETE /api/traffic
    findings.py        ← GET /api/findings
    pipeline.py        ← GET /api/pipeline/stats
    control.py         ← GET/PUT /api/control
    rules.py           ← GET/POST/PUT/DELETE/PATCH /api/rules
    assets.py          ← GET/POST/PUT/DELETE /api/assets
    allowlist.py       ← GET/POST/DELETE /api/allowlist
    audit.py           ← GET /api/audit, POST /api/audit/export-csv
    logs.py            ← GET /api/logs · DELETE /api/logs
    process.py         ← GET/POST /api/process
```

### 9-4. 주요 API 엔드포인트

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/events` | SSE 스트림 (scan·log 이벤트 실시간 push) |
| GET | `/api/traffic` | 최근 요청 목록 (DB 조회, 페이징) |
| **DELETE** | **`/api/traffic`** | **트래픽 기록 전체 삭제 (requests + findings)** |
| GET | `/api/findings` | 탐지 목록 (rule/severity/suppressed/status 필터) |
| GET | `/api/pipeline/stats` | 파이프라인 누적 통계 + 시계열 스냅샷 |
| GET/PUT | `/api/control` | 제어 파일 조회·수정 |
| GET | `/api/rules` | 빌트인(12개) + 커스텀 룰 목록 |
| POST | `/api/rules` | 커스텀 룰 추가 (정규식 검증 포함) |
| PUT | `/api/rules/{name}` | 커스텀 룰 수정 |
| DELETE | `/api/rules/{name}` | 커스텀 룰 삭제 |
| PATCH | `/api/rules/{name}/toggle` | 룰 활성/비활성 토글 |
| GET | `/api/assets` | 보호 자산 목록 |
| POST | `/api/assets` | 자산 추가 (UUID ID 자동 생성) |
| PUT | `/api/assets/{id}` | 자산 수정 |
| DELETE | `/api/assets/{id}` | 자산 삭제 |
| POST | `/api/assets/reset-defaults` | 기본 씨드 자산 복원 |
| GET | `/api/allowlist` | 허용목록 (rule/expired 필터) |
| POST | `/api/allowlist` | 항목 추가 (중복·만료일 검증) |
| DELETE | `/api/allowlist/{idx}` | 인덱스로 삭제 |
| DELETE | `/api/allowlist/purge-expired` | 만료 항목 일괄 삭제 |
| GET | `/api/audit` | 감사 로그 (날짜 범위, 페이징) |
| POST | `/api/audit/export-csv` | CSV 파일 다운로드 |
| GET | `/api/logs` | 엔진 로그 조회 |
| **DELETE** | **`/api/logs`** | **엔진 로그 전체 삭제** |
| GET | `/api/process` | 프로세스 상태 조회 |
| POST | `/api/process/start` | engine/mitmproxy 시작 |
| POST | `/api/process/stop` | engine/mitmproxy 중지 |

#### findings 상태 필터 (`/api/findings?status=`)

| 값 | 의미 |
|---|---|
| `effective` | 신뢰도 ≥ threshold & 억제 아님 (정책 유효 탐지) |
| `suppressed` | NMS 또는 allowlist 억제 (`suppressed=true`) |
| `below_threshold` | 신뢰도 < threshold (신뢰도 미달) |

### 9-5. 실시간 데이터 흐름

```
mitmproxy addon
    → engine_server.py  action=subscribe
    → FastAPI EngineClient (상시 연결)
      → asyncio.Queue
      → EventBroadcaster (fan-out)
        → 모든 SSE 클라이언트 (Browser EventSource)
          → Svelte $state 업데이트 → DOM 반응적 반영
```

엔진 로그는 `action=log_subscribe`를 통해 별도 SSE 타입(`type:"log"`)으로 전달됩니다.

### 9-6. 실행 방법

```bash
# 전체 서비스 (supervisor 이용)
./dlp-supervisor start          # engine + mitmproxy + web backend

# 개별 실행
cd web/backend
uvicorn main:app --host 127.0.0.1 --port 8765 --reload

# 프론트엔드 dev 서버
cd web/frontend
npm run dev -- --host 0.0.0.0 --port 5173

# 프로덕션 빌드
cd web/frontend && npm run build
```

### 9-7. 보호 자산 파일 위치

| 파일 | 내용 |
|---|---|
| `/tmp/dlp-control.json` | 전체 파이프라인 제어 파일 (엔진 매 스캔마다 re-read) |
| `~/.config/ai-dlp-proxy/assets.json` | 보호 자산 목록 |
| `~/.config/ai-dlp-proxy/audit.jsonl` | 감사 로그 (레거시, DB 마이그레이션 가능) |
| `~/.config/ai-dlp-proxy/db/dlp.db` | SQLite WAL (트래픽·Finding·통계) |

---

## 10 성능 최적화

### 10-1. 메시지 해시 캐시 (`engine/pipeline/__init__.py`)

AI Agent는 매 턴마다 이전 대화 전체를 포함하여 전송합니다.  
동일 메시지를 매번 스캔하면 O(n²) 복잡도가 됩니다.

```
캐시 키 = SHA-256(field_path + role + text + control_tag)
TTL = 300초
최대 = 500항목
캐시 히트 → 이전 findings 재사용, Regex/SLM 생략
```

**캐시 히트 시 마스킹 동작:**  
캐시는 `Finding` 객체 목록(오프셋·매치텍스트 포함)을 저장합니다.  
`inspect_traffic.py`의 `_apply_mask()`는 캐시 히트 여부와 관계없이 **매 요청마다 실행**되며,  
캐시에서 가져온 finding 오프셋으로 현재 요청 body를 그대로 치환합니다.  
캐시 키에 text가 포함되므로 text가 동일한 경우에만 히트 → 오프셋은 항상 유효합니다.  
즉, **스캔(Regex/SLM 실행)만 생략되고 마스킹은 생략되지 않습니다.**

history 메시지는 매 턴마다 반복 포함되므로 캐시 효과가 특히 큽니다:  
턴 N에서 스캔한 히스토리 finding을 턴 N+1, N+2에서 캐시로 재사용해도 마스킹은 동일하게 적용됩니다.

### 10-2. ftable 행 수 제한

```python
_FTABLE_MAX_ROWS = 200

# 초과 시 앞에서부터 trim
while len(self._finding_row_order) > self._FTABLE_MAX_ROWS:
    old_rk = self._finding_row_order.pop(0)
    self._finding_rows.pop(old_rk, None)
    if old_rk in tb.rows:
        tb.remove_row(old_rk)
```

### 10-3. 히스토리 로딩 2단계 분리 (`_batch`)

```python
def _batch(self, evs, hist=False):
    if hist:
        # 1단계: 모든 이벤트 turn/stats 계산 (ftable 미삽입)
        with self.batch_update():
            for ev in evs:
                self._one(ev, hist, skip_ftable=True)
        # 2단계: 마지막 200개 finding만 ftable 삽입
        all_findings = [(ev, f) for ev in evs for f in ev.get("findings", [])]
        tail = all_findings[-self._FTABLE_MAX_ROWS:]
        with self.batch_update():
            for ev, f in tail:
                self._aft(ev, f)
    else:
        with self.batch_update():
            for ev in evs:
                self._one(ev, hist)
```

---

## 11 테스트 구조

### 11-1. 회귀 테스트 (`tests/run_tests.py`)

```bash
cd /home1/ai-dlp-proxy
python3 tests/run_tests.py
# 결과: 61 passed, 0 failed
```

| 테스트 파일 | 내용 |
|---|---|
| `proto_phase1_true_positive.csv` | 실탐지 케이스 (T01~T15) |
| `proto_phase1_realistic_false_positive.csv` | 오탐 방지 케이스 (RFP 시리즈, 120건+) |

각 케이스는 `input_text`, `expected_rule`, `max_confidence`(오탐 테스트) 또는 `min_confidence`(실탐지 테스트), `expected_action`으로 구성됩니다.

### 11-2. GUI 제어탭 테스트 (`tests/run_gui_control_checks.py`)

```bash
python3 tests/run_gui_control_checks.py
# 결과: 66 passed, 0 failed
```

Textual `Pilot` API를 사용한 E2E 테스트:
- 제어탭 위젯 존재 확인
- 스위치 상태 변경 및 파일 반영
- 마스킹 규칙 테이블 ON/OFF 토글
- 커스텀 규칙 CRUD
- 허용목록 추가/삭제
- 보호 자산 CRUD
- 프로세스 start/stop/restart E2E

---

## 12 알려진 제한사항 및 설계 결정

### 12-1. assistant 메시지 스캔 제외

**결정**: OpenAI/Anthropic/Gemini 파서 모두 `assistant`(또는 `model`) role 메시지를 스캔 대상에서 제외합니다.

**이유**: LLM이 생성한 텍스트를 스캔해도 DLP 프록시가 할 수 있는 조치가 없습니다 (이미 LLM이 생성한 응답이므로). 또한 LLM이 PII 분석 결과를 응답으로 출력했을 때 이것이 히스토리에 포함되면 매 요청마다 재탐지됩니다.

**제한**: LLM이 응답에서 사용자의 PII를 echo하는 경우는 탐지되지 않습니다.

### 12-2. A-2 (줄 경계 컨텍스트) 롤백

**결정**: 컨텍스트 추출을 줄 경계로 제한하는 A-2 개선은 롤백되었습니다.

**이유**: PEM 키나 코드 내 하드코딩된 API 키처럼 매치가 줄 첫 번째에 위치할 때 `ctx_before`가 빈 문자열이 되어 키워드 매칭이 0건이 됩니다. 결과적으로 T08(PEM 키), T15(API 키 코드) 테스트가 실패했습니다.

**현재**: ±100자 고정 윈도우 사용.

### 12-3. 히스토리 finding 마스킹 보장

`inspect_traffic.py`는 engine 응답의 `protection_findings`(히스토리 포함 전체)를 마스킹 기준으로 사용하고,  
`findings`(신규만)를 DB 저장·대시보드 카운트에 사용합니다.

```
protection_action      ← 전체 finding 기준 판정 → 마스킹 여부 결정
protection_findings    ← 히스토리 포함 전체 finding → _apply_mask() 입력

pipeline_action        ← 신규 finding 기준 판정 → DB 기록
findings               ← 신규 finding만 → DB 저장 · 대시보드 카운트
```

이로 인해:

- LLM에 전달되는 요청의 모든 메시지(히스토리 포함)에서 PII가 마스킹됨 ✅
- 웹/TUI 탐지 카운트에는 새 메시지의 finding만 집계됨 ✅
- ftable(탐지 목록)에는 history finding이 표시되지 않음 (이전 턴에서 이미 표시됨) ✅

### 12-4. `DuplicateKey` 방지 — `_finding_counter`

ftable의 row key를 `f{len(self._finding_rows)}`로 생성하면 trim 후 크기가 줄어 키가 중복됩니다.

**수정**: `self._finding_counter: int = 0` 단조증가 카운터 도입. 앱 재시작(action_reload) 시 0으로 초기화.

```python
rk = f"f{self._finding_counter}"
self._finding_counter += 1
```

### 12-5. 마스킹 후 Content-Length

mitmproxy는 `flow.request.content` 교체 시 Content-Length를 자동으로 갱신하지 않습니다. 명시적으로 재계산:

```python
masked_bytes = json.dumps(masked_body, ensure_ascii=False).encode("utf-8")
flow.request.content = masked_bytes
flow.request.headers["content-length"] = str(len(masked_bytes))
```
