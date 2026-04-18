# AI DLP Proxy — 구현 상세 문서

> 작성일: 2026-04-18  
> 대상: 개발자 · 유지보수 담당자

---

## 목차

1. [전체 아키텍처](#1-전체-아키텍처)
2. [DLP 파이프라인](#2-dlp-파이프라인)
3. [RegexStage — 문맥 보정 로직](#3-regexstage--문맥-보정-로직)
4. [대화 히스토리 처리](#4-대화-히스토리-처리)
5. [마스킹 파이프라인](#5-마스킹-파이프라인)
6. [커스텀 탐지 규칙](#6-커스텀-탐지-규칙)
7. [제어 정책 (control.json)](#7-제어-정책-controljson)
8. [TUI 대시보드](#8-tui-대시보드)
9. [성능 최적화](#9-성능-최적화)
10. [테스트 구조](#10-테스트-구조)
11. [알려진 제한사항 및 설계 결정](#11-알려진-제한사항-및-설계-결정)

---

## 1. 전체 아키텍처

```
PC (AI Agent / 브라우저)
    │  시스템 프록시 → 서버:4001
    ▼
mitmproxy :4001 (inspect_traffic.py)
    │  HTTPS 복호화
    │  ┌─ API 파서 (OpenAI / Anthropic / Gemini)
    │  │   └─ DLPTarget 추출 (history 플래그 포함)
    │  └─ DLP 엔진 요청 (UDS)
    │
    ▼ Unix Domain Socket /tmp/dlp-engine.sock
engine_server.py
    │  NDJSON 프로토콜 (비동기 asyncio)
    └─ DLP Pipeline
         ├─ RegexStage  ─ 12개 빌트인 + 사용자 정의 규칙
         ├─ AssetStage  ─ 보호 자산 키워드/임베딩 탐지
         └─ SLMStage    ─ 문맥의존 PII (선택적 활성화)

tui.py (Textual TUI)
    └─ 6탭 실시간 대시보드 · 제어판
```

### 데이터 흐름

```
HTTP 요청
  → inspect_traffic.py (mitmproxy addon)
    → API 파서 (openai/anthropic/gemini)
      → DLPTarget 리스트 (field_path, role, text, history)
        → engine_server.scan()
          → run_pipeline(targets)
            → RegexStage.scan()  → Finding 리스트
            → AssetStage.scan()  → Finding 리스트 추가
            → NMS(겹침 제거)
            → [SLMStage.scan()]  → Finding 리스트 추가
          → PipelineResult (action, findings, elapsed_ms)
        → engine_server 응답 (finding_count, effective_finding_count, findings[], ...)
      → inspect_traffic: 마스킹 적용 (모든 finding, history 포함)
        → flow.request.content 교체
  → LLM 서버 전달
```

---

## 2. DLP 파이프라인

### 2-1. 스테이지 구성

| 스테이지 | 파일 | 역할 |
|---|---|---|
| `RegexStage` | `engine/pipeline/regex_stage.py` | 패턴 매칭 + 문맥 보정 |
| `AssetStage` | `engine/pipeline/asset_stage.py` | 보호 자산 탐지 (키워드/임베딩) |
| `SLMStage` | `engine/pipeline/slm_stage.py` | 문맥의존 PII, 선택적 활성화 |

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

> **중요**: `history=True` finding도 Action 결정에 포함됩니다.  
> 히스토리 메시지에 PII가 있으면 마스킹이 트리거됩니다.  
> `finding_count`/`effective_finding_count` 집계에서만 제외됩니다.

---

## 3. RegexStage — 문맥 보정 로직

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

## 4. 대화 히스토리 처리

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

### 4-4. 스캔 범위 결정 (role 기준)

| Provider | 스캔 포함 | 스캔 제외 |
|---|---|---|
| OpenAI | `user`, `tool_call`, `tool_result` | `assistant`, `system`, `tool_def` |
| Anthropic | `user`, `tool_result` | `assistant`, `system`, `tool_def` |
| Gemini | `user`, `functionResponse` | `model`(=assistant), `systemInstruction`, `tool_def` |

`assistant` 제외 이유: LLM이 생성한 텍스트는 외부에서 제어할 수 없으며, 히스토리로 다시 포함될 때 이전 PII 분석 내용이 재탐지되는 것을 방지합니다.

### 4-5. engine_server의 finding_count 분리

```python
# history finding 분리
new_findings = [f for f in result.findings if not f.history]
new_effective = [f for f in effective_findings if not f.history]
raw_finding_count = len(new_findings)           # TUI 카운트용 (히스토리 제외)
effective_finding_count = len(new_effective)    # TUI 카운트용 (히스토리 제외)

# 마스킹은 히스토리 포함 전체 findings로 수행
_effective_findings = [f for f in all_findings if conf >= threshold and not suppressed]
```

### 4-6. 결과

```
턴 1: [user: CSV(PII 71건)]               탐지: 71건 ✓ 마스킹: 71건 ✓
턴 2: [user: CSV][assistant][user: "안녕"]
       CSV findings: history=True → 카운트 제외, 마스킹 적용 ✓
       "안녕" findings: history=False → 탐지: 0건
       → 탐지 카운트: 0건 ✓  마스킹: 71건 (LLM에 전달되는 CSV는 여전히 마스킹됨) ✓
```

---

## 5. 마스킹 파이프라인

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
PipelineAction = mask 또는 alert
    + mask_on_detect = true
    + effective_findings 존재
    ↓
_apply_mask(body_obj, effective_findings, mask_templates)
    ↓
masked_bytes = json.dumps(masked_body, ensure_ascii=False).encode()
flow.request.content = masked_bytes
flow.request.headers["content-length"] = str(len(masked_bytes))
    ↓
LLM 서버로 마스킹된 요청 전달
```

### 5-4. 마스킹 텍스트 우선순위

```
커스텀 규칙 mask_template > 사용자 설정(control.json) > 기본값
```

`merge_mask_templates(user_templates, allow_custom=True)`

---

## 6. 커스텀 탐지 규칙

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

## 7. 제어 정책 (control.json)

기본 경로: `/tmp/dlp-control.json`  
TUI 제어탭 또는 직접 편집으로 실시간 반영 (엔진 재시작 불필요)

### 전체 스키마

```json
{
  "regex_enabled": true,
  "asset_enabled": true,
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

## 8. TUI 대시보드

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

## 9. 성능 최적화

### 9-1. 메시지 해시 캐시 (`engine/pipeline/__init__.py`)

AI Agent는 매 턴마다 이전 대화 전체를 포함하여 전송합니다.  
동일 메시지를 매번 스캔하면 O(n²) 복잡도가 됩니다.

```
캐시 키 = SHA-256(field_path + role + text + control_tag)
TTL = 300초
최대 = 500항목
캐시 히트 → 이전 findings 재사용, Regex/SLM 생략
```

그러나 `history=True` 마킹으로 이전 메시지도 다시 스캔하게 되므로,  
캐시를 통해 실제 성능 부담은 없습니다.

### 9-2. ftable 행 수 제한

```python
_FTABLE_MAX_ROWS = 200

# 초과 시 앞에서부터 trim
while len(self._finding_row_order) > self._FTABLE_MAX_ROWS:
    old_rk = self._finding_row_order.pop(0)
    self._finding_rows.pop(old_rk, None)
    if old_rk in tb.rows:
        tb.remove_row(old_rk)
```

### 9-3. 히스토리 로딩 2단계 분리 (`_batch`)

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

## 10. 테스트 구조

### 10-1. 회귀 테스트 (`tests/run_tests.py`)

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

### 10-2. GUI 제어탭 테스트 (`tests/run_gui_control_checks.py`)

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

## 11. 알려진 제한사항 및 설계 결정

### 11-1. assistant 메시지 스캔 제외

**결정**: OpenAI/Anthropic/Gemini 파서 모두 `assistant`(또는 `model`) role 메시지를 스캔 대상에서 제외합니다.

**이유**: LLM이 생성한 텍스트를 스캔해도 DLP 프록시가 할 수 있는 조치가 없습니다 (이미 LLM이 생성한 응답이므로). 또한 LLM이 PII 분석 결과를 응답으로 출력했을 때 이것이 히스토리에 포함되면 매 요청마다 재탐지됩니다.

**제한**: LLM이 응답에서 사용자의 PII를 echo하는 경우는 탐지되지 않습니다.

### 11-2. A-2 (줄 경계 컨텍스트) 롤백

**결정**: 컨텍스트 추출을 줄 경계로 제한하는 A-2 개선은 롤백되었습니다.

**이유**: PEM 키나 코드 내 하드코딩된 API 키처럼 매치가 줄 첫 번째에 위치할 때 `ctx_before`가 빈 문자열이 되어 키워드 매칭이 0건이 됩니다. 결과적으로 T08(PEM 키), T15(API 키 코드) 테스트가 실패했습니다.

**현재**: ±100자 고정 윈도우 사용.

### 11-3. 히스토리 finding 마스킹 보장

`inspect_traffic.py`에서 마스킹에 사용하는 `_effective_findings`는 `history` 여부와 관계없이 모든 effective finding을 포함합니다. 이로 인해:

- LLM에 전달되는 요청의 모든 메시지(히스토리 포함)에서 PII가 마스킹됨 ✅
- TUI 탐지 카운트에는 새 메시지의 finding만 집계됨 ✅
- ftable(탐지 목록)에는 history finding이 표시되지 않음 (이전 턴에서 이미 표시됨) ✅

### 11-4. `DuplicateKey` 방지 — `_finding_counter`

ftable의 row key를 `f{len(self._finding_rows)}`로 생성하면 trim 후 크기가 줄어 키가 중복됩니다.

**수정**: `self._finding_counter: int = 0` 단조증가 카운터 도입. 앱 재시작(action_reload) 시 0으로 초기화.

```python
rk = f"f{self._finding_counter}"
self._finding_counter += 1
```

### 11-5. 마스킹 후 Content-Length

mitmproxy는 `flow.request.content` 교체 시 Content-Length를 자동으로 갱신하지 않습니다. 명시적으로 재계산:

```python
masked_bytes = json.dumps(masked_body, ensure_ascii=False).encode("utf-8")
flow.request.content = masked_bytes
flow.request.headers["content-length"] = str(len(masked_bytes))
```
