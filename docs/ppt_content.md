# AI Agent DLP Proxy — 과제 계획서 PPT 내용 (v2, 2026-04-04 최신화)

> **발표 시간**: 약 15~20분 상정 | **슬라이드**: 14장

---

## [슬라이드 1] 표지

**제목**: AI Agent DLP Proxy
**부제**: LLM 트래픽 실시간 개인정보 탐지·마스킹 시스템

- 라즈베리파이 기반 mitmproxy 인라인 프록시
- 날짜: 2026. 04.
- GitHub: github.com/organic4597/ai-dlp-proxy

---

## [슬라이드 2] 배경 및 문제 정의

### AI 시대의 새로운 개인정보 유출 경로

**기존 위협**: 해킹, 내부자 유출, DB 탈취
**새로운 위협**: 사용자가 *자발적으로* LLM에 민감정보 입력

```
사용자 → AI 에이전트 → [주민번호 900101-1234568 포함된 문서 요약 요청]
                       ↓
                  OpenAI / Claude / Gemini 서버 (해외)
```

**실제 우려 사례**
- 직원이 Claude에 고객 개인정보가 포함된 계약서 붙여넣기
- 개발자가 ChatGPT에 DB 쿼리 결과(개인정보 포함) 분석 요청
- 의료진이 진단 내용·환자 정보를 LLM에 전송
- GitHub Copilot에 API 키나 JWT 토큰이 포함된 코드 전송

**핵심 문제**
- 사용자는 민감정보인지 인식 못 하거나 무시
- 기업 보안팀은 HTTPS 암호화로 내용 확인 불가
- LLM 사업자 서버에 PII가 학습 데이터로 흡수될 위험
- AI 에이전트(tool call, function calling)가 DB 데이터를 LLM에 자동 전달

---

## [슬라이드 3] 해결 아이디어

### 투명한 인라인 DLP 프록시

```
Before:  PC → LLM API  (내부 검열 없음)

After:   PC → [DLP Proxy] → LLM API
                  ↓
           PII 자동 탐지·마스킹
```

**핵심 설계 원칙**
1. **투명성**: 사용자·에이전트 코드 변경 없음 (시스템 프록시 설정만)
2. **인라인**: 요청 가로채기 → 마스킹 → 전달 (실시간 처리)
3. **불가역성**: 마스킹된 데이터는 LLM 서버에 절대 도달하지 않음
4. **제어 가능**: TUI로 규칙 ON/OFF, 정책 실시간 변경
5. **선택적 차단**: 마스킹 대신 403 차단 정책도 지원

---

## [슬라이드 4] 시스템 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│                     Windows PC                               │
│  AI Agent / 브라우저 / VS Code (Copilot)                     │
│  시스템 프록시: 192.168.0.16:4001                            │
└────────────────────────┬─────────────────────────────────────┘
                         │ HTTPS (CA 인증서로 복호화)
┌────────────────────────▼─────────────────────────────────────┐
│                  Raspberry Pi (192.168.0.16)                  │
│                                                              │
│  ① mitmproxy :4001  ──→  inspect_traffic.py (addon)         │
│     · CA 인증서로 HTTPS 복호화 (TLS MITM)                   │
│     · HTTP/2 비활성화 (HTTP/1.1 강제), IPv4 전용             │
│     · 11개 LLM 서비스 감시 (도메인 기반 라우팅)              │
│     · 텍스트 추출 → ②에 UDS로 스캔 요청                     │
│     · 마스킹/차단 결정 후 flow 수정                          │
│                                                              │
│  ② engine_server.py (UDS /tmp/dlp-engine.sock)              │
│     · asyncio + NDJSON 프로토콜                              │
│     · scan / ping / stats / masked_inc / subscribe           │
│     · DLP Pipeline: Regex Stage (12개 규칙)                  │
│     · 이벤트 pub-sub → TUI 실시간 연동                       │
│                                                              │
│  ③ tui.py (Textual TUI)                                     │
│     · 6탭 실시간 모니터링·제어                               │
│     · 프로세스 감시자: engine + mitmproxy 자동 재시작        │
│     · 패킷 캡처, 정책 파일 실시간 편집                       │
└────────────────────────┬─────────────────────────────────────┘
                         │ HTTPS (마스킹된 요청 전달)
┌────────────────────────▼─────────────────────────────────────┐
│              외부 LLM API (11개 서비스)                      │
│   OpenAI · Anthropic · Gemini · GitHub Copilot               │
│   Groq · Together · Mistral · OpenRouter                     │
│   DeepSeek · xAI · Azure OpenAI                              │
│   → PII가 제거된 안전한 요청만 수신                          │
└──────────────────────────────────────────────────────────────┘
```

**처리 흐름 요약**
1. PC의 HTTPS 요청 → mitmproxy가 CA 인증서로 TLS 복호화
2. 도메인 기반으로 LLM 서비스 판별 → API 파서가 메시지 텍스트 추출
3. UDS로 engine_server에 스캔 요청 (NDJSON)
4. DLP 엔진이 정규식 + 알고리즘 검증으로 PII 탐지
5. 정책(`/tmp/dlp-control.json`)에 따라 마스킹 또는 403 차단
6. TUI 구독자에게 이벤트 브로드캐스트 (실시간 모니터링)

---

## [슬라이드 5] 구현 현황 — 멀티 프로바이더 지원

### 11개 LLM 서비스 자동 감시

| 서비스 | 호스트 | API 포맷 |
|--------|--------|----------|
| **OpenAI** | api.openai.com | Chat Completions |
| **Anthropic** | api.anthropic.com | Messages API |
| **Google Gemini** | generativelanguage.googleapis.com | generateContent |
| **GitHub Copilot** | api.githubcopilot.com 외 2개 | Chat Completions |
| **Azure OpenAI** | *.openai.azure.com | Chat Completions |
| **Groq** | api.groq.com | Chat Completions |
| **Together AI** | api.together.ai | Chat Completions |
| **Mistral** | api.mistral.ai | Chat Completions |
| **OpenRouter** | openrouter.ai | Chat Completions |
| **DeepSeek** | api.deepseek.com | Chat Completions |
| **xAI (Grok)** | api.x.ai | Chat Completions |

**API 파서 아키텍처**

```
extractor.py (디스패처)
  ├── openai.py  — Chat Completions 포맷 (7개 서비스 공통)
  │    검사 role: user, tool (tool_result)
  │    제외 role: system, assistant, tool_call, tool_def
  ├── anthropic.py — Messages API
  │    검사 role: user, tool_result (content 블록 포함)
  └── gemini.py — generateContent API
       검사 role: user, functionResponse
       제외 role: model (assistant), systemInstruction
```

**멀티모달 대응**: 텍스트 블록만 추출, image_url·binary 블록은 DLP 제외

---

## [슬라이드 6] 구현 현황 — DLP 탐지 규칙 (12개)

### Regex Stage — 정규표현식 + 알고리즘 검증

| 규칙 | 대상 | 등급 | 검증 방식 | 마스킹 레이블 |
|------|------|------|-----------|--------------|
| `kr_rrn` | 주민등록번호 | CRITICAL | mod-11 체크섬 + 생년월일 + 성별코드 | `[주민등록번호]` |
| `credit_card` | 신용카드번호 | CRITICAL | Luhn 알고리즘 + 반복 패턴 제외 | `[카드번호]` |
| `us_ssn` | 미국 SSN | CRITICAL | 패턴 (000/666/900+ 제외) | `[SSN]` |
| `aws_access_key` | AWS 액세스키 | CRITICAL | AKIA/ABIA/ACCA/ASIA 접두어 | `[AWS_KEY]` |
| `pem_private_key` | PEM 개인키 | CRITICAL | BEGIN/END PRIVATE KEY 블록 | `[PRIVATE_KEY]` |
| `github_pat` | GitHub 토큰 | CRITICAL | ghp/gho/ghu/ghs/ghr\_ + 36자+ | `[GH_TOKEN]` |
| `kr_passport` | 여권번호 | HIGH | A-Z 1~2자 + 7~8 숫자 | `[여권번호]` |
| `kr_driver_license` | 운전면허번호 | HIGH | NN-NN-NNNNNN-NN 패턴 | `[운전면허]` |
| `jwt_token` | JWT 토큰 | HIGH | eyJ + 3-part base64url | `[JWT]` |
| `api_key_assignment` | API 키 할당문 | HIGH | api_key= / secret_key= 컨텍스트 | `[API_KEY]` |
| `kr_phone` | 휴대전화번호 | MEDIUM | 010/011/016/017/018/019 | `[전화번호]` |
| `email` | 이메일 주소 | LOW | RFC 패턴 | `[이메일]` |

**Severity → 파이프라인 Action**

```
CRITICAL (4)  →  MASK   (마스킹 후 통과)
HIGH (3)      →  ALERT  (경고 — 정책에 따라 차단 가능)
MEDIUM (2)    →  ALERT
LOW (1)       →  ALERT
```

**경계 처리**: 한글 등 유니코드 앞뒤에서도 숫자 경계 `(?<!\d) … (?!\d)` 적용

---

## [슬라이드 7] 구현 현황 — 마스킹 파이프라인

### 실제 동작 예시

**Before (사용자가 전송하려던 내용)**

```json
{
  "messages": [{
    "role": "user",
    "content": "이 환자 정보를 분석해줘: 홍길동, 주민번호 900101-1234568, 카드번호 4532-1234-5678-9012, 연락처 010-1234-5678"
  }]
}
```

**After (LLM에 실제 전달된 내용)**

```json
{
  "messages": [{
    "role": "user",
    "content": "이 환자 정보를 분석해줘: 홍길동, 주민번호 [주민등록번호], 카드번호 [카드번호], 연락처 [전화번호]"
  }]
}
```

**마스킹 구현 기술**
- 탐지된 finding의 `field_path` + `match_start` / `match_end` offset 기반 정밀 치환
- **역순(reverse) 적용**: 뒤 offset 먼저 치환 → 앞 offset drift 방지
- 동일 필드에 복수 finding 시 `field_path`별 그룹 처리
- Content-Length 헤더 자동 재계산
- `flow.request.content` 직접 교체 → mitmproxy가 재암호화 후 LLM 전달
- offset 이상 시 `match_text` 기반 단순 대체로 폴백

**정책 파일** (`/tmp/dlp-control.json`)

```json
{
  "regex_enabled":  true,
  "slm_enabled":    false,
  "mask_on_detect": true,
  "block_on_alert": false,
  "block_on_mask":  false,
  "disabled_rules": []
}
```

| 정책 | 설명 |
|------|------|
| `mask_on_detect` | 탐지 시 마스킹 후 통과 (기본값) |
| `block_on_alert` | ALERT 탐지 시 403 차단 |
| `block_on_mask` | MASK 탐지 시 403 차단 |
| `disabled_rules` | 규칙별 비활성화 목록 |

---

## [슬라이드 8] 구현 현황 — DLP 엔진 서버 아키텍처

### engine_server.py — 독립 프로세스 + NDJSON 프로토콜

```
mitmproxy addon
      │
      │ UDS /tmp/dlp-engine.sock (기본)
      │ 또는 TCP 127.0.0.1:4002 (--tcp 폴백)
      ▼
engine_server.py (asyncio)
  ┌────────────────────────────────────────────┐
  │  요청 action 처리                          │
  │  ├─ scan      : extract() → run_pipeline() │
  │  ├─ ping      : 헬스체크 응답              │
  │  ├─ stats     : 통계 반환                  │
  │  ├─ masked_inc: 마스킹 카운터 증가         │
  │  └─ subscribe : 이벤트 스트림 구독 (TUI용) │
  │                                            │
  │  extract()                                 │
  │  └─ host 기반 API 파서 선택 → DLPTarget[] │
  │                                            │
  │  run_pipeline()                            │
  │  └─ RegexStage.scan() → Finding[]         │
  │     → _decide_action() → PipelineResult   │
  └────────────────────────────────────────────┘
      │ subscribe (asyncio.Queue, maxsize=500)
      ▼
   TUI (이벤트 push — 실시간 모니터링)
```

**통계 추적**: `total` · `scanned` · `findings` · `errors` · `masked`

**Graceful Shutdown**: SIGINT/SIGTERM 2회 시 강제 종료, UDS 소켓 파일 자동 정리

---

## [슬라이드 9] 구현 현황 — TUI 대시보드

### Textual 기반 6탭 인터랙티브 TUI

```
  턴 3  요청 12  스캔 12  탐지 8  마스킹 7  │  Engine ●  mitm ●
┌──────────────────────────────────────────────────────────────┐
│ 트래픽 │ 탐지 │ 제어 │ 프로세스 │ 설정 │ 로그              │
├──────────────────────────────────────────────────────────────┤
│ [트래픽 탭]                                                  │
│ ID  시각       Provider  경로                  크기   액션   │
│ 12  20:31:42  OpenAI    /v1/chat/completions  1.2KB  masked │
│ 11  20:30:18  Gemini    /v1beta/models/...    0.8KB  masked │
│ 10  20:28:55  Copilot   /chat/completions     0.5KB  pass   │
├──────────────────────────────────────────────────────────────┤
│ [상세보기]                    [엔진 결과]                    │
│ POST /v1/chat/completions     rule: kr_rrn                  │
│ Host: api.openai.com          severity: CRITICAL             │
│ Content-Length: 1187          confidence: 1.0                │
│                               action: MASK                   │
└──────────────────────────────────────────────────────────────┘
```

**탭별 기능**
- **트래픽**: 요청 목록 + HTTP 헤더/본문 + 엔진 결과 상세
- **탐지**: 누적 findings 목록 (규칙/심각도/신뢰도/매칭 텍스트)
- **제어**: 파이프라인 ON/OFF, 정책 스위치, 규칙별 활성화 토글, 패킷 캡처
- **프로세스**: engine_server·mitmproxy 상태 모니터링·시작/중지/재시작
- **설정**: 포트, 대상 도메인 설정
- **로그**: 실시간 이벤트 스트림

**프로세스 감시자 (supervisor)**
- TUI 시작 시 engine_server + mitmdump 자동 실행
- 비정상 종료 시 3초 후 자동 재시작 (재시작 횟수 추적)
- `--no-supervisor` 플래그로 외부 실행 환경 지원

**패킷 캡처 기능**
- TUI에서 캡처 버튼 클릭 → `/tmp/dlp-capture-next` 플래그 파일 생성
- 다음 LLM 요청 1건을 `logs/captured_packet.json`에 저장

---

## [슬라이드 10] 성능 및 오탐 개선 결과

### 처리 성능

| 측정 항목 | 수치 |
|-----------|------|
| Regex Stage 스캔 응답시간 | **< 1ms** |
| 전체 마스킹 처리 오버헤드 | **< 5ms** |
| 엔진 통신 방식 | Unix Domain Socket (로컬, 네트워크 무관) |
| 버퍼 한계 | 4 MB (요청·응답 각각) |

### 오탐(False Positive) 개선 이력

**문제**: 주민번호 패턴 매칭은 되지만 실제로는 무의미한 숫자인 경우

| 항목 | 개선 전 | 개선 후 |
|------|---------|---------|
| kr_rrn 총 탐지 | 79건 | 6건 |
| 그 중 오탐 | 73건 (92%) | 0건 (0%) |
| 적용 개선 | — | 체크섬 실패 → confidence 0.0 (필터링)<br>생년월일 유효성 검사 (월 1~12, 일 1~31)<br>성별코드 유효성 검사 (1·2·3·4·9만 허용)<br>올-제로 등 반복 패턴 제거 |

**개선 핵심**: 체크섬(mod-11) 실패 시 confidence → `0.0` 으로 완전 필터링

**기타 오탐 개선**
- `aws_secret_key` 규칙 제거 (40자 base64 무조건 탐지 → 오탐 과다) → `api_key_assignment`로 대체
- `credit_card`: 올-제로·단일 숫자 반복 패턴 제외
- `kr_rrn` / `kr_phone` / `credit_card`: 한글 유니코드 앞뒤 경계 lookaround 추가

---

## [슬라이드 11] 기술 스택

```
하드웨어
└── Raspberry Pi (ARM Linux, 192.168.0.16)

프록시 레이어
└── mitmproxy 12.2.1 (Python addon API)
    ├── HTTPS TLS 복호화 (mitmproxy CA 인증서)
    ├── HTTP/2 비활성화 → HTTP/1.1 강제
    └── IPv4 전용 (getaddrinfo 오버라이드)

DLP 엔진 (engine_server.py + src/ai_dlp_proxy/)
├── Python 3.12 + asyncio
├── Unix Domain Socket IPC (기본) / TCP 폴백
├── NDJSON 프로토콜 (줄바꿈 구분 JSON)
├── extractor.py: 멀티 API 파서 디스패처
│   ├── openai.py (Chat Completions — 7개 서비스)
│   ├── anthropic.py (Messages API)
│   └── gemini.py (generateContent API)
├── RegexStage: 12개 DLP 규칙
│   ├── mod-11 체크섬 (주민번호)
│   ├── Luhn 알고리즘 (신용카드)
│   └── 컨텍스트 윈도우 추출 (match 앞뒤 100자)
└── 이벤트 pub-sub (asyncio.Queue, TUI 실시간 연동)

TUI
└── Textual 8.2.2 (Rich 기반 인터랙티브 터미널 UI)
    ├── 6탭 대시보드
    └── 프로세스 감시자 (engine + mitmproxy 자동 재시작)

로그
├── logs/traffic.log    — 텍스트 포맷 콘솔 로그
└── logs/traffic.jsonl  — 구조화 JSON Lines (분석·감사용)
```

---

## [슬라이드 12] 향후 개발 계획

### Phase 4 — SLM(소형 언어모델) 통합

**목표**: 정규식으로 탐지하기 어려운 문맥적 민감정보 탐지

```
"Project Artemis의 런칭 일정은 5월 12일..."  → 기업 기밀 (패턴 없음)
"혈압약을 처방받고 있어서 혈압이 140..."      → 의료 정보 (패턴 없음)
"이 고객의 연봉은 8천만 원이고..."            → 금융 정보 (패턴 없음)
```

- 모델: `Qwen2.5-1.5B-Q4` 또는 `EXAONE-3.5-2.4B-Q4` (한국어 특화)
- 엔진: `llama-cpp-python` (pyproject.toml에 의존성 선언 완료)
- GBNF grammar로 JSON 출력 강제 (오파싱 방지)
- `slm_enabled` 플래그로 Regex Stage와 독립 ON/OFF
- Finding의 `context_window()`: `<<<match>>>` 형식으로 SLM에 전달
- 예상 처리시간: ~150~300ms (Raspberry Pi CPU 기준)

### Phase 5 — 패키지화 및 배포

- `pip install ai-dlp-proxy` 단일 명령 설치
- CA 인증서 자동 생성 및 시스템 트러스트스토어 등록
- Windows / macOS / Linux 시스템 프록시 자동 설정
- `ai-dlp-proxy` CLI 엔트리포인트 (`__main__.py` 스켈레톤 구현 완료)

### Phase 6 — 사용자 정의 정책 (장기)

- `config/settings.yaml`로 커스텀 민감 키워드 정의
- 4계층 정책: 개인 > 조직 > 도메인 > 글로벌
- 화이트리스트 / 블랙리스트 도메인 설정

---

## [슬라이드 13] 기대 효과

### 개인 사용자
- AI 에이전트 사용 중 실수로 주민번호·카드번호 전송 방지
- 별도 행동 없이 자동 보호 (투명 프록시, 에이전트 코드 변경 불필요)
- GitHub Copilot 사용 중 코드에 포함된 API 키·JWT 토큰 유출 방지

### 기업/조직
- 임직원의 LLM 사용에서 발생하는 데이터 유출 방지
- 개인정보보호법·GDPR 컴플라이언스 지원
- 실시간 감사 로그 (`logs/traffic.jsonl`) — 보안 이벤트 추적 가능
- 정책 파일(`/tmp/dlp-control.json`)로 조직별 규칙 커스터마이징

### AI 에이전트 개발자
- tool_result (함수 실행 결과) 내 민감 데이터 자동 차단
- Gemini functionResponse, Anthropic tool_result 블록까지 커버

### AI 서비스 제공자
- 학습 데이터에 PII 포함 방지 (클라이언트 사이드에서 선제 차단)

---

## [슬라이드 14] 결론

### 핵심 가치

> **"AI를 더 안전하게 쓸 수 있도록, 사용자 몰래 지켜드립니다"**

- 설정 완료 후 **완전 자동** 동작 — 프록시 설정 1회로 영구 보호
- 처리 지연 **5ms 미만** — 사용자 경험 영향 없음
- **오픈소스**, 라즈베리파이에서 동작 — 진입 장벽 낮음

### 현재 구현 완료 (Phase 1~3)

- ✅ HTTPS 트래픽 투명 프록싱 (TLS MITM, HTTP/2 비활성화, IPv4 강제)
- ✅ **11개 LLM 서비스** 자동 감시 (OpenAI·Anthropic·Gemini·Copilot·Groq 외)
- ✅ 멀티 API 파서 (Chat Completions / Messages / generateContent + 멀티모달)
- ✅ **12개 DLP 규칙** (체크섬·Luhn 검증, 한글 유니코드 경계 처리)
- ✅ 실시간 마스킹 파이프라인 (offset 역순 치환, Content-Length 재계산)
- ✅ 정책 기반 403 차단 (`block_on_mask`, `block_on_alert`)
- ✅ Textual TUI 6탭 모니터링 대시보드
- ✅ 프로세스 감시자 (engine + mitmproxy 자동 재시작)
- ✅ 오탐 **92% 감소** (kr_rrn 체크섬 + 생년월일 + 성별코드 검증)
- ✅ 이중 로그 (traffic.log + traffic.jsonl)
- ✅ 이벤트 pub-sub (engine ↔ TUI 실시간 연동)

### 개발 예정

- 🔄 SLM 컨텍스트 기반 탐지 (Qwen2.5 / EXAONE, llama-cpp-python)
- 🔄 `pip install ai-dlp-proxy` 배포 패키지
- 🔄 CA 인증서 자동 설치, 시스템 프록시 자동 설정

---

*발표 자료 — AI Agent DLP Proxy 과제 계획서 (v2, 2026-04-04 최신화)*
