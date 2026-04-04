# Plan: AI Agent DLP Proxy (mitmproxy 기반)

## 목표
mitmproxy로 AI 에이전트의 HTTPS 트래픽을 가로채어, SLM/LLM으로 민감 데이터를 탐지하고 마스킹/차단 후 외부 LLM API로 전달하는 DLP 프록시 시스템 구축.

## 최종 제품 형태
- **CLI 앱** — ASCII/유니코드 특수문자로 TUI(Terminal UI) 구성 (박스, 테이블, 컬러 등)
- **TUI 라이브러리**: `rich` (Python) — 박스, 테이블, 패널, 실시간 로그, 프로그레스 바 등 지원
  - 대안: `textual` (rich 기반 인터랙티브 TUI), `curses` (저수준)
- **배포 구조 (최종)**:
  - AI 에이전트 사용자 PC에 직접 설치하여 로컬 프록시로 동작
  - 사용자 PC에서 `localhost:4001`로 리슨 → 시스템/에이전트 프록시로 설정
  - 단일 실행파일 또는 `pip install` 가능한 패키지 형태
  - 크로스플랫폼: Windows / macOS / Linux 지원 목표
- **개발 단계 환경**:
  - 라즈베리파이에서 개발, Windows PC에서 원격 프록시로 테스트

## 환경 구성 (개발 단계)
- **프록시 서버**: 라즈베리파이 (현재 머신, /home1)
- **테스트 클라이언트**: Windows PC → 라즈베리파이 IP:4001로 프록시 연결
- **프록시 포트**: 4001
- **mitmproxy 리슨**: 0.0.0.0:4001 (외부 접근 허용)

## 현재 단계: Phase 1 — 환경 설정 및 패킷 구조 확인

---

## Phase 1: 환경 설정 및 패킷 구조 분석 (현재)

### Step 1: Python venv 환경 구성
- `/home1/ai-dlp-proxy/` 프로젝트 디렉토리 생성
- `python3 -m venv /home1/ai-dlp-proxy/venv` 가상환경 생성
- venv 활성화 후 mitmproxy 설치: `pip install mitmproxy`

### Step 2: mitmproxy 기본 실행 및 CA 인증서 설정
- `mitmdump --listen-host 0.0.0.0 -p 4001` 실행 (외부에서 접근 가능하도록)
- 실행 시 `~/.mitmproxy/` 에 CA 인증서 자동 생성됨
- **Windows PC 설정**:
  1. 라즈베리파이의 `~/.mitmproxy/mitmproxy-ca-cert.cer` 파일을 Windows PC로 복사
  2. Windows에서 해당 인증서를 "신뢰할 수 있는 루트 인증 기관"에 설치
  3. Windows 시스템 프록시 설정: `라즈베리파이IP:4001`
  4. 또는 브라우저/앱별 프록시 설정으로 `라즈베리파이IP:4001` 지정
- 인증서 미설치 시 HTTPS 사이트 접속 시 인증서 오류 발생

### Step 3: 패킷 구조 확인용 addon 스크립트 작성
- `/home1/ai-dlp-proxy/scripts/inspect_traffic.py` 작성
- mitmproxy addon API 활용:
  - `request(flow)` 훅: 외부 LLM API로 나가는 요청 캡처
  - `response(flow)` 훅: 응답 캡처
- 캡처할 주요 대상 도메인:
  - `api.openai.com` (OpenAI / ChatGPT)
  - `api.anthropic.com` (Claude)
  - `generativelanguage.googleapis.com` (Gemini)
  - `api.groq.com`, `api.together.ai` 등
- 로깅 내용: URL, method, headers, request body (JSON), response body
- 실행: `mitmdump --listen-host 0.0.0.0 -p 4001 -s scripts/inspect_traffic.py`

### Step 4: Windows PC에서 테스트 트래픽 캡처
- Windows PC에서 AI 에이전트 또는 브라우저로 LLM API 호출
- 라즈베리파이 프록시를 경유하여 HTTPS 복호화된 패킷 구조 확인
- 요청 본문의 JSON 구조 분석 (messages, model, temperature 등)
- API key 위치 (Authorization header), content-type 등 확인

---

## Phase 2: DLP 판단 엔진 구축 (이후)

### 핵심 설계 결론: 사용자별 민감 데이터 정의 문제 해결 방안

**문제**: 사용자마다 "민감 데이터"의 정의가 다름
- A사: 프로젝트 코드명, 임직원 ID가 민감
- B 개인: 건강 정보, 재정 상태가 민감
- 의료기관: 진단명, 처방 내용이 민감
- 법무법인: 의뢰인 이름, 사건 번호가 민감

**채택 아키텍처: 병렬 듀얼 트랙 + 4계층 정책 레이어링**

#### 탐지 파이프라인 — 병렬 듀얼 트랙 (asyncio.gather)
```
텍스트 입력
    │
    ├─[Track A: 법적 의무]────────────────────────────── 1ms
    │  regex_filter.py 항상 실행 (사용자 정책 무관)
    │  주민번호(mod-11), 카드번호(Luhn), 계좌번호 등
    │
    └─[Track B: 사용자 정의]────────────────────────── 150~300ms
       (사용자 정책 있을 때만 실행)
       llama-cpp-python SLM이 전체 텍스트 스캔
         → suspects 목록 반환 (GBNF grammar로 JSON 강제)
         출력: {"suspects": [{"span": "...", "type": "..."}]}
       span_validator.py: 각 스팬을 Regex로 정밀 검증/확인
         → 오탐 필터링, 카테고리 정규화

양쪽 결과 병합 (BLOCK > MASK 우선) → action.py
```
- 사용자 정책 없음: Track B 스킵 → 전체 **1ms**
- 사용자 정책 있음: Track A‖Track B 병렬 → **150~300ms** (라즈베리파이 CPU 기준)
- SLM이 컨텍스트로 판단 (예시 문장 오탐 방지, 한글 표현 미탐 방지)
- Regex는 SLM suspects의 **형식 유효성 검증기**로만 동작

#### 4계층 정책 레이어링 (우선순위 순)
```
[1] 사용자 정책    ← 가장 높은 우선순위 (개인 설정)
[2] 조직/팀 정책   ← 회사/팀 단위 정책
[3] 도메인 규칙    ← 의료/법무/금융 등 업종별 규칙
[4] 글로벌 기본값  ← 법적 의무 PII (주민번호 등, 변경 불가)
충돌 시: 더 제한적인 규칙 우선 (BLOCK > MASK > PASS)
```

#### 정책 표현 형식 (settings.yaml 확장)
```yaml
policies:
  global:                      # 변경 불가, 법적 의무
    - type: BLOCK
      name: korean_rrn         # 주민등록번호 (체크섬 검증 포함)
    - type: BLOCK
      name: credit_card
  organization:                # 조직 관리자 설정
    - type: MASK
      name: employee_id
      pattern: "EMP-\d{6}"
    - type: MASK
      name: project_codename
      keywords: ["Project Artemis", "Operation Blue"]
  user:                        # 사용자 개인 설정
    - type: MASK
      name: my_medical_info
      keywords: ["당뇨", "혈압약", "정신과"]
      semantic: true           # 벡터 유사도 검색 활성화
  domain: medical              # 도메인 선택 시 규칙 추가 적용
```

### Step 5: 정책 레이어링 엔진 구현
- `pipeline/policy_resolver.py` — 4계층 정책 로드 및 합산
- 충돌 해결: 더 제한적 규칙 우선
- 정책 캐싱(TTL 기반) — 매 요청마다 YAML 파싱 방지

### Step 6: 탐지 파이프라인 구현

**Track A — Regex 필터 (`slm/regex_filter.py`, 항상 실행)**
한국 특화 패턴 (체크섬/알고리즘 검증 포함):
- 주민등록번호: `\d{6}-[1-4]\d{6}` + mod-11 체크섬 → BLOCK
- 휴대폰: `01[016789]-\d{3,4}-\d{4}` → MASK
- 카드번호: Luhn 알고리즘 검증 → BLOCK
- 계좌번호, 여권번호, 운전면허번호, 이메일
- 조직 정책의 커스텀 `pattern` 필드도 여기서 처리

**Track B — llama-cpp-python SLM (`slm/backends/llamacpp_backend.py`, 정책 있을 때만)**
- SLM이 전체 텍스트를 읽고 의심 스팬 목록 반환
- GBNF grammar로 출력 형식 강제 → 최대 64토큰으로 제한 (속도 최적화)
  ```
  출력 형식 (GBNF 강제):
  {"suspects": [{"span": "홍길동", "type": "이름"}, {"span": "Project X", "type": "기밀프로젝트"}]}
  ```
- 시스템 프롬프트에 사용자 정책 few-shot 예시 주입 (Constitutional AI)
- 온도: 0.0 (결정적 출력)
- 추천 모델: `Qwen2.5-1.5B-Q4` (CPU 150ms), `EXAONE-3.5-2.4B-Q4` (한국어 특화)

**Span 검증 (`slm/span_validator.py`)**
- Track B suspect 스팬을 Regex로 정밀 검증
  - "800101-1234567" → mod-11 체크섬 → 실제 주민번호? → BLOCK
  - "Project Artemis" → 사용자 정책 keywords 매칭 → MASK
  - 예시 문장 내 숫자 → 컨텍스트 불일치 → PASS (오탐 제거)
- 카테고리 정규화: `이름` → `IDENTITY_NAME`, `프로젝트코드` → `CUSTOM:project`

**SLM 백엔드 플러그인 (`slm/backends/`)**
- `llamacpp_backend.py` — 기본값, in-process, CPU+GPU 모두 지원
  - `n_gpu_layers=-1` (GPU 전부 사용) / `0` (CPU only)
- `vllm_backend.py` — GPU 전용 고성능 옵션 (optional)
- `settings.yaml`에서 백엔드 선택:
  ```yaml
  slm:
    backend: llamacpp
    model_path: ./models/qwen2.5-1.5b-q4.gguf
    n_gpu_layers: 0          # 0=CPU only, -1=GPU 전부
    constrained_output: true  # GBNF grammar 활성화
  ```

### Step 7: 마스킹/차단 로직
- `pipeline/action.py`: BLOCK → 403 반환, MASK → 토큰 치환, PASS → 통과
- `slm/masker.py`: 마스킹 매핑 테이블 (요청 단위 세션, 역마스킹용)
- 마스킹 토큰: `[주민번호]`, `[PHONE]`, `[CUSTOM:project_codename]`

### Step 8: 응답 역마스킹 (선택)
- LLM 응답에 마스킹 토큰이 포함된 경우 원본으로 복원
- 매핑 테이블 유지 (요청 단위 세션)

---

## Phase 3: CLI TUI 앱 및 로컬 배포 (이후)

### Step 8: TUI 대시보드 구현 (rich / textual)
- 실시간 트래픽 모니터링 화면:
  ```
  ┌─────────────────── AI DLP Proxy ────────────────────┐
  │ Status: ● Running on 0.0.0.0:4001                   │
  ├──────────┬──────────────┬────────┬──────────────────┤
  │ Time     │ Destination  │ Action │ Detail           │
  ├──────────┼──────────────┼────────┼──────────────────┤
  │ 12:03:01 │ openai.com   │ MASK   │ [NAME]x2 [PHONE]│
  │ 12:03:05 │ anthropic    │ PASS   │ clean            │
  │ 12:03:08 │ openai.com   │ BLOCK  │ SSN detected     │
  └──────────┴──────────────┴────────┴──────────────────┘
  │ Total: 128 │ Masked: 34 │ Blocked: 2 │ Clean: 92   │
  ```
- 상세 보기: 요청/응답 본문, 마스킹 전후 비교
- 설정 메뉴: 대상 도메인, 마스킹 규칙, SLM 엔진 선택

### Step 9: 로컬 설치형 패키지화
- `pip install ai-dlp-proxy` 또는 `pipx install` 로 설치 가능한 구조
- pyproject.toml 기반 패키징
- CLI 엔트리포인트: `ai-dlp-proxy start --port 4001`
- CA 인증서 자동 생성 및 시스템 등록 안내
- 크로스플랫폼 시스템 프록시 자동 설정 (선택적):
  - Windows: `netsh winhttp set proxy`
  - macOS: `networksetup`
  - Linux: 환경변수 설정
- 선택적으로 PyInstaller로 단일 실행파일 배포

### Step 10: 탐지 이력 로깅 및 통계
- 탐지 이력 로그 파일 저장
- TUI 내 통계 요약 (차단/마스킹/통과 건수)

---

## 주요 파일 구조 (예상)
```
/home1/ai-dlp-proxy/
├── venv/                            # Python 가상환경
├── mitmproxy_lib/                   # 벤더링된 mitmproxy 라이브러리 (임베드)
│   ├── mitmproxy/                   #   핵심 패키지 (Python 소스)
│   ├── mitmproxy_rs/                #   Rust 확장 (.abi3.so 바이너리)
│   └── mitmproxy_linux/             #   Linux 네이티브 지원
│
├── src/
│   └── ai_dlp_proxy/
│       ├── __init__.py
│       ├── __main__.py              # CLI 엔트리포인트
│       │
│       ├── proxy/                   # mitmproxy 제어 레이어 (래퍼)
│       │   ├── __init__.py
│       │   ├── master.py            # DumpMaster 기동/중지 (programmatic API)
│       │   ├── addon.py             # mitmproxy 훅 (request/response/websocket)
│       │   └── cert.py              # CA 인증서 생성 및 시스템 등록 안내
│       │
│       ├── engine/                  # 패킷 파싱 및 재조립 엔진
│       │   ├── __init__.py
│       │   ├── parser.py            # HTTP 요청 파싱 (JSON body, headers 추출)
│       │   ├── extractor.py         # API별 디스패처 (host 보고 적합한 api/ 모듈로 라우팅)
│       │   ├── rebuilder.py         # 수정된 필드로 요청 본문 재조립
│       │   └── api/                 # LLM API별 파싱/추출 구현체 (추후 추가 가능)
│       │       ├── __init__.py
│       │       ├── base.py          # 추상 기반 클래스 (APIParser 인터페이스)
│       │       ├── openai.py        # OpenAI /v1/chat/completions 파서
│       │       │                    #   messages[].content, tools, user, metadata 추출
│       │       ├── anthropic.py     # Anthropic /v1/messages 파서
│       │       │                    #   messages[].content, system, tools 추출
│       │       ├── gemini.py        # Google Gemini 파서
│       │       │                    #   contents[].parts[].text, systemInstruction 추출
│       │       ├── azure_openai.py  # Azure OpenAI 파서 (OpenAI 호환, URL 패턴 다름)
│       │       ├── groq.py          # Groq 파서 (OpenAI 호환 포맷)
│       │       └── bedrock.py       # AWS Bedrock 파서 (SigV4 서명 주의 — 수정 불가)
│       │
│       ├── slm/                     # 민감 데이터 탐지 엔진
│       │   ├── __init__.py
│       │   ├── detector.py          # asyncio.gather(Track A, Track B) 조율 메인
│       │   ├── regex_filter.py      # Track A: 법적 의무 패턴 항상 실행 + span 정밀 검증
│       │   ├── span_validator.py    # Track B suspects → Regex 검증 → 카테고리 정규화
│       │   ├── masker.py            # 마스킹/역마스킹 + 세션별 매핑 테이블
│       │   ├── backends/            # SLM 백엔드 플러그인 (settings.yaml에서 선택)
│       │   │   ├── __init__.py      #   GPU/CPU 환경에 따라 자동 선택
│       │   │   ├── base.py          #   SLMBackend 추상 클래스
│       │   │   ├── llamacpp_backend.py  # ← 기본값: llama-cpp-python in-process
│       │   │   │                        #   GBNF grammar로 JSON 출력 강제 (64토큰 제한)
│       │   │   │                        #   n_gpu_layers 설정으로 CPU/GPU 전환
│       │   │   └── vllm_backend.py      # GPU 전용 고성능 옵션 (선택적)
│       │   └── trainer/             # Phase C: LoRA 파인튜닝 도구 (별도 실행)
│       │       ├── data_gen.py      # 합성 학습 데이터 자동 생성
│       │       ├── feedback_collector.py  # TUI 피드백 → 학습 데이터 변환
│       │       └── finetune.py      # LoRA 파인튜닝 스크립트 (GGUF 변환 포함)
│       │
│       ├── pipeline/                # 전체 처리 파이프라인
│       │   ├── __init__.py
│       │   ├── dlp_pipeline.py      # parse → extract → detect → mask/block → rebuild
│       │   ├── policy_resolver.py   # 4계층 정책 로드·합산·캐싱 (user>org>domain>global)
│       │   └── action.py            # PASS / MASK / BLOCK 결정 및 flow 적용
│       │
│       └── tui/                     # Terminal UI (rich/textual)
│           ├── __init__.py
│           ├── app.py               # TUI 앱 메인
│           ├── dashboard.py         # 실시간 트래픽 모니터링 테이블
│           ├── statusbar.py         # 상태바 (포트, 통계 카운터)
│           └── detail_view.py       # 요청 상세보기 (마스킹 전후 비교)
│
├── config/
│   └── settings.yaml                # 대상 도메인, 마스킹 규칙, 포트 등
├── logs/
│   └── traffic.log
└── pyproject.toml                   # mitmproxy, rich 등 deps 포함
```

### API 파서 라우팅 로직 (engine/extractor.py)
```
flow.request.host 기반 디스패치:
  api.openai.com                           → api/openai.py
  api.anthropic.com                        → api/anthropic.py
  generativelanguage.googleapis.com        → api/gemini.py
  *.openai.azure.com                       → api/azure_openai.py
  api.groq.com                             → api/groq.py
  bedrock-runtime.*.amazonaws.com          → api/bedrock.py (수정 불가 플래그)
  그 외                                    → 로깅만, 수정 없이 통과
```

### API별 DLP 검사 대상 필드 요약
| API | 검사 필드 | 수정 금지 필드 |
|-----|---------|------------|
| OpenAI | `messages[].content`, `tools[].function.description`, `user`, `metadata` | `model`, `Authorization` |
| Anthropic | `messages[].content`, `system`, `tools[].description`, `metadata.user_id` | `model`, `x-api-key`, `anthropic-version` |
| Gemini | `contents[].parts[].text`, `systemInstruction.parts[].text` | `model`(URL), API key(URL) |
| Azure OpenAI | OpenAI와 동일 (`model` 없음, deployment명은 URL에) | `api-key`, deployment URL |
| Groq | OpenAI 호환 포맷, 동일 | `Authorization` |
| Bedrock | ⚠️ SigV4 서명 → **본문 수정 시 서명 파괴**, 로깅만 가능 | 전체 본문 |

### 모듈 간 데이터 흐름
```
proxy/addon.py (훅)
    → pipeline/dlp_pipeline.py
        → engine/parser.py          (raw HTTP → Python dict)
        → engine/extractor.py       (host 감지 → api/*.py 디스패치)
            → engine/api/openai.py  (DLP 대상 필드 목록 반환)
        → slm/regex_filter.py       (1차: 빠른 패턴 매칭)
        → slm/detector.py           (2차: SLM/LLM 판단, 필요시만)
        → pipeline/action.py        (PASS / MASK / BLOCK 결정)
        → slm/masker.py             (마스킹 처리)
        → engine/rebuilder.py       (수정된 dict → JSON body 재조립)
    → proxy/addon.py                (flow.request.content 교체)
    → tui/dashboard.py              (결과 이벤트 전달 → UI 갱신)
```

## 기술 결정 사항
- mitmproxy를 **외부 CLI가 아닌 Python 라이브러리로 임베드** (별도 설치 불필요)
  - `pyproject.toml` dependencies에 mitmproxy 포함 → `pip install .` 한 번으로 전체 설치
  - 최종 배포 시 PyInstaller로 mitmproxy 포함 단일 실행파일 번들링
- mitmproxy 실행 방식: `DumpMaster` programmatic API 사용
  ```python
  from mitmproxy.tools.dump import DumpMaster
  from mitmproxy.options import Options
  opts = Options(listen_host="0.0.0.0", listen_port=4001)
  master = DumpMaster(opts)
  master.addons.add(MyDLPAddon())
  await master.run()
  ```
- addon은 Python 클래스로 프로젝트 내부에 포함 (`src/ai_dlp_proxy/addon.py`)
- Phase 1에서는 구조 확인만, 수정/차단은 Phase 2부터
- **SLM 런타임**: `llama-cpp-python` — in-process 직접 바인딩 (HTTP 오버헤드 없음)
  - Ollama 미사용: 별도 서버 프로세스·HTTP 직렬화 오버헤드 제거
  - GBNF grammar로 JSON 출력 강제 → 최대 64토큰 생성 → CPU 기준 150~300ms
  - `n_gpu_layers` 설정으로 CPU/GPU 자동 전환 (배포 환경 대응)
  - vLLM은 GPU 전용 선택적 백엔드 (`backends/vllm_backend.py`)
- **탐지 순서 확정**: SLM 먼저(컨텍스트 판단) → Regex(형식 검증) — Regex를 먼저 돌리지 않음
  - Track A(Regex): 법적 의무 항목만, 항상 병렬 실행
  - Track B(SLM): 사용자 정의 민감 항목, suspects 목록 반환 후 Regex 검증

## 기술적 타당성 조사 결과

### 요청 본문 수정 ✅ 완전 지원
- `request(flow)` 훅에서 `flow.request.content` 읽기/쓰기로 JSON 수정 가능
- `Content-Length` 헤더는 mitmproxy가 **자동 업데이트**
- `async def request(flow)` → SLM/LLM 추론 중 비동기 대기 가능

### 스트리밍 응답 (SSE) ⚠️ 주요 주의사항
- OpenAI `stream=true` → `Content-Type: text/event-stream` SSE 반환
- mitmproxy Known Bug #4469: SSE를 스트리밍 설정 없이 받으면 응답 소실
- **DLP 목적상 스트리밍 문제 완전 회피 가능**: 요청 본문만 검사/수정하면 됨
  - `messages[].content`, `system`, `tools` 필드만 검사
  - 응답 수정은 불필요 → SSE 이슈 해당 없음
- 응답 로깅이 필요하면: `responseheaders()` 훅에서 `flow.response.stream = callable` 사용

### mitmproxy 훅 실행 순서
```
requestheaders → request(JSON 수정/차단) → responseheaders → response
```

### LLM API DLP 검사 대상 필드
- OpenAI: `messages[].content`, `tools[].result`
- Anthropic: `messages[].content`, `system`
- 수정 금지: `model`, `Authorization` / `x-api-key` 헤더, API 버전 헤더

### HTTP/2, WebSocket
- HTTP/2: ✅ 완전 지원 (OpenAI 현재 HTTP/2 사용)
- WebSocket: ✅ `websocket_message(flow)` 훅 지원
- HTTP/3(QUIC): ⚠️ 실험적
