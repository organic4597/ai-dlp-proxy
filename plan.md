# AI Agent DLP Proxy — 프로젝트 계획서 (v3, 2026-04-05 최신화)

## 프로젝트 개요
LLM API 트래픽을 투명하게 가로채어 **개인정보(PII) 자동 탐지 → 마스킹/차단** 후 외부 AI 서비스로 전달하는 DLP(Data Loss Prevention) 인라인 프록시.  
라즈베리파이에서 mitmproxy 기반으로 구현, Windows PC에서 원격 프록시로 테스트.

## 목표
- AI 에이전트/사용자가 LLM에 민감 데이터를 무심코 전송하는 것을 자동 차단
- 마스킹: 탐지된 PII를 레이블(`[주민등록번호]`)로 교체 후 요청 통과
- 차단: 정책에 따라 403 반환으로 요청 완전 차단

## 최종 제품 형태
- **인라인 프록시 + TUI 대시보드** (터미널에서 실시간 모니터링)
- **배포**: `pip install` 또는 단일 실행파일, 로컬 프록시로 동작

---

## 개발 환경

| 항목 | 내용 |
|------|------|
| 프록시 서버 | 라즈베리파이 (`192.168.0.16`, `/home1/ai_dlp_proxy`) |
| 테스트 클라이언트 | Windows PC → RPi IP:4001 프록시 설정 |
| 프록시 포트 | 4001 |
| Python | 3.12, venv `/home1/ai_dlp_proxy/venv/` |
| mitmproxy | 12.2.1 |
| TUI | Textual 8.2.2 |
| GitHub | https://github.com/organic4597/ai-dlp-proxy (private) |

---

## 시스템 아키텍처

```
Windows PC (AI Agent / Browser)
    │  HTTPS → 192.168.0.16:4001 (프록시 설정)
    ▼
┌─────────────────────────────────────────────────────┐
│              Raspberry Pi (192.168.0.16)             │
│                                                     │
│  mitmdump -p 4001 -s scripts/inspect_traffic.py     │
│  ┌──────────────────────────────────────────────┐   │
│  │         inspect_traffic.py (addon)           │   │
│  │  request() 훅                                │   │
│  │   1. API 파서 (openai/anthropic/gemini)      │   │
│  │   2. 텍스트 추출 (messages, system 등)       │   │
│  │   3. UDS → engine_server 스캔 요청           │   │
│  │   4. 결과에 따라 마스킹/차단/통과            │   │
│  └──────────────────────────────────────────────┘   │
│         │ UDS /tmp/dlp-engine.sock                  │
│  ┌──────▼───────────────────────────────────────┐   │
│  │         engine_server.py                     │   │
│  │  NDJSON 프로토콜 (action: scan/stats/ping)   │   │
│  │  ┌──────────────────────────────────────┐    │   │
│  │  │       DLP Pipeline                   │    │   │
│  │  │  RegexStage → (향후) SLMStage        │    │   │
│  │  └──────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  scripts/tui.py (Textual TUI — 별도 터미널)          │
│   트래픽/탐지/제어/프로세스/설정/로그 탭            │
└─────────────────────────────────────────────────────┘
    │
    ▼
외부 LLM API (OpenAI / Anthropic / Gemini)
  → 마스킹된 요청 전달 (PII 제거됨)
```

---

## 구현 현황 (Phase별)

### ✅ Phase 1 — 트래픽 캡처 (완료)
- mitmproxy CA 인증서 설치 (Windows PC)
- `inspect_traffic.py`: request/response 훅으로 LLM 트래픽 캡처
- 대상 도메인: `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com` 외 다수
- JSON 구조 분석 및 JSONL 로그 (`logs/traffic.jsonl`)

### ✅ Phase 2 — DLP 엔진 구축 (완료)

#### 2-1. API 파서 (`src/ai_dlp_proxy/engine/api/`)
| 파서 | 추출 필드 |
|------|-----------|
| openai.py | `messages[].content`, `system`, `user` |
| anthropic.py | `messages[].content`, `system` |
| gemini.py | `contents[].parts[].text`, `systemInstruction` |

#### 2-2. UDS 엔진 서버 (`scripts/engine_server.py`)
- Unix Domain Socket, NDJSON 프로토콜
- action: `scan` / `ping` / `stats` / `masked_inc` / `subscribe`
- 통계: `total`, `scanned`, `findings`, `errors`, `masked`

#### 2-3. Regex Stage DLP 파이프라인 (`src/ai_dlp_proxy/engine/pipeline/regex_stage.py`)

| 규칙명 | 대상 | Severity | 검증 |
|--------|------|----------|------|
| `kr_rrn` | 주민등록번호 | CRITICAL | 체크섬 mod-11 + 생년월일 + 성별코드 |
| `kr_passport` | 여권번호 | HIGH | 패턴 |
| `kr_driver_license` | 운전면허번호 | HIGH | 패턴 |
| `kr_phone` | 휴대전화번호 | MEDIUM | lookaround |
| `us_ssn` | 미국 SSN | CRITICAL | 패턴 |
| `credit_card` | 신용카드 | CRITICAL | Luhn 알고리즘 |
| `email` | 이메일 | LOW | 패턴 |
| `aws_access_key` | AWS Access Key | CRITICAL | 패턴 |
| `api_key_assignment` | API 키 할당문 | HIGH | 컨텍스트 |
| `pem_private_key` | PEM 개인키 | CRITICAL | 패턴 |
| `jwt_token` | JWT | HIGH | 3-part base64 |
| `github_pat` | GitHub PAT | CRITICAL | 패턴 |

**오탐 개선 이력:**
- `kr_rrn` 체크섬 실패: `0.7` → `0.0` (필터링) — 오탐률 92% 감소 (73/79건 제거)
- `kr_rrn` 생년월일/성별코드 유효성 검사 추가
- `aws_secret_key` (40자 base64 무조건 탐지) 규칙 제거 → `api_key_assignment`로 대체
- `kr_rrn`, `kr_phone`, `credit_card` 한글 유니코드 경계 lookaround 적용

#### 2-4. 액션 결정 (`pipeline/__init__.py`)
```
CRITICAL → MASK
HIGH/MEDIUM/LOW → ALERT
```

#### 2-5. 마스킹 엔진 (`inspect_traffic.py`)
- `_apply_mask()`: offset 역순 적용으로 drift 없이 교체
- `_MASK_TEMPLATES`: 13개 규칙 → 한국어 레이블
- Content-Length 자동 재계산
- `flow.request.content` 교체 후 LLM으로 전달

#### 2-6. 제어 파일 (`/tmp/dlp-control.json`)
```json
{
  "regex_enabled": true,
  "slm_enabled": false,
  "mask_on_detect": true,
  "block_on_alert": false,
  "block_on_mask": false,
  "disabled_rules": []
}
```
- 규칙별 ON/OFF, 정책 스위치 실시간 반영

### ✅ Phase 3 — TUI 대시보드 (완료)

`scripts/tui.py` — Textual 8.2.2, 6탭 구성

| 탭 | 기능 |
|----|------|
| 트래픽 | 요청 목록 + HTTP/엔진 결과 상세보기 + 클리어 버튼 |
| 탐지 목록 | 탐지 findings 목록 + 우측 디테일 패널 + 클리어 버튼 |
| 제어 | 파이프라인 토글, 정책 스위치, 마스킹 규칙 ON/OFF |
| 프로세스 | mitmproxy/engine_server 상태 모니터링 + 시작/중지 |
| 설정 | 포트, 대상 도메인 설정 |
| 엔진 로그 | 실시간 이벤트 로그 + 클리어 버튼 |

**StatsBar** (화면 상단 1줄):  
`턴 N  요청 N  스캔 N  탐지 N  마스킹 N  │  Engine ●  mitm ●`

**TUI 버그 수정 이력 (2026-04-05):**
- `Engine ●` 빨간불 고착 → `_poll_procs`에서 `procs["engine"].running` 으로 mitm_ok와 동일한 방식으로 변경
- `_subscribe` CancelledError sleep 미보호 → try/except 추가
- 클리어 버튼: 트래픽 클리어 시 `traffic.jsonl` 파일도 함께 비움 (재시작 후 되살아나는 문제 수정)
- 탭 툴바: `.tab-toolbar` 공통 CSS — 3탭 일관 디자인
- 탐지목록 좌측 패널 고정 너비(54), 우측 디테일 `1fr`
- mitmproxy `connection_strategy=lazy` 적용 — Bad Gateway 오류 수정
- 트래픽 컬럼: 턴(4) 시각(8) 모델(13) 요(3) 탐(3) 액션(9)
- 탐지 컬럼: 시각(8) 심각도(8) 규칙(16) 신뢰도(5) 모델(9)
- `allow_hosts` 설정으로 Target 도메인만 TLS 복호화

---

## 남은 작업 (Roadmap)

### Phase 4 — SLM 통합 (진행 예정)

#### 목표
Regex Stage만으로 잡기 어려운 **문맥 의존적 PII** (예: 이름+부서가 조합된 간접 식별 정보, 자유형식 주소 등)를 소형 언어 모델로 보완 탐지.

#### 모델 후보
| 모델 | 크기 | 형식 | 비고 |
|------|------|------|------|
| Qwen2.5-1.5B-Instruct | ~1GB Q4 | GGUF | 다국어, 속도 빠름 |
| EXAONE-3.5-2.4B-Instruct | ~1.5GB Q4 | GGUF | 한국어 특화 |

#### 구현 계획
1. **SLMStage** 클래스 작성 (`src/ai_dlp_proxy/engine/pipeline/slm_stage.py`)
   - `llama-cpp-python` 으로 GGUF 모델 로드
   - 입력: 텍스트 청크 + 기존 Regex Stage findings
   - 출력: JSON `{"findings": [{"rule": ..., "start": ..., "end": ..., "text": ..., "confidence": ...}]}`
   - GBNF grammar으로 JSON 출력 강제 (hallucination 방지)
2. **Pipeline 연결** (`pipeline/__init__.py`)
   - RegexStage → SLMStage (slm_enabled=True 시)
   - SLM finding은 Regex가 이미 탐지한 위치 중복 제거
3. **성능 고려**
   - RPi CPU 추론: ~300~800ms 예상 → 비동기 스레드풀 in executor 처리
   - 텍스트 길이 제한 (예: 2000자 초과 시 청킹)
   - 캐시: 동일 텍스트 해시 기준 LRU 캐시
4. **TUI 제어 탭 연동**
   - 기존 `slm_enabled` 스위치 활성화
   - 모델 경로 설정 UI
5. **평가 기준**
   - Regex가 못 잡는 케이스 샘플 20개 수집 → SLM으로 검증
   - 오탐률 허용치: < 10%
   - 지연 허용치: < 1000ms (RPi)

#### 선행 작업
- `llama-cpp-python` RPi ARM64 빌드/설치 확인
- GGUF 모델 다운로드 위치 결정 (`/home1/ai-dlp-proxy/models/`)

### Phase 5 — 패키지화 및 배포 (미구현)
- `pip install ai-dlp-proxy` 배포
- CA 인증서 자동 설치 안내
- Windows/macOS/Linux 시스템 프록시 자동 설정

---

## 실행 방법

```bash
cd /home1/ai-dlp-proxy
source venv/bin/activate

# TUI 실행 (engine_server + mitmdump 자동 기동)
python3 scripts/tui.py

# 수동 기동 시:
# 1. 엔진 서버
PYTHONPATH=src python3 scripts/engine_server.py
# 2. mitmproxy (명시적 프록시)
mitmdump --listen-host 0.0.0.0 -p 4001 --set connection_strategy=lazy -s scripts/inspect_traffic.py
# 2b. 투명 게이트웨이 모드
mitmdump --mode transparent --listen-host 0.0.0.0 -p 4002 --set connection_strategy=lazy -s scripts/inspect_traffic.py
```

### 테스트 클라이언트 프록시 설정
```bash
# 환경변수 방식
export HTTPS_PROXY=http://192.168.0.16:4001
export HTTP_PROXY=http://192.168.0.16:4001
opencode  # 또는 curl, python 등
```

## 주요 파일 구조

```
/home1/ai_dlp_proxy/
├── scripts/
│   ├── inspect_traffic.py   # mitmproxy addon (679줄)
│   ├── engine_server.py     # UDS NDJSON 서버 (368줄)
│   └── tui.py               # Textual TUI (1245줄)
├── src/ai_dlp_proxy/
│   ├── engine/
│   │   ├── api/             # LLM API 파서 (openai/anthropic/gemini)
│   │   └── pipeline/
│   │       ├── __init__.py  # 파이프라인 러너 + 액션 결정
│   │       ├── base.py      # Finding, Severity, Stage 추상 클래스
│   │       └── regex_stage.py  # 12개 DLP 규칙 (350줄)
│   └── extractor.py         # API별 텍스트 추출 디스패처
├── logs/
│   └── traffic.jsonl        # 구조화 로그
├── config/                  # (향후) settings.yaml
├── pyproject.toml
└── plan.md
```


