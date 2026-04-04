# AI Agent DLP Proxy

> LLM API 트래픽을 가로채어 개인정보를 자동 탐지·마스킹하는 인라인 DLP 프록시

## 개요

AI 에이전트나 사용자가 ChatGPT, Claude, Gemini 등 외부 LLM 서비스에 요청을 보낼 때, 주민등록번호·카드번호·전화번호·API 키 등 민감 데이터가 포함되는 경우가 있습니다.

**AI Agent DLP Proxy**는 mitmproxy를 기반으로 이 트래픽을 투명하게 가로채어, 민감 데이터를 자동으로 탐지하고 `[주민등록번호]`와 같은 레이블로 치환한 뒤 LLM 서버로 전달합니다. 사용자나 에이전트 코드 변경 없이 프록시 설정만으로 동작합니다.

---

## 아키텍처

```
PC (AI Agent / 브라우저)
    │  시스템 프록시 → RPi:4001
    ▼
mitmproxy :4001
    │  HTTPS 복호화 (CA 인증서)
    │  inspect_traffic.py addon
    │    ├─ API 파서 (OpenAI / Anthropic / Gemini)
    │    ├─ 텍스트 추출
    │    └─ DLP 엔진 스캔 요청
    │
    ▼ UDS /tmp/dlp-engine.sock
engine_server.py
    │  NDJSON 프로토콜
    └─ DLP Pipeline → RegexStage (12개 규칙)
         ├─ 탐지 → 마스킹 후 LLM 전달
         └─ 정책에 따라 403 차단 가능

tui.py (Textual TUI)
    └─ 6탭 실시간 모니터링 · 제어 대시보드
```

---

## 주요 기능

### DLP 탐지 규칙 (12개)

| 규칙 | 대상 | 등급 | 검증 |
|------|------|------|------|
| `kr_rrn` | 주민등록번호 | CRITICAL | mod-11 체크섬 + 생년월일 + 성별코드 |
| `credit_card` | 신용카드번호 | CRITICAL | Luhn 알고리즘 |
| `us_ssn` | 미국 SSN | CRITICAL | 패턴 |
| `aws_access_key` | AWS 액세스키 | CRITICAL | `AKIA` 접두어 |
| `pem_private_key` | PEM 개인키 | CRITICAL | BEGIN/END 블록 |
| `github_pat` | GitHub PAT | CRITICAL | `ghp_` 접두어 |
| `kr_passport` | 여권번호 | HIGH | 패턴 |
| `kr_driver_license` | 운전면허번호 | HIGH | 패턴 |
| `jwt_token` | JWT | HIGH | 3-part base64 |
| `api_key_assignment` | API 키 할당문 | HIGH | 컨텍스트 |
| `kr_phone` | 휴대전화번호 | MEDIUM | 010/011 패턴 |
| `email` | 이메일 | LOW | RFC 패턴 |

### 마스킹 파이프라인

```
탐지된 PII → offset 기반 역순 치환 → Content-Length 재계산 → LLM 전달
```

**Before**
```
주민번호 900101-1234568, 카드 4532-1234-5678-9012, 연락처 010-1234-5678
```

**After (LLM에 전달되는 내용)**
```
주민번호 [주민등록번호], 카드 [신용카드번호], 연락처 [전화번호]
```

### TUI 대시보드

Textual 기반 6탭 인터랙티브 모니터링

- **트래픽** — 요청/응답 목록 + 엔진 결과 상세보기
- **탐지** — 누적 findings (규칙·심각도·매칭 텍스트)
- **제어** — 파이프라인 ON/OFF, 정책 스위치, 규칙별 활성화
- **프로세스** — mitmproxy·engine_server 상태 모니터링·재시작
- **설정** — 포트, 대상 도메인
- **로그** — 실시간 이벤트 스트림

상단 StatsBar: `턴 N  요청 N  스캔 N  탐지 N  마스킹 N  │  Engine ●  mitm ●`

---

## 시작하기

### 요구사항

- Python 3.12+
- Raspberry Pi (또는 Linux 머신)
- Windows/Mac PC에서 프록시 설정 가능한 환경

### 설치

```bash
git clone https://github.com/organic4597/ai-dlp-proxy.git
cd ai-dlp-proxy
python3 -m venv venv
source venv/bin/activate
pip install mitmproxy textual
```

### CA 인증서 설치 (Windows PC)

```bash
# RPi에서 mitmproxy 최초 실행으로 인증서 생성
mitmdump -p 4001

# 생성된 인증서를 Windows로 복사 후 설치
# ~/.mitmproxy/mitmproxy-ca-cert.cer
# → Windows: 신뢰할 수 있는 루트 인증 기관에 설치
```

### 실행

```bash
# 1. DLP 엔진 서버
PYTHONPATH=src nohup python3 scripts/engine_server.py > /tmp/engine_server.log 2>&1 &

# 2. mitmproxy 프록시
mitmdump --listen-host 0.0.0.0 -p 4001 -s scripts/inspect_traffic.py &

# 3. TUI 모니터링
PYTHONPATH=src python3 scripts/tui.py
```

Windows PC에서 시스템 프록시를 `RPi_IP:4001`로 설정하면 LLM 트래픽이 자동으로 DLP 프록시를 경유합니다.

---

## 제어 정책

`/tmp/dlp-control.json` 파일로 실시간 정책 제어 (TUI 제어 탭에서 자동 관리)

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

| 필드 | 설명 |
|------|------|
| `mask_on_detect` | 탐지 시 마스킹 후 통과 |
| `block_on_alert` | ALERT 이상 탐지 시 403 차단 |
| `block_on_mask` | 마스킹 대상 탐지 시 403 차단 |
| `disabled_rules` | 비활성화할 규칙 이름 목록 |

---

## 성능

| 항목 | 수치 |
|------|------|
| Regex Stage 스캔 | < 1ms |
| 전체 마스킹 오버헤드 | < 5ms |
| kr_rrn 오탐률 개선 | 92% 감소 (73건 → 0건) |
| 통신 방식 | Unix Domain Socket |

---

## 프로젝트 구조

```
ai-dlp-proxy/
├── scripts/
│   ├── inspect_traffic.py    # mitmproxy addon — 트래픽 탐지·마스킹
│   ├── engine_server.py      # UDS NDJSON DLP 엔진 서버
│   └── tui.py                # Textual TUI 대시보드
├── src/ai_dlp_proxy/
│   └── engine/
│       ├── api/              # LLM API 파서 (openai / anthropic / gemini)
│       └── pipeline/
│           ├── regex_stage.py   # 12개 DLP 탐지 규칙
│           └── base.py          # Finding, Severity, Stage 추상 클래스
├── docs/
│   └── ppt_content.md        # 과제 발표 내용 초안
├── pyproject.toml
└── plan.md                   # 상세 개발 계획서
```

---

## 로드맵

- [x] HTTPS 투명 프록싱 (mitmproxy)
- [x] 12개 DLP 규칙 (체크섬·Luhn 알고리즘 검증)
- [x] 실시간 마스킹 파이프라인
- [x] Textual TUI 6탭 대시보드
- [x] 오탐 개선 (kr_rrn 체크섬 검증 강화)
- [ ] SLM 컨텍스트 기반 탐지 (Qwen2.5 / EXAONE)
- [ ] `pip install ai-dlp-proxy` 배포 패키지
- [ ] CA 인증서 자동 설치
- [ ] 사용자 정의 정책 (`settings.yaml`)

---

## 기술 스택

- **Python** 3.12
- **mitmproxy** 12.2.1
- **Textual** 8.2.2
- **asyncio** + Unix Domain Socket (IPC)
- **Raspberry Pi** (ARM Linux)

---

## 라이선스

MIT License
