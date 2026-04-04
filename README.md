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

## 실행 가이드

> RPi IP를 `192.168.0.16` 기준으로 설명합니다. 실제 IP에 맞게 변경하세요.

### 0. 공통 — RPi에서 서버 기동

TUI를 실행하면 engine_server와 mitmdump가 **자동으로** 함께 시작됩니다.

```bash
# RPi SSH 접속 후
cd /home1/ai-dlp-proxy
source venv/bin/activate
python3 scripts/tui.py
```

TUI 상단 Bar에 `Engine ●` `mitm ●` 이 **초록색**으로 표시되면 준비 완료.

> 수동 기동이 필요한 경우:
> ```bash
> # 1. DLP 엔진 서버
> PYTHONPATH=src python3 scripts/engine_server.py
>
> # 2. mitmproxy (명시적 프록시 모드)
> mitmdump --listen-host 0.0.0.0 -p 4001 -s scripts/inspect_traffic.py
> ```

---

### 모드 A — 명시적 프록시 (권장)

클라이언트 측에서 프록시 주소를 직접 지정하는 방식입니다.  
`HTTPS_PROXY` 환경변수 또는 시스템 프록시 설정을 이용합니다.

#### CA 인증서 설치 (최초 1회)

mitmproxy가 HTTPS를 복호화하려면 클라이언트에 CA 인증서를 신뢰시켜야 합니다.

```bash
# RPi에서 CA 파일 위치 확인
ls ~/.mitmproxy/mitmproxy-ca-cert.pem
# 또는 프로젝트 내 복사본
ls /home1/ai-dlp-proxy/config/mitmproxy-ca-cert.pem
```

**Linux / macOS**
```bash
# 시스템 인증서 저장소에 추가
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates          # Ubuntu/Debian
# sudo security add-trusted-cert ... # macOS
```

**Windows**
1. `mitmproxy-ca-cert.pem`을 `.crt`로 복사 후 더블클릭
2. "신뢰할 수 있는 루트 인증 기관" → 인증서 설치

#### opencode (또는 AI 에이전트/CLI 도구)

```bash
# 환경변수로 프록시 지정
export HTTPS_PROXY=http://192.168.0.16:4001
export HTTP_PROXY=http://192.168.0.16:4001

# opencode 실행 (환경변수 자동 적용)
opencode

# curl 테스트
curl -x http://192.168.0.16:4001 https://api.openai.com/v1/models
```

#### Python / requests

```python
import openai

client = openai.OpenAI(
    api_key="sk-...",
    http_client=httpx.Client(
        proxies="http://192.168.0.16:4001",
        verify=False,   # 또는 mitmproxy CA 경로 지정
    ),
)
```

#### 시스템 전체 프록시 (Windows)

설정 → 네트워크 → 프록시 → 수동 프록시 설정:
- 서버: `192.168.0.16`  포트: `4001`

---

### 모드 B — 투명 게이트웨이 (네트워크 레벨 차단)

클라이언트 설정 변경 없이 **RPi를 기본 게이트웨이로** 사용하는 방식입니다.  
모든 TCP 443 트래픽이 자동으로 mitmproxy를 경유합니다.

#### RPi 설정

```bash
# 1. mitmproxy를 투명 프록시 모드로 실행
mitmdump --mode transparent \
         --listen-host 0.0.0.0 -p 4002 \
         -s scripts/inspect_traffic.py

# 2. IP 포워딩 활성화
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# 영구 적용: /etc/sysctl.conf 에 net.ipv4.ip_forward=1 추가

# 3. iptables — HTTPS(443) 및 HTTP(80) 트래픽을 mitmproxy로 리다이렉트
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 4002
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport  80 -j REDIRECT --to-port 4002

# 규칙 확인
sudo iptables -t nat -L PREROUTING -n --line-numbers
```

> TUI에서 자동 기동할 경우 mitmdump 명령에 `--mode transparent -p 4002`를 추가해야 합니다.

#### 클라이언트 설정

클라이언트(PC/스마트폰)의 **기본 게이트웨이**를 RPi IP(`192.168.0.16`)로 변경합니다.

| 항목 | 값 |
|------|----|
| 기본 게이트웨이 | `192.168.0.16` |
| DNS | 기존 공유기 IP 또는 `8.8.8.8` |

CA 인증서는 동일하게 설치 필요 (→ 모드 A 참고).

#### 게이트웨이 모드 종료 (iptables 초기화)

```bash
# 특정 규칙 삭제
sudo iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 4002
sudo iptables -t nat -D PREROUTING -i eth0 -p tcp --dport  80 -j REDIRECT --to-port 4002

# 또는 전체 NAT 테이블 초기화
sudo iptables -t nat -F
```

---

### 모드 비교

| | 명시적 프록시 (A) | 투명 게이트웨이 (B) |
|---|---|---|
| 포트 | 4001 | 4002 |
| 클라이언트 설정 | 프록시 주소 지정 | 게이트웨이 변경 |
| 적용 범위 | 프록시 설정한 앱만 | 네트워크 전체 |
| CA 인증서 | 필요 | 필요 |
| 권장 대상 | 개발·테스트 | 시연·광범위 차단 |

---



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
