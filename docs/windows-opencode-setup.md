# Windows opencode 프록시 설정 매뉴얼

AI DLP Proxy(RPi)를 통해 opencode 트래픽을 캡처하기 위한 Windows 설정 가이드.

---

## 전제 조건

- RPi(192.168.0.16)에서 TUI(`python3 scripts/tui.py`)가 실행 중이어야 함
- Windows PC와 RPi가 같은 네트워크에 있어야 함

---

## Step 1 — mitmproxy CA 인증서 설치

> **중요**: 인증서는 반드시 **"로컬 컴퓨터 > 신뢰할 수 있는 루트 인증 기관"** 저장소에 설치해야 합니다.  
> 브라우저 더블클릭 설치나 "현재 사용자" 저장소 설치는 curl/Node.js에 적용되지 않습니다.

### 1-1. 관리자 CMD 열기

시작 메뉴 → `cmd` 검색 → **우클릭 → 관리자 권한으로 실행**

### 1-2. 인증서 다운로드

```cmd
set HTTP_PROXY=http://192.168.0.16:4001
curl http://mitm.it/cert/cer -o C:\mitmproxy-ca.cer
```

파일 크기 확인 (1KB 이상이어야 정상):
```cmd
dir C:\mitmproxy-ca.cer
```

> 파일이 0바이트이거나 HTML이면 RPi TUI가 꺼진 상태입니다. RPi 먼저 확인하세요.

### 1-3. 로컬 컴퓨터 루트 저장소에 설치

```cmd
certutil -addstore Root C:\mitmproxy-ca.cer
```

성공 메시지:
```
Root "신뢰할 수 있는 루트 인증 기관"
서명이 공개 키와 일치합니다.
인증서가 CertStore에 추가되었습니다.
```

### 1-4. 설치 검증

```cmd
curl --proxy http://192.168.0.16:4001 https://api.githubcopilot.com/ -I
```

성공 시 `HTTP/1.1 407` 또는 `HTTP/2 200` 등 응답 헤더가 출력되고 `curl: (35)` 또는 `curl: (60)` 에러가 없어야 합니다.

---

## Step 2 — opencode 실행 (매번)

opencode는 Node.js 기반으로 **Windows 인증서 저장소를 무시**하고 자체 CA 번들을 사용합니다.  
따라서 `NODE_EXTRA_CA_CERTS` 환경변수를 추가로 설정해야 합니다.

```cmd
set HTTP_PROXY=http://192.168.0.16:4001
set HTTPS_PROXY=http://192.168.0.16:4001
set NO_PROXY=localhost,127.0.0.1
set NODE_EXTRA_CA_CERTS=C:\mitmproxy-ca.cer
opencode
```

### 영구 설정 (관리자 PowerShell)

매번 입력하기 번거로우면 시스템 환경변수로 등록:

```powershell
[System.Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "C:\mitmproxy-ca.cer", "Machine")
```

> 설정 후 새 CMD 창을 열어야 적용됩니다.

---

## 트러블슈팅

### `curl: (35)` — `0x80096004` 서명 검증 불가
인증서 파일이 없거나 손상됨. Step 1-2부터 재시도.

### `curl: (60)` — `0x80090325` 신뢰되지 않은 루트
인증서가 **CurrentUser** 저장소에만 설치됨.  
→ **관리자 CMD**에서 `certutil -addstore Root` 재실행.

### `Client TLS handshake failed` (RPi mitm.log)
opencode가 mitmproxy 인증서를 거부하는 중.  
→ `NODE_EXTRA_CA_CERTS` 환경변수 설정 확인.

### `If you can see this, traffic is not going through mitmproxy` (브라우저)
브라우저는 `set HTTP_PROXY` 환경변수를 무시함 (Windows 시스템 프록시를 봄).  
→ 브라우저로 `http://mitm.it` 접속하려면 Windows 설정 → 프록시 → 수동 프록시 설정 필요.  
→ 인증서 다운로드는 **CMD의 curl**로 하면 됩니다 (브라우저 불필요).

### TUI 트래픽 탭에 아무것도 안 올라옴
1. RPi TUI 프로세스 탭에서 mitmproxy/engine 상태 확인 (초록불인지)
2. `set` 환경변수가 같은 CMD 창에 설정됐는지 확인
3. RPi 측 로그 확인: `/home1/ai-dlp-proxy/logs/mitm.log`

---

## 빠른 참조

| 항목 | 값 |
|------|-----|
| RPi 주소 | 192.168.0.16 |
| 프록시 포트 | 4001 |
| 인증서 경로 | `C:\mitmproxy-ca.cer` |
| mitm.it 인증서 페이지 | `http://mitm.it` (프록시 설정 후 접속) |
| Node.js CA 환경변수 | `NODE_EXTRA_CA_CERTS=C:\mitmproxy-ca.cer` |
