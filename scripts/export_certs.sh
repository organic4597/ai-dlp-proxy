#!/usr/bin/env bash
# =============================================================================
#  export_certs.sh — mitmproxy CA 인증서를 OS별 포맷으로 내보내기
#
#  출력 디렉토리:
#    certs/linux/    → .crt  (PEM, update-ca-certificates 용)
#    certs/wsl/      → .crt  (Linux와 동일)
#    certs/macos/    → .pem  (키체인 등록용)
#    certs/windows/  → .p12  (인증서 저장소, 더블클릭 설치)
#                   → .cer  (DER, IE/Edge 구형 방식)
#    certs/android/  → .cer  (DER, 설정 → 인증서 설치)
#
#  사용법:
#    bash scripts/export_certs.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error(){ echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="$ROOT/certs"
MITMPROXY_DIR="${MITMPROXY_DIR:-$HOME/.mitmproxy}"

CA_PEM="$MITMPROXY_DIR/mitmproxy-ca-cert.pem"
CA_KEY="$MITMPROXY_DIR/mitmproxy-ca.pem"   # 키+cert 합본 (p12 생성용)
CA_P12_SRC="$MITMPROXY_DIR/mitmproxy-ca-cert.p12"
CA_CER_SRC="$MITMPROXY_DIR/mitmproxy-ca-cert.cer"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║  AI DLP — OS별 CA 인증서 내보내기               ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ── 소스 확인 ────────────────────────────────────────────────────────────────
[[ -f "$CA_PEM" ]] || error "CA 인증서 없음: $CA_PEM\n  start_dlp.sh 를 먼저 실행하세요."
info "소스 CA: $CA_PEM"
echo ""

# ── Linux ────────────────────────────────────────────────────────────────────
info "Linux (.crt — update-ca-certificates 용)"
cp "$CA_PEM" "$CERTS_DIR/linux/mitmproxy-ca.crt"
ok "certs/linux/mitmproxy-ca.crt"

# ── WSL ──────────────────────────────────────────────────────────────────────
info "WSL (.crt — Linux와 동일)"
cp "$CA_PEM" "$CERTS_DIR/wsl/mitmproxy-ca.crt"
ok "certs/wsl/mitmproxy-ca.crt"

# ── macOS ────────────────────────────────────────────────────────────────────
info "macOS (.pem — 키체인 등록용)"
cp "$CA_PEM" "$CERTS_DIR/macos/mitmproxy-ca.pem"
ok "certs/macos/mitmproxy-ca.pem"

# ── Windows (.p12) ───────────────────────────────────────────────────────────
info "Windows (.p12 — 더블클릭 → 인증서 저장소 설치)"
if [[ -f "$CA_P12_SRC" ]]; then
    cp "$CA_P12_SRC" "$CERTS_DIR/windows/mitmproxy-ca.p12"
    ok "certs/windows/mitmproxy-ca.p12  (기존 파일 복사)"
elif [[ -f "$CA_KEY" ]] && command -v openssl &>/dev/null; then
    openssl pkcs12 -export \
        -in "$CA_PEM" \
        -inkey "$CA_KEY" \
        -out "$CERTS_DIR/windows/mitmproxy-ca.p12" \
        -passout pass: \
        -name "AI DLP Proxy CA" 2>/dev/null
    ok "certs/windows/mitmproxy-ca.p12  (openssl 변환)"
else
    warn "openssl 없음 — windows/.p12 생성 건너뜀"
fi

# ── Windows (.cer DER) ───────────────────────────────────────────────────────
info "Windows (.cer DER — 구형 방식)"
if [[ -f "$CA_CER_SRC" ]]; then
    cp "$CA_CER_SRC" "$CERTS_DIR/windows/mitmproxy-ca.cer"
    ok "certs/windows/mitmproxy-ca.cer  (기존 파일 복사)"
elif command -v openssl &>/dev/null; then
    openssl x509 -in "$CA_PEM" -outform DER \
        -out "$CERTS_DIR/windows/mitmproxy-ca.cer" 2>/dev/null
    ok "certs/windows/mitmproxy-ca.cer  (openssl DER 변환)"
else
    warn "openssl 없음 — windows/.cer 생성 건너뜀"
fi

# ── Android (.cer DER) ───────────────────────────────────────────────────────
info "Android (.cer DER — 설정 → 보안 → 인증서 설치)"
if command -v openssl &>/dev/null; then
    openssl x509 -in "$CA_PEM" -outform DER \
        -out "$CERTS_DIR/android/mitmproxy-ca.cer" 2>/dev/null
    ok "certs/android/mitmproxy-ca.cer"
else
    cp "$CA_PEM" "$CERTS_DIR/android/mitmproxy-ca.pem"
    ok "certs/android/mitmproxy-ca.pem  (openssl 없음 — PEM으로 대체)"
fi

# ── 결과 요약 ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── 생성된 파일 ──────────────────────────────────────${RESET}"
find "$CERTS_DIR" -type f | sort | while read -r f; do
    rel="${f#$ROOT/}"
    echo -e "  ${CYAN}$rel${RESET}"
done

echo ""
echo -e "${BOLD}── OS별 설치 방법 ───────────────────────────────────${RESET}"
echo ""
echo -e "  ${BOLD}Linux / WSL${RESET}"
echo -e "    sudo cp certs/linux/mitmproxy-ca.crt /usr/local/share/ca-certificates/"
echo -e "    sudo update-ca-certificates"
echo ""
echo -e "  ${BOLD}macOS${RESET}"
echo -e "    open certs/macos/mitmproxy-ca.pem"
echo -e "    (키체인 접근 → 인증서 더블클릭 → '항상 신뢰')"
echo ""
echo -e "  ${BOLD}Windows${RESET}"
echo -e "    certs\\windows\\mitmproxy-ca.p12 더블클릭"
echo -e "    → '신뢰할 루트 인증 기관'에 설치"
echo ""
echo -e "  ${BOLD}Android${RESET}"
echo -e "    기기로 파일 전송 후:"
echo -e "    설정 → 보안 → 인증서 설치 → mitmproxy-ca.cer 선택"
echo ""
echo -e "  ${BOLD}Node.js (WSL/Linux 공통 추가 설정)${RESET}"
echo -e "    export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca.crt"
echo ""
