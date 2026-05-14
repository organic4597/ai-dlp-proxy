#!/usr/bin/env bash
# =============================================================================
#  setup_iptables.sh — 투명 프록시용 iptables 규칙 설정
#
#  SNI 라우터(:4443)가 443 트래픽을 가로채어
#  AI API 트래픽만 mitmproxy(:4001)로 보내고
#  나머지는 원본 목적지로 직통 전달합니다.
#
#  사용법:
#    sudo bash setup_iptables.sh          # 규칙 적용
#    sudo bash setup_iptables.sh --remove # 규칙 제거
#    sudo bash setup_iptables.sh --status # 현재 규칙 확인
# =============================================================================
set -euo pipefail

SNI_PORT=4443
COMMENT="dlp-sni-router"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# root 확인
[[ $EUID -eq 0 ]] || error "root 권한이 필요합니다: sudo bash $0"

# ── 현재 상태 확인 ────────────────────────────────────────────────────────────
status() {
    echo -e "\n${CYAN}── PREROUTING (nat) ──${RESET}"
    iptables -t nat -L PREROUTING -n --line-numbers -v 2>/dev/null | grep -E "REDIRECT|$COMMENT" || echo "  (없음)"
    echo -e "\n${CYAN}── POSTROUTING (nat) ──${RESET}"
    iptables -t nat -L POSTROUTING -n --line-numbers -v 2>/dev/null | grep -E "MASQUERADE|$COMMENT" || echo "  (없음)"
    echo -e "\n${CYAN}── IP 포워딩 ──${RESET}"
    cat /proc/sys/net/ipv4/ip_forward
}

# ── 규칙 제거 ────────────────────────────────────────────────────────────────
remove_rules() {
    info "기존 DLP iptables 규칙 제거 중..."

    # PREROUTING 규칙 제거 (포트 4443 REDIRECT)
    while iptables -t nat -L PREROUTING -n | grep -q "redir ports $SNI_PORT"; do
        iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$SNI_PORT"
    done

    # POSTROUTING MASQUERADE 제거 (eth0 기준)
    ETH=$(ip route show default | awk '/default/ {print $5}' | head -1)
    iptables -t nat -D POSTROUTING -o "$ETH" -j MASQUERADE 2>/dev/null || true

    # 라즈베리파이 자신의 트래픽은 제외 규칙 제거
    iptables -t nat -D PREROUTING -p tcp --dport 443 -m owner --uid-owner root -j RETURN 2>/dev/null || true
    iptables -t nat -D OUTPUT    -p tcp --dport 443 -m owner --uid-owner root -j RETURN 2>/dev/null || true

    ok "규칙 제거 완료"
}

# ── 인수 처리 ────────────────────────────────────────────────────────────────
case "${1:-}" in
    --remove) remove_rules; exit 0 ;;
    --status) status; exit 0 ;;
    "") ;;  # 기본: 규칙 적용
    *) error "알 수 없는 옵션: $1\n사용법: sudo bash $0 [--remove|--status]" ;;
esac

# ── 기존 규칙 정리 후 적용 ───────────────────────────────────────────────────
remove_rules 2>/dev/null || true

# 기본 네트워크 인터페이스 감지
ETH=$(ip route show default | awk '/default/ {print $5}' | head -1)
[[ -n "$ETH" ]] || error "기본 네트워크 인터페이스를 찾을 수 없습니다"
info "기본 인터페이스: $ETH"

# IP 포워딩 활성화
info "IP 포워딩 활성화..."
echo 1 > /proc/sys/net/ipv4/ip_forward
# 영구 설정
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf \
    && sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP 포워딩: $(cat /proc/sys/net/ipv4/ip_forward)"

# ── iptables 규칙 적용 ────────────────────────────────────────────────────────

# 1. 아웃바운드 NAT (인터넷 연결)
iptables -t nat -A POSTROUTING -o "$ETH" -j MASQUERADE
ok "MASQUERADE 규칙 적용 (out: $ETH)"

# 2. 라즈베리파이 자신의 443 트래픽은 리다이렉트 제외
#    (로컬에서 curl 등을 쓸 때 무한 루프 방지)
iptables -t nat -I PREROUTING 1 -p tcp --dport 443 \
    -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -I OUTPUT     1 -p tcp --dport 443 \
    -m addrtype --dst-type LOCAL -j RETURN

# 3. 외부 클라이언트의 443 → sni-router (4443) 리다이렉트
iptables -t nat -A PREROUTING -p tcp --dport 443 \
    -j REDIRECT --to-port "$SNI_PORT"
ok "PREROUTING: :443 → :$SNI_PORT (sni-router)"

# ── mitmproxy transparent 모드를 위한 추가 규칙 ──────────────────────────────
# mitmproxy 전용 계정(dlp-mitm)의 아웃바운드만 제외 → 루프 방지
# root(VS Code extensionHost 포함) 등 나머지 모든 프로세스는 REDIRECT 적용
#
# 계정 생성: sudo useradd -r -M -s /bin/false dlp-mitm
MITM_USER="${DLP_MITM_USER:-dlp-mitm}"  # mitmproxy 실행 전용 계정
MITM_PORT_LOCAL="${DLP_MITM_PORT:-4001}"

if id "$MITM_USER" &>/dev/null 2>&1; then
    # 1. mitmproxy 계정 아웃바운드 → RETURN (루프 방지)
    iptables -t nat -I OUTPUT 1 -p tcp --dport 443 \
        -m owner --uid-owner "$MITM_USER" -j RETURN 2>/dev/null \
        && info "mitmproxy ($MITM_USER) 루프 방지 규칙 적용" \
        || warn "owner 모듈 없음 — 루프 방지 규칙 생략 (xt_owner 필요)"

    # 2. 로컬 목적지 제외 (로컬 서비스 무한루프 방지)
    iptables -t nat -I OUTPUT 2 -p tcp --dport 443 \
        -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true

    # 3. 그 외 모든 프로세스(root/VS Code 포함) → transparent proxy
    iptables -t nat -A OUTPUT -p tcp --dport 443 \
        -j REDIRECT --to-ports "$MITM_PORT_LOCAL" 2>/dev/null \
        && ok "OUTPUT REDIRECT 적용 (root/VS Code 포함 → :$MITM_PORT_LOCAL)" \
        || warn "OUTPUT REDIRECT 실패"
else
    warn "계정 '$MITM_USER' 없음 → OUTPUT REDIRECT 생략 (VS Code 트래픽 미탐지)"
    warn "  계정 생성: sudo useradd -r -M -s /bin/false $MITM_USER"
    warn "  이후 DLP_MITM_USER=$MITM_USER 환경변수와 함께 재실행"
fi

# ── 규칙 영구 저장 ───────────────────────────────────────────────────────────
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    ok "iptables 규칙 영구 저장 완료"
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null && ok "규칙 저장: /etc/iptables/rules.v4" \
    || warn "자동 저장 실패 — 수동으로 저장하세요: sudo iptables-save > /etc/iptables/rules.v4"
else
    warn "영구 저장 도구 없음. 재부팅 시 규칙 사라짐."
    warn "  sudo apt install iptables-persistent"
fi

# ── 결과 출력 ────────────────────────────────────────────────────────────────
echo ""
ok "iptables 투명 프록시 설정 완료!"
echo ""
echo "  트래픽 흐름:"
echo "    클라이언트 :443"
echo "      → iptables PREROUTING → sni-router :$SNI_PORT"
echo "          AI 도메인 → mitmproxy :4001 (DLP 검사)"
echo "          기타      → 원본 목적지 직통"
echo ""
echo "  시작 방법:"
echo "    bash start_dlp.sh --sni"
echo ""
echo "  제거 방법:"
echo "    sudo bash setup_iptables.sh --remove"
echo ""
echo "  클라이언트 공유기 설정:"
echo "    DHCP 게이트웨이 → 이 서버 IP ($(hostname -I | awk '{print $1}'))"
