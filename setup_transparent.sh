#!/usr/bin/env bash
# =============================================================================
#  setup_transparent.sh — AI DLP 투명 프록시 자동 설정
#
#  수행 작업:
#    1. iptables 투명 프록시 규칙 (443 → SNI 라우터)
#    2. dnsmasq DHCP 서버 설치 및 실행
#       → 클라이언트에게 "게이트웨이 = 이 서버"를 자동 광고
#       → 공유기 DHCP와 병행 (더 빠른 응답으로 우선 적용)
#
#  사용법:
#    sudo bash setup_transparent.sh            # 설정 적용
#    sudo bash setup_transparent.sh --remove   # 설정 제거
#    sudo bash setup_transparent.sh --status   # 현재 상태 확인
#
#  지원 공유기 자동 설정:
#    - OpenWrt (SSH 접근 가능 시): UCI 명령으로 DHCP 게이트웨이 자동 변경
#    - 일반 공유기: dnsmasq DHCP 광고로 클라이언트 유도
# =============================================================================
set -euo pipefail

# ── 색상 ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
step()  { echo -e "\n${BOLD}── $* ──${RESET}"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── 설정 값 (자동 감지) ───────────────────────────────────────────────────────
SNI_PORT=4443
DNSMASQ_CONF="/etc/dnsmasq.d/dlp-transparent.conf"
DNSMASQ_PID_FILE="/tmp/dlp-dnsmasq.pid"

# 네트워크 인터페이스 자동 감지
ETH=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)
MY_IP=$(ip -4 addr show "$ETH" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
SUBNET_PREFIX=$(echo "$MY_IP" | cut -d. -f1-3)  # 예: 192.168.0

[[ $EUID -eq 0 ]] || error "root 권한 필요: sudo bash $0"
[[ -n "$ETH" ]]    || error "기본 네트워크 인터페이스를 찾을 수 없습니다"
[[ -n "$MY_IP" ]]  || error "이 서버의 IP를 감지할 수 없습니다"

# ── 상태 확인 ────────────────────────────────────────────────────────────────
status() {
    step "현재 상태"
    echo -e "  서버 IP    : ${BOLD}$MY_IP${RESET}  (인터페이스: $ETH)"
    echo -e "  기본 게이트: $GATEWAY"
    echo ""
    echo -e "${CYAN}── iptables (nat PREROUTING) ──${RESET}"
    iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep -E "REDIRECT|RETURN" || echo "  (규칙 없음)"
    echo ""
    echo -e "${CYAN}── dnsmasq 상태 ──${RESET}"
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        echo "  dnsmasq: 실행 중"
        [[ -f "$DNSMASQ_CONF" ]] && echo "  설정 파일: $DNSMASQ_CONF"
    else
        echo "  dnsmasq: 중지됨 또는 미설치"
    fi
    echo ""
    echo -e "${CYAN}── IP 포워딩 ──${RESET}"
    echo "  net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
}

# ── 제거 ────────────────────────────────────────────────────────────────────
remove_all() {
    step "투명 프록시 설정 제거"

    # iptables 규칙 제거
    while iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports $SNI_PORT"; do
        iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$SNI_PORT" 2>/dev/null || break
    done
    iptables -t nat -D PREROUTING -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true
    iptables -t nat -D OUTPUT     -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$ETH" -j MASQUERADE 2>/dev/null || true
    # FORWARD 규칙 제거
    iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$ETH" -o "$ETH" -j ACCEPT 2>/dev/null || true
    ok "iptables 규칙 제거"

    # dnsmasq 설정 제거
    if [[ -f "$DNSMASQ_CONF" ]]; then
        rm -f "$DNSMASQ_CONF"
        systemctl restart dnsmasq 2>/dev/null || true
        ok "dnsmasq DLP 설정 제거"
    fi

    # IP 포워딩은 유지 (다른 용도 가능성)
    warn "IP 포워딩(net.ipv4.ip_forward)은 유지됩니다. 직접 끄려면:"
    warn "  sudo sysctl -w net.ipv4.ip_forward=0"

    ok "제거 완료"
}

# ── 인수 처리 ────────────────────────────────────────────────────────────────
case "${1:-}" in
    --remove) remove_all; exit 0 ;;
    --status) status; exit 0 ;;
    "") ;;
    *) error "알 수 없는 옵션: $1\n  사용법: sudo bash $0 [--remove|--status]" ;;
esac

# =============================================================================
# 시작 배너
# =============================================================================
echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║    AI DLP 투명 프록시 자동 설정                  ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo -e "  서버 IP    : ${BOLD}$MY_IP${RESET}"
echo -e "  인터페이스 : $ETH"
echo -e "  현재 GW    : $GATEWAY"
echo -e "  서브넷     : $SUBNET_PREFIX.0/24"
echo ""

# =============================================================================
# STEP 1. IP 포워딩
# =============================================================================
step "1. IP 포워딩 활성화"
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf \
    && sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP 포워딩 활성화됨"

# =============================================================================
# STEP 2. iptables 투명 프록시 규칙
# =============================================================================
step "2. iptables 규칙 적용"

# 기존 DLP 규칙 정리
while iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports $SNI_PORT"; do
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$SNI_PORT" 2>/dev/null || break
done
iptables -t nat -D PREROUTING -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true
iptables -t nat -D OUTPUT     -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true
iptables -t nat -D POSTROUTING -o "$ETH" -j MASQUERADE 2>/dev/null || true

# MASQUERADE (아웃바운드 NAT)
iptables -t nat -A POSTROUTING -o "$ETH" -j MASQUERADE
ok "NAT MASQUERADE ($ETH)"

# FORWARD 체인 — 게이트웨이 역할 허용 (기본 policy=DROP 우회)
# ESTABLISHED/RELATED: TCP 응답 패킷 통과 (없으면 단방향만 됨)
# eth0→eth0: LAN 클라이언트 ↔ 인터넷 (라우터가 같은 인터페이스)
iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$ETH" -o "$ETH" -j ACCEPT 2>/dev/null || true
iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I FORWARD 2 -i "$ETH" -o "$ETH" -j ACCEPT
ok "FORWARD 허용 (게이트웨이 모드: ESTABLISHED + $ETH → $ETH)"

# 로컬 주소행 및 이 서버 자신의 443 제외 (루프 방지)
iptables -t nat -I PREROUTING 1 -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -I OUTPUT     1 -p tcp --dport 443 -m addrtype --dst-type LOCAL -j RETURN
ok "로컬/루프백 제외 규칙"

# 외부 443 → SNI 라우터
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$SNI_PORT"
ok "PREROUTING :443 → :$SNI_PORT (sni-router)"

# mitmproxy 사용자 아웃바운드 제외 (루프 방지)
MITM_USER=$(id -un 2>/dev/null || echo "ubuntu")
iptables -t nat -I OUTPUT 1 -p tcp --dport 443 \
    -m owner --uid-owner "$MITM_USER" -j RETURN 2>/dev/null \
    && ok "mitmproxy($MITM_USER) 아웃바운드 루프 방지" \
    || warn "owner 모듈 없음 — xt_owner 커널 모듈 필요"

# 영구 저장
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    ok "iptables 영구 저장 (netfilter-persistent)"
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ok "iptables 영구 저장 (/etc/iptables/rules.v4)"
else
    warn "영구 저장 불가 — 재부팅 후 사라짐 (apt install iptables-persistent 권장)"
fi

# =============================================================================
# STEP 3. DHCP 게이트웨이 광고 — 3가지 경로 자동 시도
# =============================================================================
step "3. DHCP 게이트웨이 자동 설정"

DHCP_DONE=false

# ── 경로 A: OpenWrt 감지 (SSH + UCI) ────────────────────────────────────────
try_openwrt() {
    info "OpenWrt 감지 시도 ($GATEWAY)..."
    if ! command -v ssh &>/dev/null; then
        info "ssh 없음 — 건너뜀"
        return 1
    fi
    # SSH 연결 테스트 (타임아웃 3초)
    if ! ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o BatchMode=yes root@"$GATEWAY" \
             "uci show dhcp" &>/dev/null; then
        info "SSH 연결 불가 또는 OpenWrt 아님 — 건너뜀"
        return 1
    fi
    info "OpenWrt 감지됨! UCI로 DHCP 게이트웨이 설정..."
    ssh -o StrictHostKeyChecking=no root@"$GATEWAY" bash <<OPENWRT_EOF
# 기존 router 옵션 제거 후 새 게이트웨이 설정
uci delete dhcp.lan.dhcp_option 2>/dev/null || true
uci add_list dhcp.lan.dhcp_option="3,$MY_IP"   # option 3 = router (gateway)
uci add_list dhcp.lan.dhcp_option="6,$MY_IP"   # option 6 = DNS server
uci commit dhcp
/etc/init.d/dnsmasq restart
echo "OpenWrt DHCP 게이트웨이 → $MY_IP 설정 완료"
OPENWRT_EOF
    ok "OpenWrt: DHCP 게이트웨이 → $MY_IP"
    return 0
}

# ── 경로 B: 이 서버에서 dnsmasq DHCP 서버 실행 ──────────────────────────────
setup_dnsmasq() {
    info "dnsmasq 설치 확인..."
    if ! command -v dnsmasq &>/dev/null; then
        info "dnsmasq 설치 중..."
        apt-get install -y dnsmasq -qq || { warn "dnsmasq 설치 실패"; return 1; }
    fi
    ok "dnsmasq 사용 가능: $(dnsmasq --version 2>&1 | head -1)"

    # DHCP 범위 자동 계산 (서버 IP 제외)
    # 예: 서버가 192.168.0.100이면 DHCP는 192.168.0.150~250 제공
    local server_last_octet; server_last_octet=$(echo "$MY_IP" | cut -d. -f4)
    local dhcp_start dhcp_end
    if [[ $server_last_octet -le 100 ]]; then
        dhcp_start="${SUBNET_PREFIX}.150"
        dhcp_end="${SUBNET_PREFIX}.250"
    else
        dhcp_start="${SUBNET_PREFIX}.10"
        dhcp_end="${SUBNET_PREFIX}.100"
    fi

    info "DHCP 범위: $dhcp_start ~ $dhcp_end (게이트웨이: $MY_IP)"

    # systemd-resolved가 53번 포트를 점유하고 있으면 해제
    if ss -tlnp 2>/dev/null | grep -q ':53 '; then
        info "포트 53 충돌 감지 — systemd-resolved stub 비활성화..."
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/no-stub.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
        systemctl restart systemd-resolved 2>/dev/null || true
        ok "systemd-resolved DNSStubListener 비활성화"
    fi

    # dnsmasq DLP 설정 파일 생성
    cat > "$DNSMASQ_CONF" <<EOF
# AI DLP Proxy — 투명 프록시용 DHCP 설정
# $(date)

interface=$ETH
bind-interfaces
except-interface=lo

# DHCP 범위 및 임대 시간 (짧게 설정 → 빠른 반영)
dhcp-range=$dhcp_start,$dhcp_end,255.255.255.0,10m

# 게이트웨이 = 이 서버 (DLP 프록시)
dhcp-option=option:router,$MY_IP

# DNS = 이 서버 경유 또는 기존 공유기
dhcp-option=option:dns-server,$MY_IP,$GATEWAY

# 기존 공유기 DHCP보다 빠르게 응답하도록 지연 없음
dhcp-reply-delay=0
EOF

    # dnsmasq 재시작
    systemctl enable dnsmasq &>/dev/null || true
    systemctl restart dnsmasq
    sleep 1

    if systemctl is-active --quiet dnsmasq; then
        ok "dnsmasq 실행 중 (DHCP: $dhcp_start ~ $dhcp_end, GW: $MY_IP)"
        return 0
    else
        warn "dnsmasq 시작 실패"
        journalctl -u dnsmasq -n 10 --no-pager 2>/dev/null || true
        return 1
    fi
}

# 자동 시도 순서
if try_openwrt 2>/dev/null; then
    DHCP_DONE=true
elif setup_dnsmasq; then
    DHCP_DONE=true
else
    warn "자동 DHCP 설정 실패 — 수동 설정 필요"
fi

# =============================================================================
# STEP 4. CA 인증서 배포 안내
# =============================================================================
step "4. 클라이언트 CA 인증서"
CERT_PATH="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CERT_P12="$HOME/.mitmproxy/mitmproxy-ca-cert.p12"

if [[ -f "$CERT_PATH" ]]; then
    ok "mitmproxy CA 인증서 위치: $CERT_PATH"
    if [[ -f "$CERT_P12" ]]; then
        ok "Windows용 P12: $CERT_P12"
    fi
else
    warn "mitmproxy CA 인증서 없음 — start_dlp.sh 먼저 실행하세요"
fi

# =============================================================================
# 결과 출력
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  투명 프록시 설정 완료!                          ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}트래픽 흐름:${RESET}"
echo -e "  클라이언트 ${DIM}(게이트웨이 = $MY_IP)${RESET}"
echo -e "    → sni-router :$SNI_PORT ${DIM}(SNI 분기, TLS 미복호화)${RESET}"
echo -e "        AI API 도메인 → mitmproxy :4001 ${DIM}(DLP 검사/마스킹)${RESET}"
echo -e "        기타 트래픽   → 인터넷 직통"
echo ""

if [[ "$DHCP_DONE" == true ]]; then
    echo -e "${BOLD}DHCP 설정:${RESET}"
    echo -e "  클라이언트 재연결 또는 ${CYAN}ipconfig /renew${RESET} (Windows) 후 자동 적용"
    echo ""
fi

echo -e "${BOLD}DLP 프록시 시작:${RESET}"
echo -e "  ${CYAN}bash start_dlp.sh --transparent${RESET}"
echo ""
echo -e "${BOLD}CA 인증서 클라이언트 설치:${RESET}"
if [[ -f "$CERT_PATH" ]]; then
    echo -e "  Linux  : sudo cp $CERT_PATH /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates"
    echo -e "  macOS  : open $CERT_PATH  (키체인에서 '항상 신뢰' 설정)"
    [[ -f "$CERT_P12" ]] && echo -e "  Windows: ${CERT_P12} 더블클릭 → '신뢰할 루트 인증 기관'"
fi
echo ""
echo -e "${BOLD}제거:${RESET}"
echo -e "  sudo bash setup_transparent.sh --remove"
echo ""

# 수동 설정이 필요한 경우 안내
if [[ "$DHCP_DONE" != true ]]; then
    echo -e "${YELLOW}${BOLD}━━ 수동 DHCP 설정 필요 ━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  공유기 관리 페이지 (http://$GATEWAY) 접속"
    echo -e "  DHCP 설정 → 기본 게이트웨이(라우터) → ${BOLD}$MY_IP${RESET} 로 변경"
    echo -e "  변경 후 클라이언트에서: ${CYAN}ipconfig /renew${RESET} (Windows)"
    echo ""
fi
