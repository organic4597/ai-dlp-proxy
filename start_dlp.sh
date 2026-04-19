#!/usr/bin/env bash
# =============================================================================
#  AI DLP Proxy — 원클릭 시작 스크립트
#
#  실행 순서:
#    1. venv 활성화
#    2. DLP 엔진 서버 (백그라운드)
#    3. mitmproxy 프록시 (백그라운드)
#    4. TUI 대시보드 (포그라운드)
#    5. TUI 종료 시 엔진·프록시 자동 정리
#
#  사용법:
#    bash start_dlp.sh                  # 기본 실행 (명시적 프록시)
#    bash start_dlp.sh --transparent    # 투명 프록시 모드 (iptables + SNI 라우터)
#    bash start_dlp.sh --no-tui         # TUI 없이 서비스만 실행 (서버 모드)
#    bash start_dlp.sh --port 4001      # mitmproxy 포트 변경
#    bash start_dlp.sh --stop           # 실행 중인 프로세스 종료
# =============================================================================
set -euo pipefail

# ── 색상 ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── 경로 설정 ─────────────────────────────────────────────────────────────────
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$BASE_DIR/venv"
LOG_DIR="$BASE_DIR/logs"
ENGINE_SOCK="/tmp/dlp-engine.sock"
ENGINE_PID_FILE="/tmp/dlp-engine.pid"
MITM_PID_FILE="/tmp/dlp-mitm.pid"
SNI_PID_FILE="/tmp/dlp-sni.pid"
SNI_BINARY="$BASE_DIR/sni-router/target/release/sni-router"

# ── 인수 파싱 ─────────────────────────────────────────────────────────────────
OPT_NO_TUI=false
OPT_STOP=false
OPT_SNI=false
OPT_TRANSPARENT=false
MITM_PORT=4001
SNI_PORT=4443

for arg in "$@"; do
    case "$arg" in
        --no-tui)       OPT_NO_TUI=true ;;
        --stop)         OPT_STOP=true ;;
        --sni)          OPT_SNI=true ;;
        --transparent)  OPT_TRANSPARENT=true; OPT_SNI=true ;;  # iptables+SNI 풀세트
        --port)         shift; MITM_PORT="$1" ;;
        --port=*)       MITM_PORT="${arg#--port=}" ;;
        --sni-port=*)   SNI_PORT="${arg#--sni-port=}" ;;
        --help|-h)
            grep '^#  ' "$0" | sed 's/^#  //'
            exit 0 ;;
    esac
done

# =============================================================================
# --stop: 실행 중인 프로세스 종료
# =============================================================================
stop_all() {
    info "DLP 프록시 프로세스 종료 중..."
    local stopped=0

    if [[ -f "$SNI_PID_FILE" ]]; then
        local pid; pid=$(cat "$SNI_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "sni-router 종료 (PID $pid)"
            stopped=$((stopped+1))
        fi
        rm -f "$SNI_PID_FILE"
    fi

    if [[ -f "$MITM_PID_FILE" ]]; then
        local pid; pid=$(cat "$MITM_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "mitmproxy 종료 (PID $pid)"
            stopped=$((stopped+1))
        fi
        rm -f "$MITM_PID_FILE"
    fi

    if [[ -f "$ENGINE_PID_FILE" ]]; then
        local pid; pid=$(cat "$ENGINE_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "엔진 서버 종료 (PID $pid)"
            stopped=$((stopped+1))
        fi
        rm -f "$ENGINE_PID_FILE"
    fi

    # 소켓 파일 정리
    rm -f "$ENGINE_SOCK"

    # PID 파일 없이 프로세스명으로 추가 정리
    pkill -f "sni-router" 2>/dev/null && stopped=$((stopped+1)) || true
    pkill -f "engine_server.py" 2>/dev/null && stopped=$((stopped+1)) || true
    pkill -f "inspect_traffic.py" 2>/dev/null && stopped=$((stopped+1)) || true

    # --transparent 모드였다면 iptables + dnsmasq 제거
    if [[ -f "/etc/dnsmasq.d/dlp-transparent.conf" ]]; then
        if command -v sudo &>/dev/null && [[ $EUID -ne 0 ]]; then
            sudo bash "$BASE_DIR/setup_transparent.sh" --remove 2>/dev/null || true
        elif [[ $EUID -eq 0 ]]; then
            bash "$BASE_DIR/setup_transparent.sh" --remove 2>/dev/null || true
        fi
    fi

    if [[ $stopped -eq 0 ]]; then
        warn "실행 중인 DLP 프로세스를 찾지 못했습니다"
    else
        ok "종료 완료"
    fi
    exit 0
}

if [[ "$OPT_STOP" == true ]]; then
    stop_all
fi

# =============================================================================
# 종료 시 자동 정리 (TUI Ctrl+C, 스크립트 exit 등)
# =============================================================================
cleanup() {
    echo ""
    info "종료 신호 수신 — 프로세스 정리 중..."

    if [[ -f "$SNI_PID_FILE" ]]; then
        local pid; pid=$(cat "$SNI_PID_FILE" 2>/dev/null || echo "")
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && info "  sni-router 종료 (PID $pid)"
        rm -f "$SNI_PID_FILE"
    fi

    if [[ -f "$MITM_PID_FILE" ]]; then
        local pid; pid=$(cat "$MITM_PID_FILE" 2>/dev/null || echo "")
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && info "  mitmproxy 종료 (PID $pid)"
        rm -f "$MITM_PID_FILE"
    fi

    if [[ -f "$ENGINE_PID_FILE" ]]; then
        local pid; pid=$(cat "$ENGINE_PID_FILE" 2>/dev/null || echo "")
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && info "  엔진 서버 종료 (PID $pid)"
        rm -f "$ENGINE_PID_FILE"
    fi

    rm -f "$ENGINE_SOCK"
    ok "정리 완료. 안녕히 가세요!"
}
trap cleanup EXIT INT TERM

# =============================================================================
# 1. 사전 확인
# =============================================================================
echo -e "\n${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        AI DLP Proxy  시작 중...              ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}\n"

# venv 확인
if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
    error "venv가 없습니다. 먼저 설치를 실행하세요:\n  bash install.sh"
fi

# 이미 실행 중인지 확인
if [[ -f "$ENGINE_PID_FILE" ]]; then
    old_pid=$(cat "$ENGINE_PID_FILE" 2>/dev/null || echo "")
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
        warn "이미 엔진 서버가 실행 중입니다 (PID $old_pid)"
        warn "재시작하려면:  bash start_dlp.sh --stop && bash start_dlp.sh"
        exit 1
    fi
fi

# 로그 디렉터리
mkdir -p "$LOG_DIR"

# =============================================================================
# 2. venv 활성화
# =============================================================================
info "가상환경 활성화: $VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Python: $(python --version)"

# =============================================================================
# 3. DLP 엔진 서버 시작
# =============================================================================
info "DLP 엔진 서버 시작..."

# 이전 소켓 파일 정리
rm -f "$ENGINE_SOCK"

PYTHONPATH="$BASE_DIR/src" \
    python "$BASE_DIR/scripts/engine_server.py" \
    >> "$LOG_DIR/engine.log" 2>&1 &
ENGINE_PID=$!
echo "$ENGINE_PID" > "$ENGINE_PID_FILE"
ok "엔진 서버 시작 (PID $ENGINE_PID)"
info "  로그: $LOG_DIR/engine.log"

# 소켓 생성 대기 (최대 10초)
info "엔진 소켓 대기 중..."
for i in $(seq 1 20); do
    if [[ -S "$ENGINE_SOCK" ]]; then
        ok "엔진 소켓 준비 완료: $ENGINE_SOCK"
        break
    fi
    # 프로세스가 죽었는지 체크
    if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
        error "엔진 서버가 시작 직후 종료되었습니다.\n  로그 확인: tail -50 $LOG_DIR/engine.log"
    fi
    sleep 0.5
    if [[ $i -eq 20 ]]; then
        warn "소켓 대기 타임아웃 — TCP 모드로 계속 진행합니다"
    fi
done

# =============================================================================
# 3-a. 투명 프록시 모드: iptables + DHCP 자동 설정 (--transparent)
# =============================================================================
if [[ "$OPT_TRANSPARENT" == true ]]; then
    SETUP_SCRIPT="$BASE_DIR/setup_transparent.sh"
    if [[ ! -f "$SETUP_SCRIPT" ]]; then
        error "setup_transparent.sh 없음: $SETUP_SCRIPT"
    fi
    info "투명 프록시 설정 실행 (sudo 필요)..."
    if [[ $EUID -eq 0 ]]; then
        bash "$SETUP_SCRIPT"
    elif command -v sudo &>/dev/null; then
        sudo bash "$SETUP_SCRIPT"
    else
        error "iptables 설정에 root 권한 필요. sudo가 없습니다."
    fi
fi

# =============================================================================
# 3-b. SNI 라우터 시작 (--sni / --transparent 옵션 시)
# =============================================================================
if [[ "$OPT_SNI" == true ]]; then
    if [[ ! -x "$SNI_BINARY" ]]; then
        warn "sni-router 바이너리 없음 — 빌드 중..."
        (cd "$BASE_DIR/sni-router" && cargo build --release 2>&1) \
            || error "sni-router 빌드 실패. Rust(cargo)가 설치되어 있는지 확인하세요"
    fi
    info "SNI 라우터 시작 (포트 $SNI_PORT → mitmproxy $MITM_PORT)..."
    "$SNI_BINARY" >> "$LOG_DIR/sni.log" 2>&1 &
    SNI_PID=$!
    echo "$SNI_PID" > "$SNI_PID_FILE"
    sleep 0.3
    if ! kill -0 "$SNI_PID" 2>/dev/null; then
        error "sni-router가 시작 직후 종료되었습니다.\n  로그 확인: tail -20 $LOG_DIR/sni.log"
    fi
    ok "sni-router 시작 (PID $SNI_PID, 포트 $SNI_PORT)"
    info "  로그: $LOG_DIR/sni.log"
fi

# =============================================================================
# 4. mitmproxy 시작
# =============================================================================
info "mitmproxy 시작 (포트 $MITM_PORT)..."

PYTHONPATH="$BASE_DIR/src" \
    "$VENV_DIR/bin/mitmdump" \
    --listen-host 0.0.0.0 \
    --listen-port "$MITM_PORT" \
    --ssl-insecure \
    -s "$BASE_DIR/scripts/inspect_traffic.py" \
    >> "$LOG_DIR/mitm.log" 2>&1 &
MITM_PID=$!
echo "$MITM_PID" > "$MITM_PID_FILE"
ok "mitmproxy 시작 (PID $MITM_PID, 포트 $MITM_PORT)"
info "  로그: $LOG_DIR/mitm.log"

# mitmproxy 바인딩 대기 (최대 5초)
sleep 1
if ! kill -0 "$MITM_PID" 2>/dev/null; then
    error "mitmproxy가 시작 직후 종료되었습니다.\n  로그 확인: tail -50 $LOG_DIR/mitm.log"
fi

# =============================================================================
# 5. 상태 출력
# =============================================================================
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}${BOLD}── 실행 중 ─────────────────────────────────────${RESET}"
echo -e "  엔진 서버   PID ${ENGINE_PID}  (UDS $ENGINE_SOCK)"
echo -e "  mitmproxy   PID ${MITM_PID}   (0.0.0.0:$MITM_PORT)"
if [[ "$OPT_SNI" == true ]]; then
    echo -e "  sni-router  PID ${SNI_PID:-N/A}   (0.0.0.0:$SNI_PORT)"
fi
echo ""
echo -e "${BOLD}── 클라이언트 프록시 설정 ──────────────────────${RESET}"
if [[ "$OPT_SNI" == true ]]; then
    echo -e "  투명 프록시 (iptables 필요):  setup_iptables.sh 실행"
else
    echo -e "  HTTP/HTTPS:  ${SERVER_IP}:${MITM_PORT}"
fi
echo ""
echo -e "${BOLD}── 로그 실시간 확인 ────────────────────────────${RESET}"
echo -e "  tail -f $LOG_DIR/engine.log"
echo -e "  tail -f $LOG_DIR/mitm.log"
echo ""

# =============================================================================
# 6. TUI 실행 (포그라운드)
# =============================================================================
if [[ "$OPT_NO_TUI" == true ]]; then
    info "--no-tui 모드 — TUI 없이 서비스 실행 중"
    info "종료하려면: bash start_dlp.sh --stop"
    # 포그라운드 유지 (Ctrl+C 대기)
    wait "$ENGINE_PID"
else
    info "TUI 대시보드 시작..."
    echo -e "${YELLOW}  종료: Ctrl+C 또는 TUI 내 q키${RESET}\n"

    PYTHONPATH="$BASE_DIR/src" \
        python "$BASE_DIR/scripts/tui.py" || true
    # TUI 정상/비정상 종료 모두 cleanup 트리거
fi
