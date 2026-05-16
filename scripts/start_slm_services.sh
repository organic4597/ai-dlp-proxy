#!/usr/bin/env bash
# =============================================================================
#  start_slm_services.sh — 학습 서버(WSL2/GPU)에서 실행
#
#  역할:
#    1. SLM API 서버 기동 (slm_api_server.py, FastAPI + uvicorn)
#    2. 모델 로딩 대기 (GET /health 폴링, 최대 90초)
#    3. SSH 역방향 터널 기동 (WSL2 → 라즈베리파이 localhost:8765)
#
#  사용법:
#    # 기본 (환경변수로 설정)
#    SLM_PI_HOST=192.168.1.16 SLM_PI_USER=root bash start_slm_services.sh
#
#    # 중지
#    bash start_slm_services.sh stop
#
#  환경변수 (모두 선택 사항, 기본값 있음):
#    SLM_MODEL_PATH   모델 디렉터리 (기본: output/merged_v5)
#    SLM_PORT         API 서버 포트 (기본: 8765)
#    SLM_DEVICE       cuda / cpu (기본: cuda)
#    SLM_DTYPE        fp16 / bf16 / int4 (기본: fp16)
#    SLM_PI_HOST      라즈베리파이 IP (기본: 192.168.1.16)
#    SLM_PI_USER      라즈베리파이 SSH 사용자 (기본: root)
#    SLM_PI_SSH_PORT  라즈베리파이 SSH 포트 (기본: 22)
#    SSHPASS          SSH 비밀번호 (sshpass 사용 시)
# =============================================================================
set -uo pipefail

# ── 설정 ─────────────────────────────────────────────────────────────────────
SLM_MODEL_PATH="${SLM_MODEL_PATH:-output/merged_v5}"
SLM_PORT="${SLM_PORT:-8766}"
SLM_DEVICE="${SLM_DEVICE:-cuda}"
SLM_DTYPE="${SLM_DTYPE:-fp16}"
SLM_PI_HOST="${SLM_PI_HOST:-192.168.1.16}"
SLM_PI_USER="${SLM_PI_USER:-root}"
SLM_PI_SSH_PORT="${SLM_PI_SSH_PORT:-22}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
mkdir -p "$LOG_DIR"

API_LOG="$LOG_DIR/slm_api.log"
TUNNEL_LOG="$LOG_DIR/slm_tunnel.log"
API_PID_FILE="/tmp/slm_api.pid"
TUNNEL_PID_FILE="/tmp/slm_tunnel.pid"

# ── 색상 ─────────────────────────────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; N='\033[0m'
ok()   { echo -e "${G}[ OK ]${N}  $*"; }
info() { echo -e "${C}[INFO]${N}  $*"; }
warn() { echo -e "${Y}[WARN]${N}  $*"; }
err()  { echo -e "${R}[ERR ]${N}  $*" >&2; }

# ── 헬퍼 ────────────────────────────────────────────────────────────────────
pid_alive() {
    local f="$1"
    [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null
}

stop_pid_file() {
    local name="$1" f="$2"
    if pid_alive "$f"; then
        local pid; pid=$(cat "$f")
        kill "$pid" 2>/dev/null && ok "$name 종료 (PID $pid)" || warn "$name 종료 실패"
        # 최대 5초 대기
        local i=0
        while kill -0 "$pid" 2>/dev/null && [[ $i -lt 10 ]]; do
            sleep 0.5; i=$((i+1))
        done
        kill -9 "$pid" 2>/dev/null || true
    else
        warn "$name 실행 중이 아님"
    fi
    rm -f "$f"
}

# ── stop 명령 ─────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "stop" ]]; then
    info "SLM 서비스 중지..."
    stop_pid_file "SSH 터널" "$TUNNEL_PID_FILE"
    stop_pid_file "SLM API 서버" "$API_PID_FILE"
    ok "완료"
    exit 0
fi

# ── status 명령 ──────────────────────────────────────────────────────────────
if [[ "${1:-}" == "status" ]]; then
    echo ""
    echo "  SLM 서비스 상태"
    echo "  ──────────────────────────────"
    if pid_alive "$API_PID_FILE"; then
        echo -e "  ${G}●${N} SLM API 서버  PID $(cat "$API_PID_FILE")  http://localhost:${SLM_PORT}"
    else
        echo -e "  ${R}○${N} SLM API 서버  중지됨"
    fi
    if pid_alive "$TUNNEL_PID_FILE"; then
        echo -e "  ${G}●${N} SSH 터널      PID $(cat "$TUNNEL_PID_FILE")  → ${SLM_PI_USER}@${SLM_PI_HOST}"
    else
        echo -e "  ${R}○${N} SSH 터널      중지됨"
    fi
    # 헬스 체크
    if curl -sf "http://localhost:${SLM_PORT}/health" >/dev/null 2>&1; then
        echo -e "  ${G}✓${N} /health OK"
    else
        echo -e "  ${R}✗${N} /health 응답 없음"
    fi
    echo ""
    exit 0
fi

# ── 1. SLM API 서버 기동 ─────────────────────────────────────────────────────
if pid_alive "$API_PID_FILE"; then
    warn "SLM API 서버 이미 실행 중 (PID $(cat "$API_PID_FILE")) — skip"
else
    info "SLM API 서버 시작 (model=$SLM_MODEL_PATH, device=$SLM_DEVICE, dtype=$SLM_DTYPE)..."
    CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}" \
    nohup python3 "$SCRIPT_DIR/slm_api_server.py" \
        --model "$SLM_MODEL_PATH" \
        --port  "$SLM_PORT" \
        --device "$SLM_DEVICE" \
        --dtype  "$SLM_DTYPE" \
        >> "$API_LOG" 2>&1 &
    echo $! > "$API_PID_FILE"
    ok "SLM API 서버 기동 (PID $!, 로그: $API_LOG)"
fi

# ── 2. 모델 로딩 대기 (최대 90초, /health 폴링) ───────────────────────────────
info "모델 로딩 대기 중 (최대 90초)..."
READY=false
for i in $(seq 1 90); do
    if ! pid_alive "$API_PID_FILE"; then
        err "SLM API 서버가 시작 중 종료됨. 로그 확인: tail $API_LOG"
        exit 1
    fi
    STATUS=$(curl -sf "http://localhost:${SLM_PORT}/health" 2>/dev/null || true)
    if echo "$STATUS" | grep -q '"status":"ok"'; then
        READY=true
        break
    fi
    # "loading" 상태면 계속 대기
    printf "."
    sleep 1
done
echo ""
if [[ "$READY" == "true" ]]; then
    ok "모델 로드 완료 — http://localhost:${SLM_PORT}/health"
else
    err "모델 로딩 타임아웃 (90초 초과). 서버 로그 확인: tail -f $API_LOG"
    exit 1
fi

# ── 3. SSH 역방향 터널 기동 ──────────────────────────────────────────────────
# -R {PI_PORT}:localhost:{SLM_PORT} 으로 라즈베리파이 localhost:{PI_PORT}를
# 이쪽(WSL2) localhost:{SLM_PORT}로 포워딩
PI_TUNNEL_PORT="${SLM_PORT}"  # 라즈베리파이에서도 같은 포트 번호 사용

if pid_alive "$TUNNEL_PID_FILE"; then
    warn "SSH 터널 이미 실행 중 (PID $(cat "$TUNNEL_PID_FILE")) — skip"
else
    info "SSH 역방향 터널 시작 (→ ${SLM_PI_USER}@${SLM_PI_HOST}:${SLM_PI_SSH_PORT})..."

    SSH_OPTS=(
        -o StrictHostKeyChecking=no
        -o ServerAliveInterval=30
        -o ServerAliveCountMax=5
        -o ExitOnForwardFailure=yes
        -o BatchMode=no
        -p "$SLM_PI_SSH_PORT"
        -N
        -R "${PI_TUNNEL_PORT}:localhost:${SLM_PORT}"
        "${SLM_PI_USER}@${SLM_PI_HOST}"
    )

    if [[ -n "${SSHPASS:-}" ]]; then
        # sshpass 사용 (비밀번호 환경변수)
        nohup sshpass -e ssh "${SSH_OPTS[@]}" >> "$TUNNEL_LOG" 2>&1 &
    else
        # SSH 키 인증 (권장)
        nohup ssh "${SSH_OPTS[@]}" >> "$TUNNEL_LOG" 2>&1 &
    fi
    echo $! > "$TUNNEL_PID_FILE"
    sleep 2  # 터널 연결 수립 대기

    if pid_alive "$TUNNEL_PID_FILE"; then
        ok "SSH 터널 수립됨 (PID $(cat "$TUNNEL_PID_FILE"))"
        ok "라즈베리파이에서: curl http://localhost:${PI_TUNNEL_PORT}/health"
    else
        err "SSH 터널 수립 실패. 로그 확인: cat $TUNNEL_LOG"
        err "SSH 키 설정 또는 SSHPASS 환경변수를 확인하세요."
        exit 1
    fi
fi

echo ""
ok "=== SLM 서비스 준비 완료 ==="
echo "  API 서버  : http://localhost:${SLM_PORT}"
echo "  터널 대상 : ${SLM_PI_USER}@${SLM_PI_HOST} (포트 ${PI_TUNNEL_PORT})"
echo ""
echo "  중지: bash $0 stop"
echo "  상태: bash $0 status"
echo "  로그: tail -f $API_LOG"
