#!/usr/bin/env bash
# =============================================================================
#  AI DLP Proxy — 통합 데몬 관리 스크립트
#
#  관리 대상 (4개 서비스):
#    engine    - DLP 엔진 서버 (Unix Socket NDJSON)
#    mitm      - mitmproxy 투명 프록시
#    web       - FastAPI 웹 대시보드 백엔드 (포트 8765)
#    frontend  - SvelteKit 개발 서버 (포트 5173)
#
#  사용법:
#    bash dlp-daemon.sh start   [engine|mitm|web|frontend|all]
#    bash dlp-daemon.sh stop    [engine|mitm|web|frontend|all]
#    bash dlp-daemon.sh restart [engine|mitm|web|frontend|all]
#    bash dlp-daemon.sh status
#    bash dlp-daemon.sh logs    [engine|mitm|web|frontend]
# =============================================================================
set -uo pipefail

# ── 경로 ──────────────────────────────────────────────────────────────────────
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$BASE/venv"
LOG_DIR="$BASE/logs"
WEB_DIR="$BASE/web"

# PID 파일
PID_ENGINE="$BASE/logs/engine.pid"
PID_MITM="$BASE/logs/mitm.pid"
PID_WEB="$BASE/logs/web.pid"
PID_FRONTEND="$BASE/logs/frontend.pid"

# Unix 소켓
ENGINE_SOCK="/tmp/dlp-engine.sock"

# ── 색상 ──────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'

info()  { echo -e "${C}[INFO]${N}  $*"; }
ok()    { echo -e "${G}[ OK ]${N}  $*"; }
warn()  { echo -e "${Y}[WARN]${N}  $*"; }
err()   { echo -e "${R}[ERR ]${N}  $*" >&2; }
die()   { err "$*"; exit 1; }

mkdir -p "$LOG_DIR"

# ── PID 파일 헬퍼 ─────────────────────────────────────────────────────────────
pid_read()  { [[ -f "$1" ]] && cat "$1" 2>/dev/null || echo ""; }
pid_alive() { local p; p=$(pid_read "$1"); [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; }

pid_wait_dead() {
  local pid_file="$1" timeout="${2:-5}" i=0
  local p; p=$(pid_read "$pid_file")
  [[ -z "$p" ]] && return 0
  while kill -0 "$p" 2>/dev/null && [[ $i -lt $timeout ]]; do
    sleep 1; i=$((i+1))
  done
  kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
}

# ── 서비스별 start/stop 함수 ──────────────────────────────────────────────────

start_engine() {
  if pid_alive "$PID_ENGINE"; then
    warn "engine 이미 실행 중 (PID $(pid_read "$PID_ENGINE"))"; return 0
  fi
  rm -f "$ENGINE_SOCK"
  info "엔진 서버 시작..."
  source "$VENV/bin/activate"
  nohup env PYTHONPATH="$BASE/src" \
    python "$BASE/scripts/engine_server.py" \
    >> "$LOG_DIR/engine.log" 2>&1 &
  local p=$!
  echo "$p" > "$PID_ENGINE"
  # 소켓 대기 최대 10초
  local i=0
  while [[ ! -S "$ENGINE_SOCK" ]] && [[ $i -lt 20 ]]; do
    sleep 0.5; i=$((i+1))
    if ! kill -0 "$p" 2>/dev/null; then
      err "engine 시작 직후 종료됨. 로그: tail $LOG_DIR/engine.log"; return 1
    fi
  done
  if [[ -S "$ENGINE_SOCK" ]]; then
    ok "engine 시작 (PID $p, $ENGINE_SOCK)"
  else
    warn "소켓 대기 타임아웃 — engine은 계속 실행 중일 수 있음 (PID $p)"
  fi
}

stop_engine() {
  local p; p=$(pid_read "$PID_ENGINE")
  if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
    kill "$p" 2>/dev/null; pid_wait_dead "$PID_ENGINE" 5
    ok "engine 종료 (PID $p)"
  else
    warn "engine 실행 중이 아님"
  fi
  rm -f "$PID_ENGINE" "$ENGINE_SOCK"
  # 혹시 남아있는 동명 프로세스 정리
  pkill -f "engine_server.py" 2>/dev/null || true
}

start_mitm() {
  if pid_alive "$PID_MITM"; then
    warn "mitm 이미 실행 중 (PID $(pid_read "$PID_MITM"))"; return 0
  fi
  local port="${MITM_PORT:-4001}"
  info "mitmproxy 시작 (포트 $port)..."
  source "$VENV/bin/activate"
  nohup env PYTHONPATH="$BASE/src" \
    "$VENV/bin/mitmdump" \
    --listen-host 0.0.0.0 \
    --listen-port "$port" \
    --ssl-insecure \
    -s "$BASE/scripts/inspect_traffic.py" \
    >> "$LOG_DIR/mitm.log" 2>&1 &
  local p=$!
  echo "$p" > "$PID_MITM"
  sleep 1
  if ! kill -0 "$p" 2>/dev/null; then
    err "mitmproxy 시작 실패. 로그: tail $LOG_DIR/mitm.log"; rm -f "$PID_MITM"; return 1
  fi
  ok "mitmproxy 시작 (PID $p, 0.0.0.0:$port)"
}

stop_mitm() {
  local p; p=$(pid_read "$PID_MITM")
  if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
    kill "$p" 2>/dev/null; pid_wait_dead "$PID_MITM" 5
    ok "mitmproxy 종료 (PID $p)"
  else
    warn "mitmproxy 실행 중이 아님"
  fi
  rm -f "$PID_MITM"
  pkill -f "inspect_traffic.py" 2>/dev/null || true
  pkill -f "mitmdump" 2>/dev/null || true
}

start_web() {
  if pid_alive "$PID_WEB"; then
    warn "web backend 이미 실행 중 (PID $(pid_read "$PID_WEB"))"; return 0
  fi
  info "웹 대시보드 백엔드 시작 (포트 8765)..."
  source "$VENV/bin/activate"
  nohup bash -c "cd '$WEB_DIR/backend' && \
    source '$VENV/bin/activate' && \
    uvicorn main:app --host 127.0.0.1 --port 8765" \
    >> "$LOG_DIR/web.log" 2>&1 &
  local p=$!
  echo "$p" > "$PID_WEB"
  sleep 1.5
  if ! kill -0 "$p" 2>/dev/null; then
    err "web backend 시작 실패. 로그: tail $LOG_DIR/web.log"; rm -f "$PID_WEB"; return 1
  fi
  ok "web backend 시작 (PID $p, http://127.0.0.1:8765)"
}

stop_web() {
  local p; p=$(pid_read "$PID_WEB")
  if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
    # uvicorn의 경우 자식 프로세스(워커)까지 정리
    kill -- -"$(ps -o pgid= -p "$p" | tr -d ' ')" 2>/dev/null || kill "$p" 2>/dev/null
    pid_wait_dead "$PID_WEB" 5
    ok "web backend 종료 (PID $p)"
  else
    warn "web backend 실행 중이 아님"
  fi
  rm -f "$PID_WEB"
  pkill -f "uvicorn main:app" 2>/dev/null || true
}

start_frontend() {
  if pid_alive "$PID_FRONTEND"; then
    warn "frontend 이미 실행 중 (PID $(pid_read "$PID_FRONTEND"))"; return 0
  fi
  info "프론트엔드 개발 서버 시작 (포트 5173)..."
  nohup bash -c "cd '$WEB_DIR/frontend' && \
    npm run dev -- --host 0.0.0.0 --port 5173" \
    >> "$LOG_DIR/frontend.log" 2>&1 &
  local p=$!
  echo "$p" > "$PID_FRONTEND"
  sleep 2
  if ! kill -0 "$p" 2>/dev/null; then
    err "frontend 시작 실패. 로그: tail $LOG_DIR/frontend.log"; rm -f "$PID_FRONTEND"; return 1
  fi
  ok "frontend 시작 (PID $p, http://localhost:5173)"
}

stop_frontend() {
  local p; p=$(pid_read "$PID_FRONTEND")
  if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
    kill -- -"$(ps -o pgid= -p "$p" | tr -d ' ')" 2>/dev/null || kill "$p" 2>/dev/null
    pid_wait_dead "$PID_FRONTEND" 5
    ok "frontend 종료 (PID $p)"
  else
    warn "frontend 실행 중이 아님"
  fi
  rm -f "$PID_FRONTEND"
  pkill -f "vite dev" 2>/dev/null || true
}

# ── status 출력 ───────────────────────────────────────────────────────────────
print_status() {
  echo ""
  echo -e "${B}═══ AI DLP Proxy 서비스 상태 ══════════════════════${N}"
  local items=(
    "engine:DLP 엔진 서버  :$PID_ENGINE"
    "mitm  :mitmproxy      :$PID_MITM"
    "web   :웹 백엔드       :$PID_WEB"
    "front :프론트엔드      :$PID_FRONTEND"
  )
  for item in "${items[@]}"; do
    IFS=: read -r name label pid_file <<< "$item"
    local p; p=$(pid_read "$pid_file")
    if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
      local uptime=""
      uptime=$(ps -o etimes= -p "$p" 2>/dev/null | tr -d ' ' || echo "")
      if [[ -n "$uptime" ]]; then
        local h=$((uptime/3600)) m=$(( (uptime%3600)/60 )) s=$((uptime%60))
        uptime=$(printf "%02d:%02d:%02d" "$h" "$m" "$s")
      fi
      echo -e "  ${G}●${N} $label  PID ${B}$p${N}  uptime $uptime"
    else
      echo -e "  ${R}○${N} $label  ${Y}중지됨${N}"
    fi
  done
  echo ""

  # 포트 상태
  echo -e "${B}═══ 포트 ═══════════════════════════════════════════${N}"
  for port in 4001 8765 5173; do
    local proc; proc=$(ss -tlnp 2>/dev/null | grep ":$port " | awk -F'"' '{print $2}' | head -1)
    if [[ -n "$proc" ]]; then
      echo -e "  ${G}●${N} :$port  ($proc)"
    else
      echo -e "  ${R}○${N} :$port  미사용"
    fi
  done
  echo ""
}

# ── 명령 분기 ────────────────────────────────────────────────────────────────
CMD="${1:-status}"
TARGET="${2:-all}"

do_start() {
  case "$1" in
    engine)   start_engine ;;
    mitm)     start_mitm ;;
    web)      start_web ;;
    frontend) start_frontend ;;
    all)
      start_engine
      start_mitm
      start_web
      start_frontend
      print_status
      ;;
    *) die "알 수 없는 서비스: $1 (engine|mitm|web|frontend|all)" ;;
  esac
}

do_stop() {
  case "$1" in
    engine)   stop_engine ;;
    mitm)     stop_mitm ;;
    web)      stop_web ;;
    frontend) stop_frontend ;;
    all)
      stop_frontend
      stop_web
      stop_mitm
      stop_engine
      ok "모든 서비스 종료 완료"
      ;;
    *) die "알 수 없는 서비스: $1" ;;
  esac
}

do_logs() {
  local f=""
  case "${1:-all}" in
    engine)   f="$LOG_DIR/engine.log" ;;
    mitm)     f="$LOG_DIR/mitm.log" ;;
    web)      f="$LOG_DIR/web.log" ;;
    frontend) f="$LOG_DIR/frontend.log" ;;
    *) # 전체: 멀티tail
      tail -f "$LOG_DIR/engine.log" "$LOG_DIR/mitm.log" "$LOG_DIR/web.log" "$LOG_DIR/frontend.log" 2>/dev/null
      return
      ;;
  esac
  [[ -f "$f" ]] && tail -f "$f" || die "로그 파일 없음: $f"
}

case "$CMD" in
  start)   do_start "$TARGET" ;;
  stop)    do_stop  "$TARGET" ;;
  restart)
    do_stop  "$TARGET"
    sleep 1
    do_start "$TARGET"
    ;;
  status)  print_status ;;
  logs)    do_logs "${2:-all}" ;;
  *)
    echo "사용법: $0 {start|stop|restart|status|logs} [engine|mitm|web|frontend|all]"
    exit 1
    ;;
esac
