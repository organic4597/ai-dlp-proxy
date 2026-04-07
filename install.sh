#!/usr/bin/env bash
# =============================================================================
#  AI DLP Proxy — Rocky Linux 원클릭 설치 스크립트
#  지원: Rocky Linux 8 / 9, RHEL 8/9 호환
#
#  사용법:
#    bash install.sh              # 기본 설치 (환경 자동 감지)
#    bash install.sh --gpu        # NVIDIA GPU 강제 활성화
#    bash install.sh --no-model   # 모델 다운로드 건너뜀 (수동 배치 예정)
#    bash install.sh --no-systemd # systemd 서비스 등록 건너뜀
#
#  VMware / VirtualBox 가상 머신 환경 자동 감지:
#    - GPU passthrough 불가 → CPU 전용 모드 자동 설정 (확인 프롬프트 없음)
#    - Apple Silicon MacBook + VMware Fusion → aarch64 Rocky Linux 지원
# =============================================================================
set -euo pipefail

# ── 색상 ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }

# ── 인수 파싱 ─────────────────────────────────────────────────────────────────
OPT_GPU=false
OPT_NO_MODEL=false
OPT_NO_SYSTEMD=false
for arg in "$@"; do
    case "$arg" in
        --gpu)        OPT_GPU=true ;;
        --no-model)   OPT_NO_MODEL=true ;;
        --no-systemd) OPT_NO_SYSTEMD=true ;;
        --help|-h)
            grep '^#  ' "$0" | sed 's/^#  //'
            exit 0 ;;
        *) warn "알 수 없는 옵션: $arg (무시)" ;;
    esac
done

# ── 아키텍처 및 VM 환경 감지 (인수 파싱 직후 바로 확인) ─────────────────────
ARCH=$(uname -m)   # x86_64 | aarch64 | arm64

# systemd-detect-virt: none / vmware / kvm / virtualbox / docker ...
VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
IS_VM=false
VM_VENDOR=""
case "$VIRT_TYPE" in
    vmware|kvm|virtualbox|hyperv|xen|parallels|qemu)
        IS_VM=true
        VM_VENDOR="$VIRT_TYPE"
        ;;
esac
# DMI 폴백 (systemd-detect-virt 없는 최소 설치 환경)
if [[ "$IS_VM" == false ]] && [[ -r /sys/class/dmi/id/sys_vendor ]]; then
    DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "")
    case "${DMI_VENDOR,,}" in
        *vmware*) IS_VM=true; VM_VENDOR="vmware" ;;
        *virtualbox*|*innotek*) IS_VM=true; VM_VENDOR="virtualbox" ;;
        *parallels*) IS_VM=true; VM_VENDOR="parallels" ;;
        *microsoft*) IS_VM=true; VM_VENDOR="hyperv" ;;
    esac
fi

# ── 설치 경로 ─────────────────────────────────────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$INSTALL_DIR/venv"
MODEL_DIR="$INSTALL_DIR/models"
CONFIG_DIR="$HOME/.config/ai-dlp-proxy"
MODEL_FILENAME="gemma-4-2b-it-q4_k_m.gguf"
MODEL_PATH="$MODEL_DIR/$MODEL_FILENAME"
# HuggingFace repo — bartowski GGUF 커뮤니티 (대소문자 fallback 포함)
# bartowski 규칙: Q4_K_M (대문자) 사용
HF_REPO="bartowski/gemma-4-2b-it-GGUF"
HF_FILES=("gemma-4-2b-it-Q4_K_M.gguf" "gemma-4-2b-it-q4_k_m.gguf")
# Gemma 4는 Google gated repo → HF 토큰 필요
# 대체 repo (토큰 불필요 미러)
HF_REPO_ALT="unsloth/gemma-4-2b-it-GGUF"

# ── 서비스 실행 사용자 ────────────────────────────────────────────────────────
RUN_USER="${SUDO_USER:-$USER}"
RUN_HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)

# =============================================================================
step "1/8  환경 확인 (OS / 아키텍처 / VM)"
# =============================================================================

if [[ ! -f /etc/os-release ]]; then
    error "/etc/os-release 없음 — Rocky Linux / RHEL 계열이 아닌 환경입니다"
fi

source /etc/os-release
OS_ID="${ID:-unknown}"
OS_VER="${VERSION_ID%%.*}"   # "8.9" → "8"

case "$OS_ID" in
    rocky|rhel|almalinux|ol)
        ok "OS: $PRETTY_NAME (지원)"
        ;;
    centos)
        if [[ "$OS_VER" -lt 8 ]]; then
            error "CentOS 7 이하는 미지원. Rocky Linux 8/9 권장"
        fi
        warn "CentOS Stream 감지 — 동작은 하지만 Rocky Linux 권장"
        ;;
    *)
        warn "미검증 OS: $OS_ID. 계속 진행합니다 (오류 발생 시 Rocky Linux 사용)"
        ;;
esac

if [[ "$OS_VER" -lt 8 ]]; then
    error "Rocky Linux / RHEL 8+ 이상 필요 (현재: $VERSION_ID)"
fi

# 아키텍처 출력
case "$ARCH" in
    x86_64)  ok "아키텍처: x86_64" ;;
    aarch64) ok "아키텍처: aarch64 (ARM64) — Apple Silicon VMware Fusion 또는 ARM 서버" ;;
    *)       warn "미검증 아키텍처: $ARCH" ;;
esac

# VM 환경 출력
if [[ "$IS_VM" == true ]]; then
    ok "가상 머신 감지: ${VM_VENDOR} (GPU passthrough 불가 → CPU 전용 자동 설정)"
    [[ "$VM_VENDOR" == "vmware" && "$ARCH" == "aarch64" ]] && \
        info "  Apple Silicon MacBook + VMware Fusion 환경으로 판단됩니다"
else
    ok "베어메탈(물리 호스트) 환경"
fi

# =============================================================================
step "2/8  시스템 패키지 설치 (dnf)"
# =============================================================================

if [[ "$EUID" -ne 0 ]]; then
    warn "root 권한 없음 — sudo 없이 dnf를 실행합니다 (실패 시 sudo 권한 필요)"
    DNF="sudo dnf"
else
    DNF="dnf"
fi

info "EPEL 및 개발 도구 활성화..."
$DNF install -y epel-release 2>/dev/null || true
$DNF config-manager --set-enabled crb 2>/dev/null \
    || $DNF config-manager --set-enabled powertools 2>/dev/null \
    || true   # Rocky 8: powertools, Rocky 9: crb

# VMware Tools 설치 (VMware VM일 때만)
if [[ "$IS_VM" == true && "$VM_VENDOR" == "vmware" ]]; then
    info "VMware 환경 → open-vm-tools 설치..."
    $DNF install -y open-vm-tools 2>/dev/null || true
fi

# cmake 패키지명: Rocky 8 x86_64는 cmake3, aarch64/Rocky 9는 cmake
CMAKE_PKG="cmake"
if [[ "$OS_VER" == "8" && "$ARCH" == "x86_64" ]]; then
    CMAKE_PKG="cmake3"
fi

info "필수 패키지 설치..."
# Rocky 8에서 Python 3.11은 AppStream 모듈로 활성화 필요 (Rocky 9는 불필요)
if [[ "$OS_VER" == "8" ]]; then
    $DNF module enable -y python311 2>/dev/null || true
fi

# Rocky 9.x: python3.11-pip은 별도 패키지 없음 → python3.11만 설치 후 ensurepip 사용
# Rocky 8.x: python3.11-pip 패키지 존재
if [[ "$OS_VER" == "9" ]]; then
    $DNF install -y \
        python3.11 python3.11-devel \
        gcc gcc-c++ "$CMAKE_PKG" make \
        openssl openssl-devel \
        git wget curl \
        bzip2-devel libffi-devel zlib-devel \
        ca-certificates \
        2>/dev/null || {
            $DNF install -y python3.12 python3.12-devel 2>/dev/null || \
            $DNF install -y python3 python3-devel || true
        }
else
    $DNF install -y \
        python3.11 python3.11-devel python3.11-pip \
        gcc gcc-c++ "$CMAKE_PKG" make \
        openssl openssl-devel \
        git wget curl \
        bzip2-devel libffi-devel zlib-devel \
        ca-certificates \
        2>/dev/null || {
            $DNF install -y python3.12 python3.12-devel python3.12-pip 2>/dev/null || \
            $DNF install -y python3 python3-devel python3-pip || true
        }
fi

ok "시스템 패키지 설치 완료"

# ── Python 실행 파일 결정 ─────────────────────────────────────────────────────
PYTHON=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
        # (3, 11) 이상인지 확인
        if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

[[ -z "$PYTHON" ]] && error "Python 3.11+ 을 찾지 못했습니다. 수동 설치 후 재실행하세요"
ok "Python: $($PYTHON --version)"

# =============================================================================
step "3/8  GPU 환경 감지"
# =============================================================================

COMPUTE_MODE="cpu"

if [[ "$OPT_GPU" == true ]]; then
    COMPUTE_MODE="cuda"
    info "--gpu 플래그 → CUDA 강제 활성"
elif [[ "$IS_VM" == true ]]; then
    # 가상 머신: GPU passthrough 일반적으로 불가 → 자동 CPU 모드 (프롬프트 없음)
    COMPUTE_MODE="cpu"
    info "VM 환경 → GPU passthrough 미지원 → CPU 전용 자동 설정"
elif command -v nvidia-smi &>/dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | head -1)
    if [[ -n "$GPU_INFO" ]]; then
        COMPUTE_MODE="cuda"
        ok "NVIDIA GPU 감지: $GPU_INFO"
    fi
fi

if [[ "$COMPUTE_MODE" == "cpu" ]]; then
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│  ⚠  경고: CPU 전용 모드                                     │${RESET}"
    echo -e "${YELLOW}│                                                             │${RESET}"
    if [[ "$IS_VM" == true ]]; then
    echo -e "${YELLOW}│  원인: 가상 머신(${VM_VENDOR}) — GPU passthrough 불가        │${RESET}"
    else
    echo -e "${YELLOW}│  원인: NVIDIA GPU 미감지                                    │${RESET}"
    echo -e "${YELLOW}│  NVIDIA GPU 환경이라면:  bash install.sh --gpu               │${RESET}"
    fi
    echo -e "${YELLOW}│  SLM(Gemma 4 2B) 추론 시 요청당 3~10초 소요 예상           │${RESET}"
    echo -e "${YELLOW}│  SLM 없이 Regex만 사용:  TUI → 제어탭 → SLM Stage OFF      │${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    # VM 환경은 확인 불필요 (이미 알고 있는 제약), 베어메탈만 확인 프롬프트
    if [[ "$IS_VM" == false ]]; then
        read -rp "계속 진행하시겠습니까? [Y/n] " confirm
        confirm="${confirm:-Y}"
        [[ "${confirm,,}" != "y" ]] && { info "설치 취소"; exit 0; }
    fi
fi

# =============================================================================
step "4/8  Python 가상환경 구성"
# =============================================================================

if [[ -d "$VENV_DIR" ]]; then
    warn "기존 venv 발견 ($VENV_DIR) — 재사용합니다"
    warn "깨끗하게 재설치하려면:  rm -rf venv && bash install.sh"
else
    info "가상환경 생성: $VENV_DIR"
    # Rocky 9: pip이 번들에 없는 경우 ensurepip으로 부트스트랩
    "$PYTHON" -m ensurepip --upgrade 2>/dev/null || true
    "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade "pip>=24" "setuptools>=69" wheel -q
ok "가상환경 활성화: $VENV_DIR"

# =============================================================================
step "5/8  Python 패키지 설치"
# =============================================================================

# ── llama-cpp-python: GPU 여부에 따라 빌드 플래그 다름 ──────────────────────
info "llama-cpp-python 설치 중 (시간이 걸릴 수 있습니다)..."

if [[ "$COMPUTE_MODE" == "cuda" ]]; then
    info "  모드: CUDA GPU 빌드"
    CMAKE_ARGS="-DGGML_CUDA=on" \
    FORCE_CMAKE=1 \
        pip install llama-cpp-python --no-binary llama-cpp-python -q \
        || {
            warn "CUDA 빌드 실패 → CPU 빌드로 폴백"
            pip install llama-cpp-python -q
        }
elif [[ "$ARCH" == "aarch64" ]]; then
    info "  모드: CPU 빌드 (aarch64/ARM64)"
    # aarch64에서 llamafile 모듈이 빌드 오류를 낼 수 있어 비활성화
    CMAKE_ARGS="-DGGML_LLAMAFILE=OFF" \
    FORCE_CMAKE=1 \
        pip install llama-cpp-python --no-binary llama-cpp-python -q \
        || {
            warn "aarch64 네이티브 빌드 실패 → 바이너리 wheel 폴백"
            pip install llama-cpp-python -q
        }
else
    info "  모드: CPU 빌드 (x86_64)"
    pip install llama-cpp-python -q
fi

# ── 나머지 패키지 ────────────────────────────────────────────────────────────
info "프로젝트 의존성 설치 중..."

# mitmproxy: PyPI 최신 버전 자동으로 탐지
# --prefer-binary: 소스 빌드 없이 wheel 우선 (aarch64 등 플랫폼 호환성 보장)
# h11: mitmproxy 11.x 가 h11<=0.14.0 요구 → 함께 고정
install_mitmproxy() {
    local spec="$1"
    info "  mitmproxy ${spec} 시도..."
    pip install --prefer-binary "$spec" "h11>=0.11,<=0.14.0" -q 2>/dev/null && return 0
    return 1
}

# 12 → 11 → 10 순서로 fallback
if   install_mitmproxy "mitmproxy>=12.0"; then
    ok "  mitmproxy >=12.0 설치 완료"
elif install_mitmproxy "mitmproxy>=11.0,<12.0"; then
    ok "  mitmproxy >=11.0 설치 완료"
elif install_mitmproxy "mitmproxy>=10.0,<11.0"; then
    ok "  mitmproxy >=10.0 설치 완료"
else
    error "mitmproxy 설치 실패. 네트워크 상태를 확인하세요:\n  curl -I https://pypi.org"
fi

pip install --prefer-binary \
    "rich>=13.0" \
    "pyyaml>=6.0" \
    "textual>=8.2.2" \
    "huggingface_hub>=0.22" \
    -q

# ── 프로젝트 자체 설치 (editable) ────────────────────────────────────────────
pip install -e "$INSTALL_DIR" -q

ok "Python 패키지 설치 완료"

# =============================================================================
step "6/8  Gemma 4 2B-IT 모델 다운로드"
# =============================================================================

mkdir -p "$MODEL_DIR"

if [[ "$OPT_NO_MODEL" == true ]]; then
    warn "--no-model 플래그 — 모델 다운로드 건너뜀"
    warn "수동으로 다음 경로에 배치하세요: $MODEL_PATH"
elif [[ -f "$MODEL_PATH" ]]; then
    ok "모델 파일 이미 존재: $MODEL_PATH"
else
    info "HuggingFace에서 모델 다운로드 중..."
    info "  저장소: $HF_REPO"
    info "  경로:   $MODEL_PATH"
    echo -e "\n${YELLOW}  모델 크기 약 1.6GB — 네트워크 속도에 따라 수 분 소요${RESET}"
    echo -e "${YELLOW}  Gemma 4는 Google gated repo입니다. HuggingFace 토큰이 필요합니다.${RESET}\n"

    # HF 토큰: 환경변수 → 프롬프트 순서로 획득
    HF_TOKEN="${HUGGING_FACE_HUB_TOKEN:-${HF_TOKEN:-}}"
    if [[ -z "$HF_TOKEN" ]]; then
        echo    "  HuggingFace 토큰 없이는 Gemma gated repo에 접근할 수 없습니다."
        echo    "  토큰 발급: https://huggingface.co/settings/tokens"
        echo    "  (토큰 없이 건너뛰려면 Enter)"
        read -rsp "  HF 토큰 입력: " HF_TOKEN
        echo ""
    fi

    if [[ -z "$HF_TOKEN" ]]; then
        warn "토큰 없음 — 모델 다운로드를 건너뜁니다"
        warn "나중에 수동 다운로드:"
        warn "  huggingface-cli login"
        warn "  huggingface-cli download $HF_REPO ${HF_FILES[0]} --local-dir $MODEL_DIR"
        warn "  mv $MODEL_DIR/${HF_FILES[0]} $MODEL_PATH 2>/dev/null || true"
    else
        # huggingface_hub CLI 사용 — 파일명 대소문자 fallback + 대체 repo
        python - <<PYEOF
import sys, os
os.environ["HUGGING_FACE_HUB_TOKEN"] = "$HF_TOKEN"
try:
    from huggingface_hub import hf_hub_download
except ImportError:
    print("[ERROR] huggingface_hub 미설치", file=sys.stderr)
    sys.exit(1)

repos  = ["$HF_REPO", "$HF_REPO_ALT"]
files  = ["${HF_FILES[0]}", "${HF_FILES[1]}"]
dest   = "$MODEL_PATH"
destdir= "$MODEL_DIR"

for repo in repos:
    for fname in files:
        try:
            print(f"[INFO]  시도: {repo} / {fname}")
            path = hf_hub_download(
                repo_id=repo,
                filename=fname,
                local_dir=destdir,
                token="$HF_TOKEN",
            )
            # 파일명이 다르면 표준 경로로 복사
            import shutil
            if str(path) != dest:
                shutil.copy2(path, dest)
            print(f"[OK]    다운로드 완료: {dest}")
            sys.exit(0)
        except Exception as e:
            print(f"[WARN]  실패 ({repo}/{fname}): {e}", file=sys.stderr)

print("[ERROR] 모든 저장소/파일명 시도 실패", file=sys.stderr)
print("[INFO]  수동 다운로드:", file=sys.stderr)
print(f"  huggingface-cli download {repos[0]} {files[0]} --local-dir {destdir} --token <TOKEN>", file=sys.stderr)
sys.exit(1)
PYEOF
        if [[ $? -eq 0 ]]; then
            ok "모델 다운로드 완료: $MODEL_PATH"
        else
            warn "모델 다운로드 실패 — 나머지 설치는 계속 진행합니다"
            warn "SLM 없이도 Regex Stage는 정상 동작합니다 (TUI → SLM Stage OFF)"
        fi
    fi
fi

# =============================================================================
step "7/8  설정 디렉터리 및 mitmproxy CA 인증서"
# =============================================================================

mkdir -p "$CONFIG_DIR"

# 기본 제어 파일 생성 (없을 때만)
CTRL_FILE="$CONFIG_DIR/dlp-control.json"
if [[ ! -f "$CTRL_FILE" ]]; then
    cat > "$CTRL_FILE" <<'JSON'
{
    "disabled_rules":          [],
    "block_on_critical":       false,
    "slm_enabled":             true,
    "asset_enabled":           false,
    "context_penalty_enabled": true,
    "confidence_threshold":    0.5,
    "allowlist":               []
}
JSON
    ok "기본 제어 파일 생성: $CTRL_FILE"
fi

# mitmproxy CA 인증서 생성 (없을 때만)
MITM_CA="$CONFIG_DIR/mitmproxy-ca-cert.pem"
if [[ ! -f "$MITM_CA" ]]; then
    info "mitmproxy CA 인증서 생성 중..."
    # mitmdump를 0.5초만 실행해서 CA 생성만 트리거
    MITMPROXY_CONFDIR="$CONFIG_DIR" \
        "$VENV_DIR/bin/mitmdump" --listen-port 18999 &
    MITM_PID=$!
    sleep 2
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true

    # mitmproxy 기본 저장 위치에서 복사
    MITM_DEFAULT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
    if [[ -f "$MITM_DEFAULT" ]]; then
        cp "$MITM_DEFAULT" "$MITM_CA"
        ok "CA 인증서 복사: $MITM_CA"
    else
        warn "CA 인증서 자동 생성 실패 — 최초 mitmdump 실행 시 자동 생성됩니다"
    fi
fi

# logs 디렉터리
mkdir -p "$INSTALL_DIR/logs"
ok "설정 디렉터리 준비 완료: $CONFIG_DIR"

# =============================================================================
step "8/8  systemd 서비스 등록"
# =============================================================================

if [[ "$OPT_NO_SYSTEMD" == true ]]; then
    warn "--no-systemd 플래그 — 서비스 등록 건너뜀"
else
    if [[ "$EUID" -ne 0 ]]; then
        warn "root 권한 없음 — systemd 서비스를 사용자 단위(--user)로 등록합니다"
        SYSTEMD_DIR="$HOME/.config/systemd/user"
        SYSTEMCTL="systemctl --user"
    else
        SYSTEMD_DIR="/etc/systemd/system"
        SYSTEMCTL="systemctl"
    fi

    mkdir -p "$SYSTEMD_DIR"

    # ── DLP 엔진 서비스 ──────────────────────────────────────────────────────
    cat > "$SYSTEMD_DIR/ai-dlp-engine.service" <<EOF
[Unit]
Description=AI DLP Proxy — Engine Server
After=network.target
Documentation=https://github.com/organic4597/ai-dlp-proxy

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/scripts/engine_server.py
Restart=on-failure
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/engine.log
StandardError=append:$INSTALL_DIR/logs/engine.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    # ── mitmproxy 서비스 ─────────────────────────────────────────────────────
    cat > "$SYSTEMD_DIR/ai-dlp-mitm.service" <<EOF
[Unit]
Description=AI DLP Proxy — mitmproxy HTTPS Interceptor
After=ai-dlp-engine.service
Requires=ai-dlp-engine.service
Documentation=https://github.com/organic4597/ai-dlp-proxy

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/mitmdump \\
    --listen-host 0.0.0.0 \\
    --listen-port 4001 \\
    --ssl-insecure \\
    -s $INSTALL_DIR/scripts/inspect_traffic.py
Restart=on-failure
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/mitm.log
StandardError=append:$INSTALL_DIR/logs/mitm.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    # ── TUI 서비스 (선택) ────────────────────────────────────────────────────
    cat > "$SYSTEMD_DIR/ai-dlp-tui.service" <<EOF
[Unit]
Description=AI DLP Proxy — TUI Dashboard
After=ai-dlp-engine.service
Documentation=https://github.com/organic4597/ai-dlp-proxy

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/scripts/tui.py
Restart=on-failure
RestartSec=3
StandardInput=tty
TTYPath=/dev/tty1
StandardOutput=tty
StandardError=append:$INSTALL_DIR/logs/tui.log

[Install]
WantedBy=multi-user.target
EOF

    # systemd 리로드 및 서비스 활성화
    if [[ "$EUID" -eq 0 ]]; then
        systemctl daemon-reload
        systemctl enable ai-dlp-engine.service ai-dlp-mitm.service
        ok "systemd 서비스 등록 및 활성화 (root)"
    else
        systemctl --user daemon-reload
        systemctl --user enable ai-dlp-engine.service ai-dlp-mitm.service 2>/dev/null || true
        ok "systemd 사용자 서비스 등록 완료"
    fi
fi

# =============================================================================
#  설치 완료 — 사용법 안내
# =============================================================================

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║              AI DLP Proxy 설치 완료!                           ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}── 서비스 시작 ─────────────────────────────────────────────────────${RESET}"
if [[ "$EUID" -eq 0 ]]; then
    echo "  sudo systemctl start ai-dlp-engine ai-dlp-mitm"
    echo "  sudo systemctl status ai-dlp-engine ai-dlp-mitm"
else
    echo "  systemctl --user start ai-dlp-engine ai-dlp-mitm"
    echo "  systemctl --user status ai-dlp-engine ai-dlp-mitm"
fi
echo ""
echo -e "${BOLD}── TUI 대시보드 (터미널에서 직접 실행) ───────────────────────────────${RESET}"
echo "  cd $INSTALL_DIR"
echo "  source venv/bin/activate"
echo "  python scripts/tui.py"
echo ""
echo -e "${BOLD}── 클라이언트 프록시 설정 ──────────────────────────────────────────${RESET}"
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  HTTP/HTTPS 프록시:  ${SERVER_IP}:4001"
echo "  CA 인증서 경로:     $CONFIG_DIR/mitmproxy-ca-cert.pem"
echo "  (클라이언트 PC에서 CA 인증서를 신뢰하도록 설치 필요)"
echo ""
echo -e "${BOLD}── 모델 경로 ───────────────────────────────────────────────────────${RESET}"
if [[ -f "$MODEL_PATH" ]]; then
    echo -e "  ${GREEN}✓${RESET}  $MODEL_PATH"
else
    echo -e "  ${YELLOW}✗${RESET}  $MODEL_PATH  (없음 — SLM 비활성 상태로 실행됨)"
fi
echo ""
echo -e "${BOLD}── 컴퓨팅 모드 ─────────────────────────────────────────────────────${RESET}"
if [[ "$COMPUTE_MODE" == "cuda" ]]; then
    echo -e "  ${GREEN}NVIDIA GPU (CUDA)${RESET} — 예상 레이턴시 ~200ms/req"
elif [[ "$IS_VM" == true ]]; then
    echo -e "  ${YELLOW}CPU 전용 (${VM_VENDOR} VM)${RESET} — 예상 레이턴시 ~5초/req (SLM 활성 시)"
    [[ "$VM_VENDOR" == "vmware" && "$ARCH" == "aarch64" ]] && \
        echo "  환경: Apple Silicon MacBook + VMware Fusion"
    echo "  SLM 비활성 권장: TUI → 제어탭 → SLM Stage OFF (Regex만으로도 충분)"
else
    echo -e "  ${YELLOW}CPU 전용${RESET} — 예상 레이턴시 ~5초/req (SLM 활성 시)"
    echo "  GPU 추가 후 재설치: bash install.sh --gpu"
fi
echo ""
echo -e "${BOLD}── 로그 ────────────────────────────────────────────────────────────${RESET}"
echo "  $INSTALL_DIR/logs/engine.log"
echo "  $INSTALL_DIR/logs/mitm.log"
echo ""
