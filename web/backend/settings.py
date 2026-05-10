"""웹 대시보드 백엔드 설정."""
import os
from pathlib import Path

ENGINE_SOCK   = os.getenv("DLP_ENGINE_SOCK",  "/tmp/dlp-engine.sock")
CONTROL_FILE  = Path(os.getenv("DLP_CONTROL",  "/tmp/dlp-control.json"))
AUDIT_FILE    = Path(os.getenv("DLP_AUDIT",    str(Path.home() / ".config/ai-dlp-proxy/audit.jsonl")))
DB_PATH       = Path(os.getenv("DLP_DB_PATH",  str(Path.home() / ".config/ai-dlp-proxy/db/dlp.db")))
WEB_HOST      = os.getenv("DLP_WEB_HOST", "127.0.0.1")
WEB_PORT      = int(os.getenv("DLP_WEB_PORT", "8765"))
CORS_ORIGINS: list[str] = os.getenv(
    "DLP_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

# 프로세스 관련 경로
PROXY_DIR        = Path(__file__).parent.parent.parent
_DAEMON_LOG_DIR  = PROXY_DIR / "logs" / "daemon"
MITM_PID_FILE    = _DAEMON_LOG_DIR / "mitm.pid"
ENGINE_PID_FILE  = _DAEMON_LOG_DIR / "engine.pid"
MITM_PORT        = int(os.getenv("DLP_MITM_PORT", "4001"))
