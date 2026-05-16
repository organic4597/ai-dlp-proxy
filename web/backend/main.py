"""FastAPI 앱 진입점."""
from __future__ import annotations
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from db import init_db, close_db
from workers import engine_bridge, log_bridge, snapshot_worker, purge_worker
from settings import CORS_ORIGINS
from routers import events, traffic, findings, pipeline, control, process, audit, logs
from routers import rules, assets, allowlist

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WEB] %(levelname)s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dlp.web")

_bg_tasks: list[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작
    await init_db()
    log.info("DB 초기화 완료")

    for coro_func, name in [
        (engine_bridge, "engine-bridge"),
        (log_bridge,    "log-bridge"),
        (snapshot_worker, "snapshot"),
        (purge_worker,  "purge"),
    ]:
        t = asyncio.create_task(coro_func(), name=name)
        _bg_tasks.append(t)
        log.info(f"백그라운드 태스크 시작: {name}")

    yield

    # 종료
    for t in _bg_tasks:
        t.cancel()
    await asyncio.gather(*_bg_tasks, return_exceptions=True)
    await close_db()
    log.info("웹 서버 종료")


app = FastAPI(
    title="AI-DLP-Proxy 대시보드",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API 라우터
prefix = "/api"
app.include_router(events.router,   prefix=prefix, tags=["events"])
app.include_router(traffic.router,  prefix=prefix, tags=["traffic"])
app.include_router(findings.router, prefix=prefix, tags=["findings"])
app.include_router(pipeline.router, prefix=prefix, tags=["pipeline"])
app.include_router(control.router,  prefix=prefix, tags=["control"])
app.include_router(process.router,  prefix=prefix, tags=["process"])
app.include_router(audit.router,    prefix=prefix, tags=["audit"])
app.include_router(logs.router,      prefix=prefix, tags=["logs"])
app.include_router(rules.router,     prefix=prefix, tags=["rules"])
app.include_router(assets.router,    prefix=prefix, tags=["assets"])
app.include_router(allowlist.router, prefix=prefix, tags=["allowlist"])

# 프로덕션: 빌드된 SvelteKit static 파일 서빙 (SPA 폴백 포함)
_static = Path(__file__).parent.parent / "frontend" / "build"
_certs_dir = Path(__file__).parent.parent.parent / "certs"

# CA 인증서 다운로드 — Windows/macOS/Linux/Android 설치용
# http://<pi-ip>:8765/certs/windows/mitmproxy-ca.p12
if _certs_dir.exists():
    app.mount("/certs", StaticFiles(directory=str(_certs_dir)), name="certs")
    log.info(f"Certs dir served at /certs: {_certs_dir}")

if _static.exists():
    # _app/ 디렉토리 — JS/CSS 번들 등 해시된 정적 에셋
    _app_dir = _static / "_app"
    if _app_dir.exists():
        app.mount("/_app", StaticFiles(directory=str(_app_dir)), name="static-app")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """SPA 폴백: 실제 파일이면 직접 서빙, 아니면 index.html 반환."""
        candidate = _static / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_static / "index.html"))

    log.info(f"Static files (SPA mode): {_static}")


@app.get("/api/health")
async def health():
    return {"ok": True, "service": "ai-dlp-proxy-dashboard"}
