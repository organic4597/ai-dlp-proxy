"""FastAPI 앱 진입점."""
from __future__ import annotations
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

# 프로덕션: 빌드된 SvelteKit static 파일 서빙
_static = Path(__file__).parent.parent / "frontend" / "build"
if _static.exists():
    app.mount("/", StaticFiles(directory=str(_static), html=True), name="static")
    log.info(f"Static files: {_static}")


@app.get("/api/health")
async def health():
    return {"ok": True, "service": "ai-dlp-proxy-dashboard"}
