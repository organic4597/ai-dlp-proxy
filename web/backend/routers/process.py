"""프로세스 상태 및 제어 API."""
from __future__ import annotations
import asyncio
import os
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

import engine_client
from models import ProcessStatus
from settings import PROXY_DIR, MITM_PID_FILE, ENGINE_PID_FILE, MITM_PORT

router = APIRouter()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def _proc_uptime(pid: int) -> float | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().split()
        # field 22 = starttime (jiffies since boot)
        starttime = int(stat[21])
        hz = os.sysconf("SC_CLK_TCK")
        with open("/proc/uptime") as f:
            uptime_sec = float(f.read().split()[0])
        start_sec = starttime / hz
        return uptime_sec - start_sec
    except Exception:
        return None


@router.get("/process", response_model=list[ProcessStatus])
async def list_processes():
    engine_alive = await engine_client.ping()
    engine_pid = _read_pid(ENGINE_PID_FILE)

    mitm_pid = _read_pid(MITM_PID_FILE)
    mitm_alive = _pid_alive(mitm_pid) if mitm_pid else False

    return [
        ProcessStatus(
            name="engine",
            running=engine_alive,
            pid=engine_pid if (engine_pid and _pid_alive(engine_pid)) else None,
            uptime_sec=_proc_uptime(engine_pid) if engine_pid else None,
            extra={"sock": str(engine_client.ENGINE_SOCK)},
        ),
        ProcessStatus(
            name="mitmproxy",
            running=mitm_alive,
            pid=mitm_pid if mitm_alive else None,
            uptime_sec=_proc_uptime(mitm_pid) if mitm_pid else None,
            extra={"port": str(MITM_PORT)},
        ),
    ]


_SVC_MAP = {"engine": "engine", "mitmproxy": "mitm"}


@router.post("/process/{name}/start")
async def start_process(name: str):
    svc = _SVC_MAP.get(name)
    if not svc:
        raise HTTPException(400, f"알 수 없는 프로세스: {name}")
    supervisor = PROXY_DIR / "dlp-supervisor"
    if not supervisor.exists():
        raise HTTPException(404, "dlp-supervisor 스크립트 없음")
    proc = await asyncio.create_subprocess_exec(
        "bash", str(supervisor), "start", svc,
        cwd=str(PROXY_DIR),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return {"ok": True, "pid": proc.pid, "message": f"{name} 시작 요청됨"}


@router.post("/process/{name}/stop")
async def stop_process(name: str):
    svc = _SVC_MAP.get(name)
    if not svc:
        raise HTTPException(400, f"알 수 없는 프로세스: {name}")
    supervisor = PROXY_DIR / "dlp-supervisor"
    if not supervisor.exists():
        raise HTTPException(404, "dlp-supervisor 스크립트 없음")
    proc = await asyncio.create_subprocess_exec(
        "bash", str(supervisor), "stop", svc,
        cwd=str(PROXY_DIR),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return {"ok": True, "pid": proc.pid, "message": f"{name} 중지 요청됨"}
