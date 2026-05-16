"""engine_server.py와 Unix Domain Socket으로 통신하는 비동기 클라이언트."""
from __future__ import annotations
import asyncio
import json
import logging
from typing import AsyncGenerator

from settings import ENGINE_SOCK

log = logging.getLogger(__name__)
_REQ_ID = 0


def _next_id() -> int:
    global _REQ_ID
    _REQ_ID += 1
    return _REQ_ID


async def _open(timeout: float = 3.0):
    return await asyncio.wait_for(
        asyncio.open_unix_connection(ENGINE_SOCK, limit=4 * 1024 * 1024),
        timeout=timeout,
    )


async def ping() -> bool:
    try:
        r, w = await _open()
        try:
            w.write(json.dumps({"action": "ping", "id": _next_id()}).encode() + b"\n")
            await w.drain()
            line = await asyncio.wait_for(r.readline(), timeout=2)
            return bool(json.loads(line).get("ok"))
        finally:
            w.close()
    except Exception:
        return False


async def get_stats() -> dict | None:
    """ping + stats 순서로 요청 (engine_server 프로토콜 요구)."""
    try:
        r, w = await _open()
        try:
            # ping 먼저
            w.write(json.dumps({"action": "ping", "id": _next_id()}).encode() + b"\n")
            await w.drain()
            await asyncio.wait_for(r.readline(), timeout=2)
            # stats
            w.write(json.dumps({"action": "stats", "id": _next_id()}).encode() + b"\n")
            await w.drain()
            line = await asyncio.wait_for(r.readline(), timeout=3)
            data = json.loads(line)
            return data if data.get("ok") else None
        finally:
            w.close()
    except Exception as e:
        log.debug(f"get_stats error: {e}")
        return None


async def subscribe() -> AsyncGenerator[dict, None]:
    """scan_result 이벤트 무한 스트림 (자동 재연결)."""
    while True:
        try:
            r, w = await _open(timeout=10.0)
            try:
                w.write(json.dumps({"action": "subscribe", "id": _next_id()}).encode() + b"\n")
                await w.drain()
                # 엔진이 바쁠 때(예: SLM 추론) ACK가 늦을 수 있으므로 여유 있게 대기
                await asyncio.wait_for(r.readline(), timeout=30)  # ack
                log.info("Engine subscribe 연결됨")
                while True:
                    # 유휴 구간에서 끊지 않도록 타임아웃 없이 대기
                    line = await r.readline()
                    if not line:
                        break
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            msg = str(e).strip() or type(e).__name__
            log.warning(f"Engine subscribe 연결 끊김: {msg} — 3초 후 재연결")
        await asyncio.sleep(3)


async def log_subscribe() -> AsyncGenerator[dict, None]:
    """엔진 로그 무한 스트림 (자동 재연결)."""
    while True:
        try:
            r, w = await _open(timeout=10.0)
            try:
                w.write(json.dumps({"action": "log_subscribe", "id": _next_id()}).encode() + b"\n")
                await w.drain()
                # 엔진이 바쁠 때(예: SLM 추론) ACK가 늦을 수 있으므로 여유 있게 대기
                await asyncio.wait_for(r.readline(), timeout=30)  # ack
                log.info("Engine log_subscribe 연결됨")
                while True:
                    # 유휴 구간에서 끊지 않도록 타임아웃 없이 대기
                    line = await r.readline()
                    if not line:
                        break
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            msg = str(e).strip() or type(e).__name__
            log.warning(f"Engine log_subscribe 연결 끊김: {msg} — 3초 후 재연결")
        await asyncio.sleep(3)
