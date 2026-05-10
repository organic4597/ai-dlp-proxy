"""백그라운드 워커: 엔진 이벤트를 DB에 저장 + 통계 스냅샷."""
from __future__ import annotations
import asyncio
import logging
import time

import engine_client
from db import insert_request, insert_log, insert_snapshot, purge_old_data, update_dlp_applied
from event_bus import event_bus

log = logging.getLogger(__name__)


async def engine_bridge() -> None:
    """엔진 scan_result + scan_applied 이벤트 → event_bus + DB."""
    async for event in engine_client.subscribe():
        try:
            etype = event.get("type", "scan_result")
            if etype == "scan_applied":
                # 마스킹/차단 결과 업데이트
                rid = str(event.get("id", ""))
                applied = event.get("dlp_applied", "pass")
                if rid:
                    await update_dlp_applied(rid, applied)
                event_bus.publish_scan(event)
            else:
                event_bus.publish_scan(event)
                await insert_request(event)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.debug(f"engine_bridge error: {e}")


async def log_bridge() -> None:
    """엔진 로그 이벤트 → event_bus + DB."""
    async for event in engine_client.log_subscribe():
        try:
            event_bus.publish_log(event)
            await insert_log(event)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.debug(f"log_bridge error: {e}")


async def snapshot_worker() -> None:
    """1분 주기로 엔진 통계를 DB에 스냅샷 저장."""
    while True:
        try:
            await asyncio.sleep(60)
            stats = await engine_client.get_stats()
            if stats:
                import time as _t
                stats["ts"] = _t.strftime("%Y-%m-%dT%H:%M:%S")
                await insert_snapshot(stats)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.debug(f"snapshot_worker error: {e}")


async def purge_worker() -> None:
    """1시간 주기로 오래된 DB 데이터 정리."""
    while True:
        try:
            await asyncio.sleep(3600)
            await purge_old_data()
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.debug(f"purge_worker error: {e}")
