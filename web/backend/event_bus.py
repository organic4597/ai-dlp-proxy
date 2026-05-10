"""SSE fan-out 이벤트 버스: 엔진 이벤트를 여러 SSE 클라이언트에 전달."""
from __future__ import annotations
import asyncio
from typing import AsyncGenerator


class EventBus:
    """asyncio.Queue 기반 fan-out 브로드캐스터."""

    def __init__(self) -> None:
        self._scan_subs: list[asyncio.Queue] = []
        self._log_subs:  list[asyncio.Queue] = []

    # ── 발행 ───────────────────────────────────────────────────────────────

    def publish_scan(self, event: dict) -> None:
        self._broadcast(self._scan_subs, event)

    def publish_log(self, event: dict) -> None:
        self._broadcast(self._log_subs, event)

    def _broadcast(self, subs: list[asyncio.Queue], event: dict) -> None:
        dead: list[asyncio.Queue] = []
        for q in subs:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
        for q in dead:
            if q in subs:
                subs.remove(q)

    # ── 구독 ───────────────────────────────────────────────────────────────

    async def subscribe_scan(self) -> AsyncGenerator[dict, None]:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._scan_subs.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            if q in self._scan_subs:
                self._scan_subs.remove(q)

    async def subscribe_log(self) -> AsyncGenerator[dict, None]:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._log_subs.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            if q in self._log_subs:
                self._log_subs.remove(q)

    async def subscribe_all(self) -> AsyncGenerator[dict, None]:
        """scan + log 이벤트를 모두 받는 통합 구독."""
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._scan_subs.append(q)
        self._log_subs.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            for lst in (self._scan_subs, self._log_subs):
                if q in lst:
                    lst.remove(q)


# 싱글턴
event_bus = EventBus()
