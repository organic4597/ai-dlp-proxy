"""SSE 이벤트 스트림 엔드포인트."""
from __future__ import annotations
import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from event_bus import event_bus

router = APIRouter()


@router.get("/events")
async def sse_stream(request: Request):
    """SSE 통합 스트림: scan_result + log 이벤트."""

    async def generate():
        # 연결 keepalive 코멘트
        yield ": connected\n\n"
        try:
            async for event in event_bus.subscribe_all():
                if await request.is_disconnected():
                    break
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
