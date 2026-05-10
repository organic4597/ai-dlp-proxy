"""파이프라인 통계 API."""
from __future__ import annotations

from fastapi import APIRouter, Query

import engine_client
from db import get_db

router = APIRouter()


@router.get("/pipeline/stats")
async def pipeline_stats():
    """엔진 실시간 stats 조회."""
    stats = await engine_client.get_stats()
    if stats is None:
        return {"ok": False, "error": "엔진에 연결할 수 없습니다"}
    return stats


@router.get("/pipeline/snapshots")
async def pipeline_snapshots(
    range_h: int = Query(1, ge=1, le=720, description="조회 기간(시간)"),
):
    """파이프라인 통계 히스토리 (차트용)."""
    db = await get_db()
    async with db.execute(
        f"""SELECT * FROM pipeline_snapshots
            WHERE ts >= datetime('now', '-{range_h} hours')
            ORDER BY ts ASC"""
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/pipeline/snapshots/latest")
async def pipeline_snapshots_latest():
    """최근 스냅샷 1건."""
    db = await get_db()
    async with db.execute(
        "SELECT * FROM pipeline_snapshots ORDER BY id DESC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
    return dict(row) if row else {}
