"""엔진 로그 조회 API."""
from __future__ import annotations

from fastapi import APIRouter, Query

from db import get_db

router = APIRouter()


@router.delete("/logs")
async def clear_logs():
    """엔진 로그 전체 삭제."""
    db = await get_db()
    async with db.execute("DELETE FROM engine_logs") as cur:
        deleted = cur.rowcount
    await db.commit()
    return {"deleted": deleted}


@router.get("/logs")
async def get_logs(
    limit:  int = Query(200, ge=1, le=2000),
    level:  str | None = Query(None),
    search: str | None = Query(None),
):
    """DB에 저장된 엔진 로그 최근 N줄 조회."""
    db = await get_db()
    where = ["1=1"]
    params: list = []
    if level:
        where.append("level = ?")
        params.append(level.upper())
    if search:
        where.append("message LIKE ?")
        params.append(f"%{search}%")

    sql = (
        f"SELECT * FROM engine_logs WHERE {' AND '.join(where)}"
        f" ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in reversed(rows)]
