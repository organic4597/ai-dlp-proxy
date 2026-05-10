"""트래픽 요청 목록 API."""
from __future__ import annotations
from typing import Literal

from fastapi import APIRouter, Query

from db import get_db
from models import RequestOut, FindingOut

router = APIRouter()

_ACTIONS = {"pass", "alert", "mask", "block"}


@router.delete("/traffic")
async def clear_traffic():
    """트래픽 기록(requests + findings) 전체 삭제."""
    db = await get_db()
    async with db.execute("DELETE FROM findings") as cur:
        del_findings = cur.rowcount
    async with db.execute("DELETE FROM requests") as cur:
        del_requests = cur.rowcount
    await db.commit()
    return {"deleted_requests": del_requests, "deleted_findings": del_findings}


@router.get("/traffic", response_model=list[RequestOut])
async def list_traffic(
    limit:    int = Query(100, ge=1, le=500),
    offset:   int = Query(0, ge=0),
    action:   str | None = Query(None),
    provider: str | None = Query(None),
    model:    str | None = Query(None),
    with_findings: bool = Query(False),
):
    db = await get_db()
    where = ["1=1"]
    params: list = []
    if action and action in _ACTIONS:
        where.append("pipeline_action = ?")
        params.append(action)
    if provider:
        where.append("provider LIKE ?")
        params.append(f"%{provider}%")
    if model:
        where.append("model LIKE ?")
        params.append(f"%{model}%")

    sql = (
        f"SELECT * FROM requests WHERE {' AND '.join(where)}"
        f" ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params += [limit, offset]
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()

    result = []
    for row in rows:
        r = dict(row)
        r["cache_hit"] = bool(r.get("cache_hit"))
        findings = None
        if with_findings:
            findings = await _get_findings(r["request_id"])
        result.append(RequestOut(**{**r, "findings": findings}))
    return result


@router.get("/traffic/{request_id}", response_model=RequestOut)
async def get_traffic_detail(request_id: str):
    db = await get_db()
    async with db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, "요청을 찾을 수 없습니다")
    r = dict(row)
    r["cache_hit"] = bool(r.get("cache_hit"))
    findings = await _get_findings(request_id)
    return RequestOut(**{**r, "findings": findings})


@router.get("/traffic/stats/summary")
async def traffic_summary():
    db = await get_db()
    async with db.execute(
        """SELECT
             COUNT(*) as total,
             SUM(CASE WHEN pipeline_action='pass'  THEN 1 ELSE 0 END) as pass_count,
             SUM(CASE WHEN pipeline_action='alert' THEN 1 ELSE 0 END) as alert_count,
             SUM(CASE WHEN pipeline_action='mask'  THEN 1 ELSE 0 END) as mask_count,
             SUM(CASE WHEN pipeline_action='block' THEN 1 ELSE 0 END) as block_count,
             AVG(elapsed_ms) as avg_elapsed_ms,
             SUM(raw_finding_count) as total_findings
           FROM requests"""
    ) as cur:
        row = await cur.fetchone()
    return dict(row) if row else {}


async def _get_findings(request_id: str) -> list[FindingOut]:
    import json as _json
    db = await get_db()
    async with db.execute(
        "SELECT * FROM findings WHERE request_id=? ORDER BY id", (request_id,)
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["suppressed"] = bool(r.get("suppressed"))
        if r.get("metadata"):
            try:
                r["metadata"] = _json.loads(r["metadata"])
            except Exception:
                r["metadata"] = None
        result.append(FindingOut(**r))
    return result
