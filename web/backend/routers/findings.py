"""PII 탐지 결과 API."""
from __future__ import annotations
import json as _json

from fastapi import APIRouter, Query

from db import get_db
from models import FindingOut
from settings import CONTROL_FILE

router = APIRouter()


def _confidence_threshold() -> float:
    try:
        data = _json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
        return float(data.get("confidence_threshold", 0.5))
    except Exception:
        return 0.5


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    limit:    int = Query(200, ge=1, le=1000),
    offset:   int = Query(0, ge=0),
    rule:     str | None = Query(None),
    severity: str | None = Query(None),
    suppressed: bool | None = Query(None),
    status:   str | None = Query(None),
    stage:    str | None = Query(None),
):
    db = await get_db()
    threshold = _confidence_threshold()
    where = ["1=1"]
    params: list = []
    if rule:
        where.append("rule LIKE ?")
        params.append(f"%{rule}%")
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if suppressed is not None:
        where.append("suppressed = ?")
        params.append(1 if suppressed else 0)
    if status == "effective":
        where.append("suppressed = 0 AND confidence >= ?")
        params.append(threshold)
    elif status == "suppressed":
        where.append("suppressed = 1")
    elif status == "below_threshold":
        where.append("suppressed = 0 AND confidence < ?")
        params.append(threshold)
    if stage:
        where.append("stage = ?")
        params.append(stage)

    sql = (
        f"SELECT f.*, r.dlp_applied, r.pipeline_action as req_action, r.prompt_excerpt"
        f" FROM findings f"
        f" LEFT JOIN requests r ON f.request_id = r.request_id"
        f" WHERE {' AND '.join(where)}"
        f" ORDER BY f.id DESC LIMIT ? OFFSET ?"
    )
    params += [limit, offset]
    async with db.execute(sql, params) as cur:
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
        r["confidence_threshold"] = threshold
        r["policy_effective"] = bool(
            not r.get("suppressed") and float(r.get("confidence") or 0.0) >= threshold
        )
        if r["policy_effective"]:
            r["policy_reason"] = "effective"
        elif r.get("suppressed"):
            r["policy_reason"] = r.get("suppressed_reason") or "suppressed"
        else:
            r["policy_reason"] = "below_threshold"
        result.append(FindingOut(**r))
    return result


@router.get("/findings/stats/by-rule")
async def findings_by_rule():
    """룰별 탐지 통계."""
    db = await get_db()
    threshold = _confidence_threshold()
    async with db.execute(
        """SELECT rule,
                  COUNT(*) as total,
                  SUM(CASE WHEN suppressed=0 AND confidence >= ? THEN 1 ELSE 0 END) as effective,
                  SUM(CASE WHEN suppressed=1 THEN 1 ELSE 0 END) as suppressed_count,
                  AVG(confidence) as avg_confidence
           FROM findings
           WHERE rule IS NOT NULL
           GROUP BY rule
           ORDER BY total DESC""",
        (threshold,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/findings/stats/suppress-breakdown")
async def suppress_breakdown():
    """suppress 이유별 분류 통계."""
    db = await get_db()
    async with db.execute(
        """SELECT suppressed_reason,
                  COUNT(*) as count
           FROM findings
           WHERE suppressed=1
           GROUP BY suppressed_reason
           ORDER BY count DESC"""
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]
