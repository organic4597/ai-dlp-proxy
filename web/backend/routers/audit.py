"""감사 로그 API (DB 기반 + audit.jsonl 마이그레이션)."""
from __future__ import annotations
import csv
import io
import json as _json

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from db import get_db, insert_request
from models import AuditOut, FindingOut
from settings import AUDIT_FILE

router = APIRouter()


@router.get("/audit", response_model=list[AuditOut])
async def list_audit(
    limit:    int = Query(100, ge=1, le=500),
    offset:   int = Query(0, ge=0),
    action:   str | None = Query(None),
    rule:     str | None = Query(None),
    date_from: str | None = Query(None, description="ISO8601 시작일"),
    date_to:   str | None = Query(None, description="ISO8601 종료일"),
    with_findings: bool = Query(False),
):
    db = await get_db()
    where = ["1=1"]
    params: list = []
    if action and action != "all":
        where.append("r.pipeline_action = ?")
        params.append(action)
    if date_from:
        where.append("r.ts >= ?")
        params.append(date_from)
    if date_to:
        where.append("r.ts <= ?")
        params.append(date_to)
    if rule:
        # finding 테이블 join
        where.append(
            "r.request_id IN (SELECT DISTINCT request_id FROM findings WHERE rule LIKE ?)"
        )
        params.append(f"%{rule}%")

    sql = (
        f"SELECT r.* FROM requests r WHERE {' AND '.join(where)}"
        f" ORDER BY r.id DESC LIMIT ? OFFSET ?"
    )
    params += [limit, offset]
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()

    result = []
    for row in rows:
        r = dict(row)
        r["cache_hit"] = bool(r.get("cache_hit"))
        # AuditOut 필드 매핑
        out = AuditOut(
            id=r.get("id"),
            ts=r.get("ts", ""),
            request_id=r.get("request_id", ""),
            provider=r.get("provider"),
            model=r.get("model"),
            pipeline_action=r.get("pipeline_action", "pass"),
            finding_count=r.get("raw_finding_count", 0),
            effective_finding_count=r.get("effective_finding_count", 0),
            total_text_len=r.get("total_text_len", 0),
            target_count=r.get("target_count", 0),
            elapsed_ms=r.get("elapsed_ms"),
        )
        if with_findings:
            async with db.execute(
                "SELECT * FROM findings WHERE request_id=? ORDER BY id",
                (r["request_id"],),
            ) as cur2:
                frows = await cur2.fetchall()
            findings = []
            for fr in frows:
                fd = dict(fr)
                fd["suppressed"] = bool(fd.get("suppressed"))
                if fd.get("metadata"):
                    try:
                        fd["metadata"] = _json.loads(fd["metadata"])
                    except Exception:
                        fd["metadata"] = None
                findings.append(FindingOut(**fd))
            out.findings = findings
        result.append(out)
    return result


@router.get("/audit/export/csv")
async def export_audit_csv(
    action:   str | None = Query(None),
    date_from: str | None = Query(None),
    date_to:   str | None = Query(None),
):
    """감사 로그 CSV 내보내기."""
    rows = await list_audit(limit=5000, offset=0, action=action,
                            date_from=date_from, date_to=date_to,
                            with_findings=False)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ts", "request_id", "provider", "model", "action",
                     "findings", "effective", "text_len", "elapsed_ms"])
    for r in rows:
        writer.writerow([
            r.ts, r.request_id, r.provider, r.model, r.pipeline_action,
            r.finding_count, r.effective_finding_count, r.total_text_len, r.elapsed_ms,
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dlp-audit.csv"},
    )


@router.post("/audit/migrate-jsonl")
async def migrate_jsonl():
    """audit.jsonl → DB 마이그레이션 (최초 1회)."""
    if not AUDIT_FILE.exists():
        return {"ok": True, "migrated": 0, "message": "audit.jsonl 없음"}
    count = 0
    errors = 0
    with open(AUDIT_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
                await insert_request(rec)
                count += 1
            except Exception:
                errors += 1
    return {"ok": True, "migrated": count, "errors": errors}
