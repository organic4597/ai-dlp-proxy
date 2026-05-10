"""Allowlist 상세 관리 API.

control.json 의 allowlist 배열을 직접 편집.
각 항목: { "rule": str, "value": str, "added_at": ISO8601, "expires_at": ISO8601|null }
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from settings import CONTROL_FILE

router = APIRouter()


class AllowlistEntryIn(BaseModel):
    rule: str = "*"          # "*" = 모든 룰에 적용
    value: str
    expires_at: str | None = None   # ISO8601 (예: "2026-12-31T00:00:00Z")


def _read_allowlist() -> list[dict]:
    try:
        data = json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
        return data.get("allowlist", [])
    except Exception:
        return []


def _write_allowlist(entries: list[dict]) -> None:
    try:
        data = json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    data["allowlist"] = entries
    CONTROL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _is_expired(entry: dict) -> bool:
    exp = entry.get("expires_at")
    if not exp:
        return False
    try:
        dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


@router.get("/allowlist")
async def list_allowlist(
    rule: str | None = Query(None, description="특정 룰로 필터"),
    expired: bool | None = Query(None, description="만료 항목만/유효 항목만"),
):
    entries = _read_allowlist()
    result = []
    for i, e in enumerate(entries):
        item = {**e, "_idx": i, "_expired": _is_expired(e)}
        if rule and e.get("rule", "*") not in ("*", rule):
            continue
        if expired is True and not item["_expired"]:
            continue
        if expired is False and item["_expired"]:
            continue
        result.append(item)
    return result


@router.post("/allowlist", status_code=201)
async def add_allowlist(body: AllowlistEntryIn):
    value = body.value.strip()
    if not value:
        raise HTTPException(422, "value 는 비어있을 수 없습니다")
    rule = body.rule.strip() or "*"

    # 만료일 형식 검증
    if body.expires_at:
        try:
            datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(422, "expires_at 형식 오류 (ISO8601 사용)")

    entries = _read_allowlist()
    # 중복 체크
    if any(e.get("rule", "*") == rule and e.get("value") == value for e in entries):
        raise HTTPException(409, f"'{rule}:{value}' 이미 존재")

    entry: dict = {
        "rule": rule,
        "value": value,
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    if body.expires_at:
        entry["expires_at"] = body.expires_at

    entries.append(entry)
    _write_allowlist(entries)
    return {**entry, "_expired": False}


@router.delete("/allowlist/{idx}", status_code=204)
async def delete_allowlist(idx: int):
    entries = _read_allowlist()
    if idx < 0 or idx >= len(entries):
        raise HTTPException(404, f"인덱스 {idx} 없음")
    entries.pop(idx)
    _write_allowlist(entries)


@router.delete("/allowlist/purge-expired", status_code=200)
async def purge_expired():
    """만료된 항목 일괄 삭제."""
    entries = _read_allowlist()
    before = len(entries)
    entries = [e for e in entries if not _is_expired(e)]
    _write_allowlist(entries)
    return {"removed": before - len(entries), "remaining": len(entries)}
