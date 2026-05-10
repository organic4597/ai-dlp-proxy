"""SQLite DB 연결 및 스키마 마이그레이션."""
from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path

import aiosqlite

from settings import DB_PATH

log = logging.getLogger(__name__)

_db: aiosqlite.Connection | None = None
_db_lock = asyncio.Lock()

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS requests (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                      TEXT    NOT NULL,
    request_id              TEXT    UNIQUE,
    provider                TEXT,
    model                   TEXT,
    pipeline_action         TEXT DEFAULT 'pass',
    raw_finding_count       INTEGER DEFAULT 0,
    effective_finding_count INTEGER DEFAULT 0,
    total_text_len          INTEGER DEFAULT 0,
    target_count            INTEGER DEFAULT 0,
    elapsed_ms              REAL,
    cache_hit               INTEGER DEFAULT 0,
    dlp_applied             TEXT DEFAULT 'pass'
);
CREATE INDEX IF NOT EXISTS idx_req_ts  ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_req_act ON requests(pipeline_action);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       TEXT    NOT NULL,
    ts               TEXT    NOT NULL,
    stage            TEXT,
    rule             TEXT,
    severity         TEXT,
    confidence       REAL,
    suppressed       INTEGER DEFAULT 0,
    suppressed_reason TEXT,
    match_text       TEXT,
    field_path       TEXT,
    role             TEXT,
    metadata         TEXT
);
CREATE INDEX IF NOT EXISTS idx_find_req  ON findings(request_id);
CREATE INDEX IF NOT EXISTS idx_find_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS idx_find_ts   ON findings(ts);

CREATE TABLE IF NOT EXISTS pipeline_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    cache_hits    INTEGER DEFAULT 0,
    cache_misses  INTEGER DEFAULT 0,
    nms_suppressed   INTEGER DEFAULT 0,
    ml_suppressed    INTEGER DEFAULT 0,
    al_suppressed    INTEGER DEFAULT 0,
    slm_calls        INTEGER DEFAULT 0,
    slm_avg_ms       REAL    DEFAULT 0,
    action_pass      INTEGER DEFAULT 0,
    action_alert     INTEGER DEFAULT 0,
    action_mask      INTEGER DEFAULT 0,
    action_block     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snap_ts ON pipeline_snapshots(ts);

CREATE TABLE IF NOT EXISTS engine_logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    level    TEXT DEFAULT 'INFO',
    message  TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_ts ON engine_logs(ts);
"""


async def _ensure_column(db: aiosqlite.Connection, table: str, column: str, definition: str) -> None:
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        rows = await cur.fetchall()
    if column not in {row["name"] for row in rows}:
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


async def init_db() -> None:
    """DB 초기화: 디렉터리 생성 + 스키마 적용."""
    global _db
    async with _db_lock:
        if _db is not None:
            return
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _db = await aiosqlite.connect(str(DB_PATH), check_same_thread=False)
        _db.row_factory = aiosqlite.Row
        await _db.executescript(SCHEMA_SQL)
        await _ensure_column(_db, "requests", "dlp_applied", "TEXT DEFAULT 'pass'")
        await _db.commit()
        log.info(f"DB 초기화 완료: {DB_PATH}")


async def get_db() -> aiosqlite.Connection:
    if _db is None:
        await init_db()
    return _db  # type: ignore[return-value]


async def close_db() -> None:
    global _db
    async with _db_lock:
        if _db is not None:
            await _db.close()
            _db = None


async def purge_old_data() -> None:
    """오래된 데이터 정리 (1시간 주기로 호출)."""
    db = await get_db()
    await db.execute("DELETE FROM requests         WHERE ts < datetime('now', '-30 days')")
    await db.execute("DELETE FROM findings         WHERE ts < datetime('now', '-30 days')")
    await db.execute("DELETE FROM pipeline_snapshots WHERE ts < datetime('now', '-90 days')")
    await db.execute("DELETE FROM engine_logs      WHERE ts < datetime('now', '-7 days')")
    await db.execute("PRAGMA incremental_vacuum")
    await db.commit()
    log.info("오래된 데이터 정리 완료")


async def insert_request(event: dict) -> None:
    """scan_result 이벤트 → requests + findings INSERT."""
    db = await get_db()
    rid = event.get("request_id") or str(event.get("id", ""))
    if not rid:
        return
    ts = event.get("ts") or ""
    try:
        await db.execute(
            """INSERT INTO requests
               (ts, request_id, provider, model, pipeline_action,
                raw_finding_count, effective_finding_count,
                total_text_len, target_count, elapsed_ms, cache_hit, dlp_applied)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(request_id) DO UPDATE SET
                   ts=excluded.ts,
                   provider=excluded.provider,
                   model=excluded.model,
                   pipeline_action=excluded.pipeline_action,
                   raw_finding_count=excluded.raw_finding_count,
                   effective_finding_count=excluded.effective_finding_count,
                   total_text_len=excluded.total_text_len,
                   target_count=excluded.target_count,
                   elapsed_ms=excluded.elapsed_ms,
                   cache_hit=excluded.cache_hit,
                   dlp_applied=excluded.dlp_applied""",
            (
                ts, rid,
                event.get("provider"), event.get("model"),
                event.get("pipeline_action", "pass"),
                event.get("raw_finding_count", event.get("finding_count", 0)),
                event.get("effective_finding_count", 0),
                event.get("total_text_len", 0),
                event.get("target_count", 0),
                event.get("elapsed_ms"),
                1 if event.get("cache_hit") else 0,
                event.get("dlp_applied", "pass"),
            ),
        )
        await db.execute("DELETE FROM findings WHERE request_id=?", (rid,))
        for f in event.get("findings", []):
            meta = f.get("metadata") or {}
            await db.execute(
                """INSERT INTO findings
                   (request_id, ts, stage, rule, severity, confidence,
                    suppressed, suppressed_reason, match_text, field_path, role, metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rid, ts,
                    f.get("stage"), f.get("rule"), f.get("severity"),
                    float(f.get("confidence", 0)),
                    1 if f.get("suppressed") else 0,
                    meta.get("suppressed_reason") or f.get("suppressed_reason"),
                    (f.get("match_text") or "")[:500],
                    f.get("field_path"), f.get("role"),
                    json.dumps(meta, ensure_ascii=False),
                ),
            )
        await db.commit()
    except Exception as e:
        log.debug(f"insert_request error: {e}")


async def update_dlp_applied(request_id: str, dlp_applied: str) -> None:
    """scan_applied 이벤트 → requests.dlp_applied UPDATE."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE requests SET dlp_applied=? WHERE request_id=?",
            (dlp_applied, request_id),
        )
        await db.commit()
    except Exception as e:
        log.debug(f"update_dlp_applied error: {e}")


async def insert_log(event: dict) -> None:
    """log 이벤트 → engine_logs INSERT."""
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO engine_logs (ts, level, message) VALUES (?,?,?)",
            (event.get("ts", ""), event.get("level", "INFO"), event.get("message", "")),
        )
        await db.commit()
    except Exception as e:
        log.debug(f"insert_log error: {e}")


async def insert_snapshot(stats: dict) -> None:
    """pipeline_snapshots INSERT."""
    db = await get_db()
    cache = stats.get("cache", {})
    slm   = stats.get("slm", {})
    acts  = {
        "pass":  stats.get("action_pass",  0),
        "alert": stats.get("action_alert", 0),
        "mask":  stats.get("action_mask",  0),
        "block": stats.get("action_block", 0),
    }
    try:
        await db.execute(
            """INSERT INTO pipeline_snapshots
               (ts, cache_hits, cache_misses,
                nms_suppressed, ml_suppressed, al_suppressed,
                slm_calls, slm_avg_ms,
                action_pass, action_alert, action_mask, action_block)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                stats.get("ts", ""),
                cache.get("hits",   0),
                cache.get("misses", 0),
                stats.get("nms_suppressed", 0),
                stats.get("ml_suppressed",  0),
                stats.get("al_suppressed",  0),
                slm.get("total_calls", 0),
                slm.get("avg_ms",      0),
                acts["pass"], acts["alert"], acts["mask"], acts["block"],
            ),
        )
        await db.commit()
    except Exception as e:
        log.debug(f"insert_snapshot error: {e}")
