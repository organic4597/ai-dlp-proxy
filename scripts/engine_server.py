#!/usr/bin/env python3
"""
DLP Engine Server — mitmproxy와 분리된 독립 프로세스.
Unix Domain Socket (UDS) + NDJSON 프로토콜로 통신.

파이프라인:
  Extractor → Regex Stage → (향후 sLM Stage)

실행:
    python3 scripts/engine_server.py                              # 기본 UDS
    python3 scripts/engine_server.py --sock /tmp/dlp-engine.sock  # 소켓 경로 변경
    python3 scripts/engine_server.py --tcp 4002                   # 폴백: TCP 모드

프로토콜 (NDJSON — 줄바꿈 구분 JSON):
  요청 → {"action":"scan", "id":1, "host":"...", "url":"...", "content_type":"...", "body":{...}}
  응답 ← {"ok":true, "id":1, "action":"alert", "findings":[...], ...}
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

# ── 엔진 임포트 ──────────────────────────────────────────────────────────────
_SRC_DIR = Path(__file__).parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from engine import extract, run_pipeline  # noqa: E402
from engine.pipeline import get_cache_stats, get_slm_stats  # noqa: E402
from engine.pipeline.control import load_control  # noqa: E402

# ── 로깅 설정 ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ENGINE] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dlp.engine")


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"


# 기본 UDS 소켓 경로
DEFAULT_SOCK = "/tmp/dlp-engine.sock"

# ── 통계 ─────────────────────────────────────────────────────────────────────
_stats = {"total": 0, "scanned": 0, "findings": 0, "errors": 0, "masked": 0}

# ── 이벤트 구독자 (TUI 등) ───────────────────────────────────────────────────
_subscribers: list[asyncio.Queue] = []

# ── 로그 구독자 (웹 대시보드 등) ─────────────────────────────────────────────
_log_subscribers: list[asyncio.Queue] = []
_log_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)


class _AsyncLogHandler(logging.Handler):
    """로그 레코드를 _log_queue에 넣어 log_subscribe 구독자에게 전달."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            _log_queue.put_nowait({
                "type": "log",
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "message": msg,
            })
        except Exception:
            pass


async def _log_fan_out() -> None:
    """_log_queue 드레인 → 모든 _log_subscribers에 fan-out."""
    while True:
        try:
            event = await asyncio.wait_for(_log_queue.get(), timeout=2.0)
            dead: list[asyncio.Queue] = []
            for q in _log_subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                if q in _log_subscribers:
                    _log_subscribers.remove(q)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            return


def _broadcast_event(event: dict) -> None:
    """모든 구독자에게 이벤트 전파. 큐가 가득 차면 오래된 항목 드롭."""
    dead: list[asyncio.Queue] = []
    for q in _subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            try:
                q.get_nowait()  # 오래된 항목 드롭
                q.put_nowait(event)
            except Exception:
                dead.append(q)
    for q in dead:
        _subscribers.remove(q)


# ── 요청 핸들러 ──────────────────────────────────────────────────────────────

def _action_from_findings(findings: list, threshold: float) -> str:
    effective = [
        f for f in findings
        if f.confidence >= threshold and not f.suppressed
    ]
    if not effective:
        return "pass"
    max_sev = max(f.severity.value for f in effective)
    if max_sev >= 4:
        return "mask"
    if max_sev >= 3:
        return "alert"
    return "alert"


def _finding_to_dict(f) -> dict:
    return {
        "stage": f.stage,
        "rule": f.rule,
        "severity": f.severity.label,
        "field_path": f.field_path,
        "role": f.role,
        "match_text": f.match_text,
        "match_start": f.match_start,
        "match_end": f.match_end,
        "context_before": f.context_before,
        "context_after": f.context_after,
        "confidence": f.confidence,
        "suppressed": f.suppressed,
        "history": f.history,
        "description": f.metadata.get("description", ""),
        "metadata": f.metadata,
    }


def _handle_scan(request: dict) -> dict:
    """scan 액션: 추출 + 파이프라인 실행."""
    host = request.get("host", "")
    url = request.get("url", "")
    content_type = request.get("content_type", "")
    body = request.get("body")
    msg_count = request.get("msg_count", 0)

    if body is None:
        return {"ok": True, "matched": False}

    # body → bytes
    if isinstance(body, dict):
        body_bytes = json.dumps(body, ensure_ascii=False).encode()
    elif isinstance(body, str):
        body_bytes = body.encode()
    else:
        return {"ok": False, "error": "body must be dict or str"}

    # 1) 추출
    parsed = extract(host, url, content_type, body_bytes)
    if parsed is None:
        return {"ok": True, "matched": False}

    # 2) 파이프라인 실행
    try:
        _ctrl = json.loads(Path("/tmp/dlp-control.json").read_text())
    except Exception:
        _ctrl = {}
    slm_enabled = bool(_ctrl.get("slm_enabled", False))
    control = load_control()

    # role 필터: skip_roles에 포함된 role은 스캔 대상에서 제외
    # 기본값: system(시스템 프롬프트), tool_def(함수 정의) 제외
    scan_targets = [
        t for t in parsed.targets
        if t.role not in control.skip_roles
    ]
    skipped_target_count = len(parsed.targets) - len(scan_targets)

    result = run_pipeline(scan_targets, slm_enabled=slm_enabled)
    effective_findings = result.effective_findings(control.confidence_threshold)

    # history 플래그 기준: 이전 턴 히스토리 finding 분리
    new_findings = [f for f in result.findings if not f.history]
    new_effective = [f for f in effective_findings if not f.history]
    protection_findings = list(result.findings)
    raw_finding_count = len(new_findings)
    effective_finding_count = len(new_effective)
    suppressed_finding_count = max(0, raw_finding_count - effective_finding_count)
    history_finding_count = len(protection_findings) - raw_finding_count

    return {
        "ok": True,
        "matched": True,
        "provider": parsed.provider,
        "model": parsed.model,
        "stream": parsed.stream,
        "msg_count": msg_count,
        "target_count": len(parsed.targets),
        "scan_target_count": len(scan_targets),
        "skipped_target_count": skipped_target_count,
        "skip_roles": sorted(control.skip_roles),
        "total_text_len": parsed.total_text_len,
        # 파이프라인 결과
        "pipeline_action": result.action.value,
        "protection_action": _action_from_findings(protection_findings, control.confidence_threshold),
        "pipeline_elapsed_ms": result.elapsed_ms,
        "finding_count": raw_finding_count,
        "raw_finding_count": raw_finding_count,
        "effective_finding_count": effective_finding_count,
        "suppressed_finding_count": suppressed_finding_count,
        "history_finding_count": history_finding_count,
        "protection_finding_count": len(protection_findings),
        "findings": [_finding_to_dict(f) for f in new_findings],
        "protection_findings": [_finding_to_dict(f) for f in protection_findings],
        "pipeline_summary": result.summary(),
        # TUI 전송 내용 표시용 — scan_targets만 (skip된 role 제외)
        "targets": [
            {
                "field_path": t.field_path,
                "role": t.role,
                "text": t.text,
            }
            for t in scan_targets
        ],
    }


# ── 클라이언트 핸들러 ─────────────────────────────────────────────────────────

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername") or "UDS"
    _logged_conn = False  # scan 시에만 CONN 로그 출력

    try:
        while True:
            line = await reader.readline()
            if not line:
                break

            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                _stats["errors"] += 1
                resp = {"ok": False, "error": f"JSON parse: {e}"}
                writer.write(json.dumps(resp, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
                continue

            req_id = request.get("id", "?")
            action = request.get("action", "scan")
            if action == "scan":
                _stats["total"] += 1
            t0 = time.monotonic()

            if action == "scan":
                if not _logged_conn:
                    log.info(f"{C.GREEN}[CONN]{C.RESET} {peer} (scan)")
                    _logged_conn = True
                resp = _handle_scan(request)
            elif action == "ping":
                resp = {"ok": True, "action": "pong"}
            elif action == "masked_inc":
                _stats["masked"] += 1
                resp = {"ok": True, "masked": _stats["masked"]}
            elif action == "applied_result":
                applied = str(request.get("dlp_applied", "pass") or "pass")
                resp = {"ok": True, "dlp_applied": applied}
                if _subscribers:
                    _broadcast_event({
                        "type": "scan_applied",
                        "id": req_id,
                        "dlp_applied": applied,
                    })
            elif action == "stats":
                resp = {"ok": True, **_stats, "cache": get_cache_stats(), "slm": get_slm_stats()}
            elif action == "log_subscribe":
                # 로그 스트림 구독 — 연결 유지하며 로그를 push
                lq: asyncio.Queue = asyncio.Queue(maxsize=1000)
                _log_subscribers.append(lq)
                ack2 = {"ok": True, "action": "log_subscribed", "id": req_id}
                writer.write(json.dumps(ack2).encode() + b"\n")
                await writer.drain()
                log.info(f"  {C.CYAN}[LOG-SUB]{C.RESET} 로그 구독자 추가 ({len(_log_subscribers)}명)")
                try:
                    while True:
                        event = await lq.get()
                        writer.write(json.dumps(event, ensure_ascii=False).encode() + b"\n")
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass
                finally:
                    if lq in _log_subscribers:
                        _log_subscribers.remove(lq)
                    log.info(f"  {C.DIM}[LOG-UNSUB]{C.RESET} 로그 구독자 해제 ({len(_log_subscribers)}명)")
                break
            elif action == "subscribe":
                # 이벤트 스트림 구독 — 연결 유지하며 이벤트를 push
                q: asyncio.Queue = asyncio.Queue(maxsize=500)
                _subscribers.append(q)
                ack = {"ok": True, "action": "subscribed"}
                ack["id"] = req_id
                writer.write(json.dumps(ack).encode() + b"\n")
                await writer.drain()
                log.info(f"  {C.CYAN}[SUB]{C.RESET} 구독자 추가 ({len(_subscribers)}명)")
                try:
                    while True:
                        event = await q.get()
                        writer.write(json.dumps(event, ensure_ascii=False).encode() + b"\n")
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass
                finally:
                    if q in _subscribers:
                        _subscribers.remove(q)
                    log.info(f"  {C.DIM}[UNSUB]{C.RESET} 구독자 해제 ({len(_subscribers)}명)")
                break  # subscribe 모드는 루프 탈출
            else:
                resp = {"ok": False, "error": f"unknown action: {action}"}

            elapsed = round((time.monotonic() - t0) * 1000, 2)
            resp["id"] = req_id
            resp["elapsed_ms"] = elapsed

            writer.write(json.dumps(resp, ensure_ascii=False).encode() + b"\n")
            await writer.drain()

            # 콘솔 로그
            if resp.get("matched"):
                _stats["scanned"] += 1
                prov = resp.get("provider", "?")
                model = resp.get("model", "?")
                fc = resp.get("raw_finding_count", resp.get("finding_count", 0))
                efc = resp.get("effective_finding_count", fc)
                pa = resp.get("pipeline_action", "pass")
                _stats["findings"] += fc

                if fc > 0:
                    action_c = {
                        "pass": C.GREEN, "alert": C.YELLOW,
                        "mask": C.RED, "block": C.RED,
                    }.get(pa, C.RESET)
                    log.info(
                        f"  #{req_id} {C.CYAN}{prov}{C.RESET} "
                        f"model={C.GREEN}{model}{C.RESET} "
                        f"{action_c}[{pa.upper()}]{C.RESET} "
                        f"findings={C.RED}{fc}{C.RESET}"
                        f" effective={C.YELLOW}{efc}{C.RESET} "
                        f"{C.DIM}{elapsed}ms{C.RESET}"
                    )
                    for f in resp.get("findings", []):
                        sev_c = {
                            "critical": C.RED, "high": C.MAGENTA,
                            "medium": C.YELLOW, "low": C.DIM,
                        }.get(f["severity"], C.RESET)
                        log.info(
                            f"    {sev_c}[{f['severity'].upper()}]{C.RESET} "
                            f"{f['rule']} conf={f['confidence']:.1f}: {f['match_text'][:60]!s} "
                            f"@ {C.DIM}{f['field_path']}{C.RESET}"
                        )
                else:
                    log.info(
                        f"  #{req_id} {C.CYAN}{prov}{C.RESET} "
                        f"model={C.GREEN}{model}{C.RESET} "
                        f"{C.GREEN}[PASS]{C.RESET} "
                        f"{C.DIM}{elapsed}ms{C.RESET}"
                    )
            elif not resp.get("ok"):
                _stats["errors"] += 1
                log.warning(f"  #{req_id} {C.RED}ERR{C.RESET}: {resp.get('error', '?')}")

            # 구독자에게 이벤트 브로드캐스트
            if _subscribers and resp.get("matched"):
                _broadcast_event({
                    "type": "scan_result",
                    "id": req_id,
                    "request_id": str(req_id),
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "provider": resp.get("provider"),
                    "model": resp.get("model"),
                    "stream": resp.get("stream"),
                    "msg_count": resp.get("msg_count", 0),
                    "target_count": resp.get("target_count", 0),
                    "total_text_len": resp.get("total_text_len", 0),
                    "pipeline_action": resp.get("pipeline_action"),
                    "finding_count": resp.get("finding_count", 0),
                    "raw_finding_count": resp.get("raw_finding_count", resp.get("finding_count", 0)),
                    "effective_finding_count": resp.get("effective_finding_count", 0),
                    "suppressed_finding_count": resp.get("suppressed_finding_count", 0),
                    "findings": resp.get("findings", []),
                    "elapsed_ms": elapsed,
                    "targets": resp.get("targets", []),
                    "messages": request.get("messages", []),  # inspect_traffic이 전달한 원본 메시지
                    "dlp_applied": "pass",
                })

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.error(f"  {C.RED}[ERR]{C.RESET} {peer} — {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass
        if _logged_conn:
            log.info(f"{C.DIM}[DISC]{C.RESET} {peer}")


# ── 메인 서버 ─────────────────────────────────────────────────────────────────

async def _is_socket_alive(sock_path: str, timeout: float = 0.5) -> bool:
    """기존 UDS 파일이 실제로 응답하는 서버인지 확인.

    True  → 다른 engine_server 인스턴스가 이미 살아있음 (중복 실행 차단)
    False → stale 소켓 (안전하게 unlink 가능)
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(sock_path),
            timeout=timeout,
        )
    except (FileNotFoundError, ConnectionRefusedError, OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(b'{"action":"ping"}\n')
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return bool(line)
    except Exception:
        return False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main(sock_path: str | None = None, tcp_port: int | None = None):
    if sock_path:
        # UDS 모드 — 기존 소켓이 있으면 살아있는 서버인지 먼저 확인
        if os.path.exists(sock_path):
            if await _is_socket_alive(sock_path):
                log.error(
                    f"[FATAL] 이미 다른 engine_server 인스턴스가 {sock_path} 에서 응답 중입니다. "
                    f"중복 실행을 방지하려고 종료합니다."
                )
                sys.exit(3)
            # 응답 없는 stale 소켓만 정리
            try:
                os.unlink(sock_path)
            except OSError:
                pass
        server = await asyncio.start_unix_server(
            handle_client, path=sock_path,
            limit=4 * 1024 * 1024,
        )
        os.chmod(sock_path, 0o666)  # 모든 사용자 접근 허용 (로컬 UDS는 안전)
        addr_str = f"UDS {sock_path}"
        test_cmd = f"echo '{{\"action\":\"ping\"}}' | socat - UNIX-CONNECT:{sock_path}"
    else:
        # TCP 폴백
        port = tcp_port or 4002
        server = await asyncio.start_server(
            handle_client, "127.0.0.1", port,
            limit=4 * 1024 * 1024,
        )
        addr_str = f"TCP 127.0.0.1:{port}"
        test_cmd = f"echo '{{\"action\":\"ping\"}}' | nc -w 1 -q 1 127.0.0.1 {port}"

    log.info(f"{C.BOLD}{'═' * 60}{C.RESET}")
    log.info(f"{C.BOLD}  DLP Engine Server 시작{C.RESET}")
    log.info(f"  주소      : {addr_str}")
    log.info(f"  프로토콜  : NDJSON (줄바꿈 구분 JSON)")
    log.info(f"  파이프라인: Regex Stage")
    log.info(f"  테스트    : {test_cmd}")
    log.info(f"{C.BOLD}{'═' * 60}{C.RESET}")

    # graceful shutdown
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    _force_count = 0

    def _signal_handler():
        nonlocal _force_count
        _force_count += 1
        if _force_count >= 2:
            log.info(f"{C.RED}[FORCE]{C.RESET} 강제 종료")
            os._exit(1)
        log.info(f"\n{C.YELLOW}[SHUTDOWN]{C.RESET} 종료 신호 수신... (한번 더 누르면 강제 종료)")
        log.info(
            f"  총 수신: {_stats['total']}  스캔: {_stats['scanned']}  "
            f"탐지: {_stats['findings']}  오류: {_stats['errors']}"
        )
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # 로그 fan-out 백그라운드 태스크 시작
    log_fan_task = asyncio.ensure_future(_log_fan_out())
    # _AsyncLogHandler 등록 (루프 시작 후 등록해야 put_nowait 안전)
    _log_handler = _AsyncLogHandler()
    _log_handler.setFormatter(logging.Formatter("%(asctime)s [ENGINE] %(message)s", "%H:%M:%S"))
    logging.getLogger().addHandler(_log_handler)

    async with server:
        await stop.wait()
        log_fan_task.cancel()
        server.close()
        await server.wait_closed()
        tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # UDS 소켓 파일 정리
    if sock_path and os.path.exists(sock_path):
        os.unlink(sock_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DLP Engine Server")
    parser.add_argument("--sock", default=DEFAULT_SOCK,
                        help=f"UDS 소켓 경로 (기본: {DEFAULT_SOCK})")
    parser.add_argument("--tcp", type=int, default=None,
                        help="TCP 모드로 실행할 포트 (UDS 대신)")
    args = parser.parse_args()

    if args.tcp:
        asyncio.run(main(tcp_port=args.tcp))
    else:
        asyncio.run(main(sock_path=args.sock))
