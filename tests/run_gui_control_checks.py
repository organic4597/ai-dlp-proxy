#!/usr/bin/env python3
"""TUI GUI 컨트롤 검증 스크립트.

목표:
1. GUI에 노출된 버튼/스위치/입력들이 올바른 내부 상태/제어 파일을 갱신하는지 검증
2. 제어 파일 기반 정책이 실제 엔진/프록시 동작에 반영되는지 검증

실행:
    source venv/bin/activate
    python tests/run_gui_control_checks.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "mitmproxy_lib"))

import scripts.engine_server as engine_server
import scripts.inspect_traffic as inspect_traffic
import scripts.tui as tui
from ai_dlp_proxy.engine.api.base import DLPTarget
from ai_dlp_proxy.engine.pipeline import run_pipeline
from ai_dlp_proxy.engine.pipeline import _cache_stats, _msg_cache
from ai_dlp_proxy.engine.pipeline.base import Action, PipelineResult
from textual.widgets import DataTable, Input, RichLog, Switch, TabbedContent


G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
W = "\033[0m"


def _control_defaults() -> dict:
    return {
        "regex_enabled": True,
        "asset_enabled": True,
        "slm_enabled": False,
        "mask_on_detect": False,
        "block_on_alert": False,
        "block_on_mask": False,
        "disabled_rules": [],
        "confidence_threshold": 0.5,
        "context_penalty_enabled": True,
        "allowlist": [],
    }


def _write_control(data: dict) -> None:
    tui._CONTROL_FILE.parent.mkdir(parents=True, exist_ok=True)
    tui._CONTROL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_control() -> dict:
    return json.loads(tui._CONTROL_FILE.read_text(encoding="utf-8"))


def _reset_pipeline_cache() -> None:
    _msg_cache.clear()
    _cache_stats["hits"] = 0
    _cache_stats["misses"] = 0


@contextmanager
def _backup_path(path: Path):
    existed = path.exists()
    payload = path.read_bytes() if existed else None
    try:
        yield
    finally:
        try:
            if existed:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload or b"")
            else:
                path.unlink(missing_ok=True)
        except Exception:
            pass


class _Result:
    def __init__(self):
        self.rows: list[tuple[bool, str, str]] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.rows.append((True, name, detail))
        print(f"  [{G}PASS{W}] {name}{(' — ' + detail) if detail else ''}")

    def fail(self, name: str, detail: str) -> None:
        self.rows.append((False, name, detail))
        print(f"  [{R}FAIL{W}] {name} — {detail}")

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        if cond:
            self.ok(name, detail)
        else:
            self.fail(name, detail or "조건 불만족")

    def summary(self) -> int:
        passed = sum(1 for ok, _, _ in self.rows if ok)
        failed = len(self.rows) - passed
        print(f"\n{'='*70}")
        color = G if failed == 0 else R
        print(f"  {color}GUI 검증 결과: {passed} passed, {failed} failed{W}")
        print(f"{'='*70}\n")
        return 0 if failed == 0 else 1


async def _wait_until(predicate, timeout: float = 3.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _richlog_text(widget: RichLog) -> str:
    return "\n".join(line.text for line in widget.lines)


def _phone_targets() -> list[DLPTarget]:
    return [DLPTarget("messages[0].content", "user", "연락처는 010-1234-5678 입니다")]


def _asset_targets() -> list[DLPTarget]:
    return [DLPTarget("messages[0].content", "user", "id_rsa 키 파일을 전송합니다")]


def _make_finding_event(request_id: str = "req-1", dlp_applied: str = "pass") -> dict:
    return {
        "id": request_id,
        "ts": "2026-04-18 12:00:00.000",
        "provider": "OpenAI",
        "model": "gpt-4o-mini",
        "msg_count": 1,
        "pipeline_action": "alert",
        "finding_count": 1,
        "raw_finding_count": 1,
        "effective_finding_count": 1,
        "suppressed_finding_count": 0,
        "elapsed_ms": 12,
        "target_count": 1,
        "total_text_len": 20,
        "targets": [
            {
                "field_path": "messages[0].content",
                "role": "user",
                "text": "연락처는 010-1234-5678 입니다",
            }
        ],
        "dlp_applied": dlp_applied,
        "findings": [
            {
                "stage": "regex",
                "rule": "kr_phone",
                "severity": "medium",
                "field_path": "messages[0].content",
                "role": "user",
                "match_text": "010-1234-5678",
                "match_start": 6,
                "match_end": 19,
                "context_before": "연락처는 ",
                "context_after": " 입니다",
                "confidence": 0.8,
                "suppressed": False,
                "metadata": {
                    "candidate_value": "01012345678",
                    "allowlisted": False,
                    "code_context": False,
                    "context_multiplier": 1.0,
                    "validator_floor": None,
                },
            }
        ],
    }


def _make_pass_event(model: str = "gpt-4o-mini", request_id: str = "pass-1") -> dict:
    return {
        "id": request_id,
        "ts": "2026-04-18 12:00:01.000",
        "provider": "OpenAI",
        "model": model,
        "msg_count": 2,
        "pipeline_action": "pass",
        "finding_count": 0,
        "raw_finding_count": 0,
        "effective_finding_count": 0,
        "suppressed_finding_count": 0,
        "elapsed_ms": 5,
        "target_count": 1,
        "total_text_len": 8,
        "targets": [
            {
                "field_path": "messages[0].content",
                "role": "user",
                "text": "hello",
            }
        ],
        "dlp_applied": "pass",
        "findings": [],
    }


def _make_policy_off_mask_event(request_id: str = "req-mask-pass") -> dict:
    return {
        "id": request_id,
        "ts": "2026-04-18 12:00:02.000",
        "provider": "OpenAI",
        "model": "gpt-4o-mini",
        "msg_count": 3,
        "pipeline_action": "mask",
        "finding_count": 1,
        "raw_finding_count": 1,
        "effective_finding_count": 1,
        "suppressed_finding_count": 0,
        "elapsed_ms": 9,
        "target_count": 1,
        "total_text_len": 20,
        "targets": [
            {
                "field_path": "messages[0].content",
                "role": "user",
                "text": "연락처는 010-1234-5678 입니다",
            }
        ],
        "dlp_applied": "pass",
        "findings": [
            {
                "stage": "regex",
                "rule": "kr_phone",
                "severity": "critical",
                "field_path": "messages[0].content",
                "role": "user",
                "match_text": "010-1234-5678",
                "match_start": 6,
                "match_end": 19,
                "context_before": "연락처는 ",
                "context_after": " 입니다",
                "confidence": 0.95,
                "suppressed": False,
                "metadata": {
                    "candidate_value": "01012345678",
                    "allowlisted": False,
                    "code_context": False,
                    "context_multiplier": 1.3,
                    "validator_floor": None,
                },
            }
        ],
    }


def _make_suppressed_nms_event(request_id: str = "req-suppressed") -> dict:
    return {
        "id": request_id,
        "ts": "2026-04-18 12:00:03.000",
        "provider": "OpenAI",
        "model": "gpt-4o-mini",
        "msg_count": 4,
        "pipeline_action": "pass",
        "finding_count": 1,
        "raw_finding_count": 1,
        "effective_finding_count": 0,
        "suppressed_finding_count": 1,
        "elapsed_ms": 11,
        "target_count": 1,
        "total_text_len": 24,
        "targets": [
            {
                "field_path": "messages[0].content",
                "role": "user",
                "text": "카드번호는 4111-1111-1111-1111",
            }
        ],
        "dlp_applied": "pass",
        "findings": [
            {
                "stage": "regex",
                "rule": "credit_card",
                "severity": "critical",
                "field_path": "messages[0].content",
                "role": "user",
                "match_text": "4111-1111-1111-1111",
                "match_start": 6,
                "match_end": 25,
                "context_before": "카드번호는 ",
                "context_after": "",
                "confidence": 1.0,
                "suppressed": True,
                "metadata": {
                    "suppressed_reason": "nms",
                    "suppressed_by_rule": "pem_private_key",
                    "suppressed_by_stage": "asset",
                    "suppressed_by_confidence": 1.0,
                    "suppressed_by_match_text": "4111-1111-1111-1111",
                },
            }
        ],
    }


def _make_long_content_event(request_id: str = "req-long") -> dict:
    match_text = "MATCH-CONTENT-LONG-4111-1111-1111-1111-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    before = "TARGET-START::CTX-BEFORE-START::" + ("left-segment-" * 8)
    after = ("right-segment-" * 8) + "::CTX-AFTER-END::TARGET-END"
    text = before + match_text + after
    match_start = len(before)
    match_end = match_start + len(match_text)
    return {
        "id": request_id,
        "ts": "2026-04-18 12:00:04.000",
        "provider": "OpenAI",
        "model": "gpt-4o-mini",
        "msg_count": 5,
        "pipeline_action": "alert",
        "finding_count": 1,
        "raw_finding_count": 1,
        "effective_finding_count": 1,
        "suppressed_finding_count": 0,
        "elapsed_ms": 13,
        "target_count": 1,
        "total_text_len": len(text),
        "targets": [
            {
                "field_path": "messages[0].content",
                "role": "user",
                "text": text,
            }
        ],
        "dlp_applied": "pass",
        "findings": [
            {
                "stage": "regex",
                "rule": "credit_card",
                "severity": "critical",
                "field_path": "messages[0].content",
                "role": "user",
                "match_text": match_text,
                "match_start": match_start,
                "match_end": match_end,
                "context_before": before,
                "context_after": after,
                "confidence": 0.99,
                "suppressed": False,
                "metadata": {
                    "candidate_value": match_text,
                    "allowlisted": False,
                    "code_context": False,
                    "context_multiplier": 1.3,
                    "validator_floor": 0.6,
                },
            }
        ],
    }


class _FakeRequest:
    def __init__(self, body_obj: dict):
        self.pretty_host = "api.openai.com"
        self.path = "/v1/chat/completions"
        self.method = "POST"
        self.pretty_url = "https://api.openai.com/v1/chat/completions"
        self.http_version = "HTTP/1.1"
        self.headers = {
            "content-type": "application/json",
            "content-length": "0",
        }
        self.content = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")


class _FakeFlow:
    def __init__(self, body_obj: dict):
        self.id = "flow-1"
        self.request = _FakeRequest(body_obj)
        self.response = None


class _FakeProc:
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.running = False
        self.proc = None
        self.returncode = None
        self.status = "대기"
        self.restarts = 0
        self.pid = None
        self.started_at = ""


class _FakeSup:
    def __init__(self):
        self.procs = {
            "engine": _FakeProc("Engine Server"),
            "mitm": _FakeProc("mitmproxy"),
        }
        self.killed: list[str] = []
        self.watched: list[str] = []

    async def _kill(self, ps):
        self.killed.append(ps.name)
        ps.running = False
        ps.proc = None

    async def _watch(self, key, ps):
        self.watched.append(key)
        ps.running = True

    async def stop(self):
        return None


async def _verify_runtime_controls(res: _Result) -> None:
    _reset_pipeline_cache()

    class _FakeReader:
        def __init__(self, payloads: list[dict]):
            self._lines = [json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n" for payload in payloads]

        async def readline(self) -> bytes:
            return self._lines.pop(0) if self._lines else b""

    class _FakeWriter:
        def __init__(self):
            self.output: list[bytes] = []
            self.closed = False

        def get_extra_info(self, _name: str):
            return "test-client"

        def write(self, data: bytes) -> None:
            self.output.append(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    saved_stats = dict(engine_server._stats)
    orig_handle_scan = engine_server._handle_scan
    try:
        engine_server._stats.update({"total": 0, "scanned": 0, "findings": 0, "errors": 0, "masked": 0})
        engine_server._handle_scan = lambda _request: {"ok": True, "matched": False}

        await engine_server.handle_client(
            _FakeReader([{"action": "stats", "id": 1}]),
            _FakeWriter(),
        )
        total_after_stats = engine_server._stats["total"]

        await engine_server.handle_client(
            _FakeReader([{"action": "scan", "id": 2, "body": "hello"}]),
            _FakeWriter(),
        )
        res.check(
            "runtime/engine internal stats 제외",
            total_after_stats == 0 and engine_server._stats["total"] == 1,
            f"after_stats={total_after_stats}, after_scan={engine_server._stats['total']}",
        )
    finally:
        engine_server._stats.clear()
        engine_server._stats.update(saved_stats)
        engine_server._handle_scan = orig_handle_scan

    ctrl = _control_defaults()
    _write_control(ctrl)
    result = run_pipeline(_phone_targets())
    res.check("runtime/regex_enabled ON baseline", any(f.rule == "kr_phone" for f in result.findings), "kr_phone 탐지")

    ctrl["regex_enabled"] = False
    _write_control(ctrl)
    _reset_pipeline_cache()
    result = run_pipeline(_phone_targets())
    res.check("runtime/regex_enabled OFF 적용", not result.findings, f"findings={len(result.findings)}")

    ctrl = _control_defaults()
    _write_control(ctrl)
    tui._ASSETS_FILE.unlink(missing_ok=True)
    seeded_assets = tui._read_assets()
    seeded_names = [str(asset.get("name", "")) for asset in seeded_assets if isinstance(asset, dict)]
    res.check("runtime/default assets seed", "SSH 키" in seeded_names and len(seeded_assets) >= 3,
              json.dumps(seeded_names, ensure_ascii=False))
    result = run_pipeline(_asset_targets())
    res.check("runtime/asset_enabled ON baseline", any(f.stage == "asset" for f in result.findings), "asset finding 존재")

    ctrl["asset_enabled"] = False
    _write_control(ctrl)
    _reset_pipeline_cache()
    result = run_pipeline(_asset_targets())
    res.check("runtime/asset_enabled OFF 적용", not any(f.stage == "asset" for f in result.findings), "asset finding 제거")

    captured_threshold: dict[str, object] = {}
    orig_extract = engine_server.extract
    orig_run_pipeline = engine_server.run_pipeline
    try:
        from ai_dlp_proxy.engine.pipeline.base import Finding, Severity

        def fake_extract_threshold(host, url, content_type, body_bytes):
            return SimpleNamespace(
                provider="OpenAI",
                model="gpt-4o-mini",
                stream=False,
                total_text_len=10,
                targets=[DLPTarget("messages[0].content", "user", "hello")],
            )

        def fake_run_pipeline_threshold(targets, slm_enabled=False):
            return PipelineResult(
                action=Action.ALERT,
                findings=[Finding(
                    stage="regex",
                    rule="kr_phone",
                    severity=Severity.MEDIUM,
                    field_path="messages[0].content",
                    role="user",
                    match_text="010-1234-5678",
                    match_start=0,
                    match_end=13,
                    context_before="",
                    context_after="",
                    confidence=0.8,
                    suppressed=False,
                    metadata={},
                )],
                elapsed_ms=0.1,
            )

        engine_server.extract = fake_extract_threshold
        engine_server.run_pipeline = fake_run_pipeline_threshold
        ctrl = _control_defaults()
        ctrl["confidence_threshold"] = 0.95
        _write_control(ctrl)
        out = engine_server._handle_scan({
            "host": "api.openai.com",
            "url": "https://api.openai.com/v1/chat/completions",
            "content_type": "application/json",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
            "msg_count": 1,
        })
        captured_threshold["effective"] = out.get("effective_finding_count")
        res.check("runtime/confidence_threshold 적용", out.get("effective_finding_count") == 0,
                  f"effective={out.get('effective_finding_count')}, threshold={ctrl['confidence_threshold']}")
    finally:
        engine_server.extract = orig_extract
        engine_server.run_pipeline = orig_run_pipeline

    ctrl = _control_defaults()
    ctrl["disabled_rules"] = ["kr_phone"]
    _write_control(ctrl)
    _reset_pipeline_cache()
    result = run_pipeline(_phone_targets())
    res.check("runtime/disabled_rules 적용", not any(f.rule == "kr_phone" for f in result.findings), "kr_phone 비활성")

    ctrl = _control_defaults()
    ctrl["allowlist"] = [{"rule": "kr_phone", "value": "010-1234-5678", "normalized": "01012345678"}]
    _write_control(ctrl)
    _reset_pipeline_cache()
    result = run_pipeline(_phone_targets())
    phone = next((f for f in result.findings if f.rule == "kr_phone"), None)
    res.check("runtime/allowlist 적용", phone is not None and phone.suppressed is True, f"suppressed={getattr(phone, 'suppressed', None)}")

    # slm_enabled는 engine_server가 run_pipeline에 전달하는지 검증
    captured: dict[str, object] = {}
    orig_extract = engine_server.extract
    orig_run_pipeline = engine_server.run_pipeline
    try:
        def fake_extract(host, url, content_type, body_bytes):
            return SimpleNamespace(
                provider="OpenAI",
                model="gpt-4o-mini",
                stream=False,
                total_text_len=10,
                targets=[DLPTarget("messages[0].content", "user", "hello")],
            )

        def fake_run_pipeline(targets, slm_enabled=False):
            captured["slm_enabled"] = slm_enabled
            return PipelineResult(action=Action.PASS, findings=[], elapsed_ms=0.1)

        engine_server.extract = fake_extract
        engine_server.run_pipeline = fake_run_pipeline
        ctrl = _control_defaults()
        ctrl["slm_enabled"] = True
        _write_control(ctrl)
        engine_server._handle_scan({
            "host": "api.openai.com",
            "url": "https://api.openai.com/v1/chat/completions",
            "content_type": "application/json",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
            "msg_count": 1,
        })
        res.check("runtime/slm_enabled 전달", captured.get("slm_enabled") is True, f"captured={captured.get('slm_enabled')}")
    finally:
        engine_server.extract = orig_extract
        engine_server.run_pipeline = orig_run_pipeline

    # inspect_traffic 정책 적용 검증
    orig_engine_request = inspect_traffic._engine_request
    orig_write_jsonl = inspect_traffic._write_jsonl
    orig_counter = inspect_traffic._request_counter
    try:
        async def fake_engine_request(payload: dict):
            if payload.get("action") == "masked_inc":
                return {"ok": True}
            return {
                "matched": True,
                "pipeline_action": "alert",
                "findings": [{
                    "rule": "kr_phone",
                    "match_text": "010-1234-5678",
                    "match_start": 6,
                    "match_end": 19,
                    "field_path": "messages[0].content",
                    "confidence": 0.9,
                    "suppressed": False,
                    "severity": "medium",
                }],
                "effective_finding_count": 1,
                "finding_count": 1,
                "target_count": 1,
                "total_text_len": 20,
                "elapsed_ms": 1.0,
            }

        inspect_traffic._engine_request = fake_engine_request
        inspect_traffic._write_jsonl = lambda *_args, **_kwargs: None
        inspect_traffic._request_counter = 0
        addon = inspect_traffic.InspectAddon()

        ctrl = _control_defaults()
        ctrl["mask_on_detect"] = True
        _write_control(ctrl)
        flow = _FakeFlow({"messages": [{"role": "user", "content": "연락처는 010-1234-5678 입니다"}]})
        await addon.request(flow)
        masked_text = json.loads(flow.request.content.decode("utf-8"))["messages"][0]["content"]
        res.check("runtime/mask_on_detect 적용", "[전화번호]" in masked_text and flow.response is None, masked_text)

        ctrl = _control_defaults()
        ctrl["block_on_alert"] = True
        _write_control(ctrl)
        flow = _FakeFlow({"messages": [{"role": "user", "content": "연락처는 010-1234-5678 입니다"}]})
        await addon.request(flow)
        res.check("runtime/block_on_alert 적용", flow.response is not None and flow.response.status_code == 403,
                  f"status={getattr(flow.response, 'status_code', None)}")

        async def fake_engine_request_mask(payload: dict):
            if payload.get("action") == "masked_inc":
                return {"ok": True}
            return {
                "matched": True,
                "pipeline_action": "mask",
                "findings": [{
                    "rule": "kr_phone",
                    "match_text": "010-1234-5678",
                    "match_start": 6,
                    "match_end": 19,
                    "field_path": "messages[0].content",
                    "confidence": 0.9,
                    "suppressed": False,
                    "severity": "medium",
                }],
                "effective_finding_count": 1,
                "finding_count": 1,
                "target_count": 1,
                "total_text_len": 20,
                "elapsed_ms": 1.0,
            }

        inspect_traffic._engine_request = fake_engine_request_mask
        ctrl = _control_defaults()
        _write_control(ctrl)
        flow = _FakeFlow({"messages": [{"role": "user", "content": "연락처는 010-1234-5678 입니다"}]})
        await addon.request(flow)
        passthrough_text = json.loads(flow.request.content.decode("utf-8"))["messages"][0]["content"]
        res.check(
            "runtime/policy off no masking",
            flow.response is None and passthrough_text == "연락처는 010-1234-5678 입니다",
            passthrough_text,
        )

        ctrl = _control_defaults()
        ctrl["block_on_mask"] = True
        _write_control(ctrl)
        flow = _FakeFlow({"messages": [{"role": "user", "content": "연락처는 010-1234-5678 입니다"}]})
        await addon.request(flow)
        res.check("runtime/block_on_mask 적용", flow.response is not None and flow.response.status_code == 403,
                  f"status={getattr(flow.response, 'status_code', None)}")
    finally:
        inspect_traffic._engine_request = orig_engine_request
        inspect_traffic._write_jsonl = orig_write_jsonl
        inspect_traffic._request_counter = orig_counter


async def _verify_tui_controls(res: _Result) -> None:
    temp_jsonl = Path(tempfile.gettempdir()) / "ai-dlp-proxy-gui-checks.jsonl"
    temp_jsonl.write_text("{}\n", encoding="utf-8")
    app = tui.DLPApp(sock="/tmp/nonexistent.sock", jsonl_path=str(temp_jsonl), supervise=False)

    async with app.run_test(notifications=True) as pilot:
        await pilot.pause()

        worker_ready = await _wait_until(
            lambda: {worker.group for worker in app.workers} >= {"engine-subscribe", "engine-poll"},
            timeout=2.5,
        )
        res.check(
            "tui/live workers active",
            worker_ready,
            str(sorted((worker.name, worker.group, worker.state.name) for worker in app.workers)),
        )

        # local switches
        sw = app.query_one("#sw-cap", Switch)
        sw.value = True
        await pilot.pause()
        res.check("tui/sw-cap ON", tui._CAPTURE_FLAG.exists(), str(tui._CAPTURE_FLAG))
        sw.value = False
        await pilot.pause()
        res.check("tui/sw-cap OFF", not tui._CAPTURE_FLAG.exists(), "capture flag removed")

        app.query_one("#sw-auto", Switch).value = False
        await pilot.pause()
        res.check("tui/sw-auto", app._auto is False, f"_auto={app._auto}")

        app.query_one("#sw-pass", Switch).value = False
        await pilot.pause()
        before = app.query_one("#ttable", DataTable).row_count
        app._one(_make_pass_event())
        after = app.query_one("#ttable", DataTable).row_count
        res.check("tui/sw-pass 필터", before == after, f"rows {before}->{after}")

        app.query_one("#sw-tg", Switch).value = False
        await pilot.pause()
        before = app.query_one("#ttable", DataTable).row_count
        app._one(_make_pass_event(model="gpt-5-mini"))
        after = app.query_one("#ttable", DataTable).row_count
        res.check("tui/sw-tg 필터", before == after, f"rows {before}->{after}")

        # settings -> control file
        app.query_one("#sw-regex", Switch).value = False
        await pilot.pause()
        res.check("tui/sw-regex 저장", _read_control().get("regex_enabled") is False, str(_read_control().get("regex_enabled")))

        app.query_one("#sw-asset", Switch).value = False
        await pilot.pause()
        res.check("tui/sw-asset 저장", _read_control().get("asset_enabled") is False, str(_read_control().get("asset_enabled")))

        app.query_one("#sw-slm", Switch).value = True
        await pilot.pause()
        res.check("tui/sw-slm 저장", _read_control().get("slm_enabled") is True, str(_read_control().get("slm_enabled")))

        # threshold input/save
        threshold_input = app.query_one("#ctrl-threshold-input", Input)
        threshold_input.value = "0.83"
        app._btn_threshold_save(None)
        await pilot.pause()
        res.check("tui/threshold 저장 버튼", abs(float(_read_control().get("confidence_threshold", 0)) - 0.83) < 1e-9,
                  str(_read_control().get("confidence_threshold")))
        threshold_input.value = "0.77"
        app._ctrl_threshold_submit(SimpleNamespace())
        await pilot.pause()
        res.check("tui/threshold Enter", abs(float(_read_control().get("confidence_threshold", 0)) - 0.77) < 1e-9,
                  str(_read_control().get("confidence_threshold")))

        # control switches
        app.query_one("#ctrl-sw-mask-on-detect", Switch).value = True
        await pilot.pause()
        res.check("tui/mask_on_detect 저장", _read_control().get("mask_on_detect") is True, str(_read_control().get("mask_on_detect")))

        app.query_one("#ctrl-sw-block-alert", Switch).value = True
        await pilot.pause()
        res.check("tui/block_on_alert 저장", _read_control().get("block_on_alert") is True, str(_read_control().get("block_on_alert")))

        app.query_one("#ctrl-sw-block-mask", Switch).value = True
        await pilot.pause()
        res.check("tui/block_on_mask 저장", _read_control().get("block_on_mask") is True, str(_read_control().get("block_on_mask")))

        # startup warning popup
        original_warning_reader = tui.get_runtime_warning_lines
        try:
            expected_warnings = [
                "[asset] sentence-transformers 미설치 — 키워드 전용 모드",
                "[SLM] 경고: CPU 전용 모드",
            ]
            tui.get_runtime_warning_lines = lambda: [
                "[asset] sentence-transformers 미설치 — 키워드 전용 모드",
                "[SLM] 경고: CPU 전용 모드",
            ]
            app.clear_notifications()
            app._refresh_startup_warnings(show_popup=True)
            await pilot.pause()
            notifications = list(app._notifications)
            res.check(
                "tui/startup warning popup",
                len(notifications) == 1
                and notifications[0].severity == "warning"
                and notifications[0].title == "런타임 경고"
                and notifications[0].message == "\n".join(expected_warnings)
                and app._startup_warnings == expected_warnings,
                f"notifications={[(n.title, n.severity, n.message) for n in notifications]}, warnings={app._startup_warnings}",
            )
            expired = await _wait_until(lambda: len(app._notifications) == 0, timeout=app._STARTUP_WARNING_TIMEOUT + 2.0)
            res.check("tui/startup warning auto-hide", expired, f"remaining={len(app._notifications)}")
        finally:
            tui.get_runtime_warning_lines = original_warning_reader
            app.clear_notifications()
            app._refresh_startup_warnings()
            await pilot.pause()

        # mask rule row toggle/save/button toggle/reset
        app._last_toggle_ts = 0.0
        app._mask_rule_row_selected(SimpleNamespace(row_key=SimpleNamespace(value="kr_phone")))
        await pilot.pause()
        res.check(
            "tui/mask-table row toggle",
            "kr_phone" in set(_read_control().get("disabled_rules", [])),
            str(_read_control().get("disabled_rules")),
        )
        app.query_one("#mask-edit-input", Input).value = "[연락처-마스킹]"
        app._btn_mask_save(None)
        await pilot.pause()
        res.check(
            "tui/mask-table save",
            _read_control().get("mask_templates", {}).get("kr_phone") == "[연락처-마스킹]",
            json.dumps(_read_control().get("mask_templates", {}), ensure_ascii=False),
        )
        app._last_toggle_ts = 0.0
        app._btn_mask_toggle(None)
        await pilot.pause()
        res.check("tui/mask-table toggle button", "kr_phone" not in set(_read_control().get("disabled_rules", [])), str(_read_control().get("disabled_rules")))
        app._btn_mask_reset(None)
        await pilot.pause()
        res.check(
            "tui/mask-table reset",
            "kr_phone" not in _read_control().get("mask_templates", {}),
            json.dumps(_read_control().get("mask_templates", {}), ensure_ascii=False),
        )

        # asset add modal + select/edit/delete
        before_assets = list(tui._read_assets())
        app._btn_asset_add(None)
        await pilot.pause()
        screen = app.screen
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-asset-cancel")))
        await pilot.pause()
        res.check("tui/btn-asset-cancel", tui._read_assets() == before_assets, json.dumps(tui._read_assets(), ensure_ascii=False))

        app._btn_asset_add(None)
        await pilot.pause()
        screen = app.screen
        screen.query_one("#asset-name", Input).value = "UI 테스트 자산"
        screen.query_one("#asset-sev").value = "critical"
        screen.query_one("#asset-keywords", Input).value = "ui_secret"
        screen.query_one("#asset-examples", Input).value = "테스트 자산을 보냅니다"
        screen.query_one("#asset-threshold", Input).value = "0.80"
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-asset-ok")))
        await pilot.pause()
        assets = tui._read_assets()
        res.check("tui/btn-asset-add", any(a.get("name") == "UI 테스트 자산" and a.get("severity") == "critical" for a in assets), json.dumps(assets, ensure_ascii=False))
        asset_id = next(a.get("id") for a in assets if a.get("name") == "UI 테스트 자산")
        app._asset_row_selected(SimpleNamespace(row_key=SimpleNamespace(value=asset_id)))
        await pilot.pause()
        res.check("tui/asset row select", app._selected_asset_id == asset_id, str(app._selected_asset_id))
        app._btn_asset_edit(None)
        await pilot.pause()
        screen = app.screen
        screen.query_one("#asset-name", Input).value = "UI 테스트 자산 수정"
        screen.query_one("#asset-sev").value = "medium"
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-asset-ok")))
        await pilot.pause()
        assets = tui._read_assets()
        edited_asset = next((a for a in assets if a.get("id") == asset_id), {})
        res.check(
            "tui/btn-asset-edit",
            edited_asset.get("name") == "UI 테스트 자산 수정" and edited_asset.get("severity") == "medium",
            json.dumps(edited_asset, ensure_ascii=False),
        )
        app._asset_row_selected(SimpleNamespace(row_key=SimpleNamespace(value=asset_id)))
        await pilot.pause()
        app._btn_asset_delete(None)
        await pilot.pause()
        assets = tui._read_assets()
        res.check("tui/asset delete", not any(a.get("id") == asset_id for a in assets), json.dumps(assets, ensure_ascii=False))

        # allowlist direct add modal
        before_allowlist = list(_read_control().get("allowlist", []))
        app._btn_allowlist_add(None)
        await pilot.pause()
        screen = app.screen
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-allowlist-cancel")))
        await pilot.pause()
        res.check("tui/btn-allowlist-cancel", _read_control().get("allowlist", []) == before_allowlist,
              json.dumps(_read_control().get("allowlist", []), ensure_ascii=False))

        app._btn_allowlist_add(None)
        await pilot.pause()
        screen = app.screen
        screen.query_one("#allowlist-rule").value = "email"
        screen.query_one("#allowlist-value", Input).value = "support@example.com"
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-allowlist-ok")))
        await pilot.pause()
        allowlist = _read_control().get("allowlist", [])
        res.check("tui/btn-allowlist-add", any(str(x.get("value", "")) == "support@example.com" and str(x.get("rule", "")) == "email" for x in allowlist if isinstance(x, dict)),
                  json.dumps(allowlist, ensure_ascii=False))
        allowlist_index = next(
            i for i, item in enumerate(allowlist)
            if isinstance(item, dict) and str(item.get("value", "")) == "support@example.com" and str(item.get("rule", "")) == "email"
        )
        app._allowlist_row_selected(SimpleNamespace(row_key=SimpleNamespace(value=str(allowlist_index))))
        await pilot.pause()
        res.check("tui/allowlist row select", app._selected_allowlist_index == allowlist_index, str(app._selected_allowlist_index))
        app._btn_allowlist_edit(None)
        await pilot.pause()
        screen = app.screen
        screen.query_one("#allowlist-rule").value = "email"
        screen.query_one("#allowlist-value", Input).value = "help@example.com"
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn-allowlist-ok")))
        await pilot.pause()
        allowlist = _read_control().get("allowlist", [])
        res.check(
            "tui/btn-allowlist-edit",
            any(str(x.get("value", "")) == "help@example.com" and str(x.get("rule", "")) == "email" for x in allowlist if isinstance(x, dict)),
            json.dumps(allowlist, ensure_ascii=False),
        )

        # finding/turn table interactions + selected allowlist add
        finding_event = _make_finding_event(request_id="traffic-1")
        app._one(finding_event)
        await pilot.pause()
        stats_bar = app.query_one(tui.StatsBar)
        res.check(
            "tui/traffic stats aggregate",
            stats_bar.total == 1 and stats_bar.scanned == 1 and stats_bar.findings == 1 and stats_bar.masked == 0,
            f"total={stats_bar.total}, scanned={stats_bar.scanned}, findings={stats_bar.findings}, masked={stats_bar.masked}",
        )
        app._sel(SimpleNamespace(row_key=SimpleNamespace(value="t1")))
        await pilot.pause()
        res.check("tui/ttable row select", len(app.query_one("#dlog", RichLog).lines) > 0, "turn detail rendered")
        copied: dict[str, str] = {}
        original_copy = app.copy_to_clipboard
        try:
            app.copy_to_clipboard = lambda text: copied.setdefault("text", text)
            app._btn_copy_sent(None)
            await pilot.pause()
        finally:
            app.copy_to_clipboard = original_copy
        res.check(
            "tui/copy sent text",
            "연락처는 010-1234-5678 입니다" in copied.get("text", ""),
            copied.get("text", ""),
        )

        policy_off_event = _make_policy_off_mask_event(request_id="traffic-2")
        app._one(policy_off_event)
        await pilot.pause()
        app._sel(SimpleNamespace(row_key=SimpleNamespace(value="t2")))
        await pilot.pause()
        res.check(
            "tui/policy off shows alert",
            app._tk.turns[1].wa == "alert"
            and "정책이 꺼져 있어 원문 그대로 전달" in app._sent_text_cache
            and "[전화번호]" not in app._sent_text_cache,
            app._sent_text_cache,
        )

        app._apply_live_applied_update("traffic-1", "masked")
        await pilot.pause()
        app._sel(SimpleNamespace(row_key=SimpleNamespace(value="t1")))
        await pilot.pause()
        stats_bar = app.query_one(tui.StatsBar)
        masked_text = tui.DEFAULT_MASK_TEMPLATES.get("kr_phone", "")
        res.check(
            "tui/scan_applied sent text",
            masked_text in app._sent_text_cache and "실제 적용: 마스킹 후 전달" in app._sent_text_cache and app._tk.turns[0].wa == "mask",
            app._sent_text_cache,
        )
        res.check(
            "tui/traffic masked aggregate",
            stats_bar.masked == 1,
            f"masked={stats_bar.masked}, action={app._tk.turns[0].wa}",
        )

        app.query_one("#sw-pass", Switch).value = True
        await pilot.pause()
        suppressed_event = _make_suppressed_nms_event(request_id="traffic-3")
        app._one(suppressed_event)
        await pilot.pause()
        app._sel(SimpleNamespace(row_key=SimpleNamespace(value="t3")))
        await pilot.pause()
        detail_text = _richlog_text(app.query_one("#dlog", RichLog))
        stats_bar = app.query_one(tui.StatsBar)
        res.check(
            "tui/nms suppressed final pass",
            app._tk.turns[2].wa == "pass"
            and stats_bar.findings == 2
            and "억제=1" in detail_text
            and "억제된 탐지 1건 — 최종 전송은 원문 PASS" in app._sent_text_cache,
            detail_text,
        )

        app._sel_finding(SimpleNamespace(row_key=SimpleNamespace(value="f0")))
        await pilot.pause()
        res.check("tui/ftable row select", app._selected_finding is not None,
              "selected_finding set")

        app._sel_finding(SimpleNamespace(row_key=SimpleNamespace(value="f2")))
        await pilot.pause()
        selected_pair = app._selected_finding
        selected_event, selected_finding = selected_pair if selected_pair else ({}, {})
        res.check(
            "tui/suppressed finding detail consistent",
            selected_pair is not None
            and selected_finding.get("rule") == "credit_card"
            and app._display_action_for_event(selected_event) == "pass"
            and app._suppressed_finding_count(selected_event) == 1
            and (selected_finding.get("metadata") or {}).get("suppressed_reason") == "nms",
            json.dumps(selected_finding, ensure_ascii=False),
        )

        long_event = _make_long_content_event(request_id="traffic-4")
        app._one(long_event)
        await pilot.pause()
        app._sel(SimpleNamespace(row_key=SimpleNamespace(value="t4")))
        await pilot.pause()
        long_turn_detail = _richlog_text(app.query_one("#dlog", RichLog))
        res.check(
            "tui/turn detail shows full content",
            "TARGET-START::CTX-BEFORE-START::" in long_turn_detail
            and "::CTX-AFTER-END::TARGET-END" in long_turn_detail
            and "MATCH-CONTENT-LONG-4111-1111-1111-1111-ABCDEFGHIJKLMNOPQRSTUVWXYZ" in long_turn_detail,
            long_turn_detail,
        )

        app.query_one(TabbedContent).active = "tab-findings"
        await pilot.pause()
        app._sel_finding(SimpleNamespace(row_key=SimpleNamespace(value="f3")))
        await pilot.pause()
        long_finding_detail = _richlog_text(app.query_one("#fdetail", RichLog))
        res.check(
            "tui/finding detail shows full content",
            "MATCH-CONTENT-LONG-4111-1111-1111-1111" in long_finding_detail
            and "TARGET-START::CTX-BEFORE-START::" in long_finding_detail
            and "::CTX-AFTER-END::TARGET-END" in long_finding_detail
            and "치환 미리보기" in long_finding_detail
            and "[카드번호]" in long_finding_detail,
            long_finding_detail,
        )

        before_count = len(_read_control().get("allowlist", []))
        app._btn_allowlist_add_selected(None)
        await pilot.pause()
        after_allowlist = _read_control().get("allowlist", [])
        res.check("tui/btn-allowlist-add-selected", len(after_allowlist) == before_count + 1,
                  json.dumps(after_allowlist, ensure_ascii=False))

        allowlist_delete_index = next(
            i for i, item in enumerate(after_allowlist)
            if isinstance(item, dict) and str(item.get("value", "")) == "help@example.com" and str(item.get("rule", "")) == "email"
        )
        app._allowlist_row_selected(SimpleNamespace(row_key=SimpleNamespace(value=str(allowlist_delete_index))))
        await pilot.pause()
        app._btn_allowlist_delete(None)
        await pilot.pause()
        res.check(
            "tui/allowlist delete",
            not any(
                isinstance(item, dict) and str(item.get("value", "")) == "help@example.com" and str(item.get("rule", "")) == "email"
                for item in _read_control().get("allowlist", [])
            ),
            json.dumps(_read_control().get("allowlist", []), ensure_ascii=False),
        )

        # clear buttons
        elog = app.query_one("#elog", RichLog)
        elog.write("hello")
        app._btn_clear_log(None)
        await pilot.pause()
        res.check("tui/btn-clear-log", len(elog.lines) == 0, f"lines={len(elog.lines)}")

        Path(app._jsonl).write_text('{"type":"request"}\n', encoding="utf-8")
        app._btn_clear_traffic(None)
        await pilot.pause()
        res.check("tui/btn-clear-traffic rows", app.query_one("#ttable", DataTable).row_count == 0 and app.query_one("#ftable", DataTable).row_count == 0,
                  f"ttable={app.query_one('#ttable', DataTable).row_count}, ftable={app.query_one('#ftable', DataTable).row_count}")
        res.check("tui/btn-clear-traffic file", Path(app._jsonl).read_text(encoding="utf-8") == "", "jsonl cleared")

        app._one(_make_finding_event())
        await pilot.pause()
        app._btn_clear_findings(None)
        await pilot.pause()
        res.check("tui/btn-clear-findings", app.query_one("#ftable", DataTable).row_count == 0, f"rows={app.query_one('#ftable', DataTable).row_count}")

        # process button 핸들러 연결 (가벼운 dispatch 검증)
        app._sup = _FakeSup()
        app._btn_restart_engine(None)
        app._btn_restart_mitm(None)
        app._btn_stop_engine(None)
        app._btn_stop_mitm(None)
        app._btn_start_engine(None)
        app._btn_start_mitm(None)
        await pilot.pause()
        res.check("tui/process button dispatch", set(app._sup.killed) >= {"Engine Server", "mitmproxy"} and set(app._sup.watched) >= {"engine", "mitm"},
                  f"killed={app._sup.killed}, watched={app._sup.watched}")


async def _verify_quit_shortcut(res: _Result) -> None:
    temp_jsonl = Path(tempfile.gettempdir()) / "ai-dlp-proxy-gui-checks-quit.jsonl"
    temp_jsonl.write_text("", encoding="utf-8")
    app = tui.DLPApp(sock="/tmp/nonexistent.sock", jsonl_path=str(temp_jsonl), supervise=False)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("ctrl+q")
        quit_ok = await _wait_until(lambda: not app.is_running, timeout=2.0)
        res.check("tui/ctrl+q quit", quit_ok, f"is_running={app.is_running}")


async def _verify_process_buttons_e2e(res: _Result) -> None:
    fixture = ROOT / "tests" / "fixtures" / "dummy_service.py"
    with tempfile.TemporaryDirectory(prefix="ai-dlp-proc-") as tmpdir:
        tmp = Path(tmpdir)
        temp_jsonl = tmp / "traffic.jsonl"
        temp_jsonl.write_text("", encoding="utf-8")
        temp_sock = tmp / "engine.sock"
        log_dir = tmp / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        engine_events = tmp / "engine-events.jsonl"
        mitm_events = tmp / "mitm-events.jsonl"

        sup = tui.ProcessSupervisor(
            sock=str(temp_sock),
            log_dir=log_dir,
            addon_path=str(fixture),
            on_event=None,
        )
        sup._running = True
        sup.procs = {
            "engine": tui.ProcState(
                "Engine Dummy",
                [sys.executable, str(fixture), "--name", "engine", "--events-file", str(engine_events)],
                str(ROOT),
                restart_delay=0.2,
            ),
            "mitm": tui.ProcState(
                "mitmproxy Dummy",
                [sys.executable, str(fixture), "--name", "mitm", "--events-file", str(mitm_events), "-p", "49123"],
                str(ROOT),
                restart_delay=0.2,
            ),
        }

        app = tui.DLPApp(sock=str(temp_sock), jsonl_path=str(temp_jsonl), supervise=False)
        app._sup = sup

        async with app.run_test() as pilot:
            await pilot.pause()

            app._btn_start_engine(None)
            app._btn_start_mitm(None)
            started = await _wait_until(
                lambda: sup.procs["engine"].running and sup.procs["mitm"].running,
                timeout=5.0,
            )
            await pilot.pause()
            res.check(
                "tui/process start e2e",
                started and sup.procs["engine"].pid is not None and sup.procs["mitm"].pid is not None,
                f"engine_pid={sup.procs['engine'].pid}, mitm_pid={sup.procs['mitm'].pid}",
            )

            engine_pid_1 = sup.procs["engine"].pid
            mitm_pid_1 = sup.procs["mitm"].pid

            app._btn_restart_engine(None)
            app._btn_restart_mitm(None)
            restarted = await _wait_until(
                lambda: sup.procs["engine"].running and sup.procs["mitm"].running and
                sup.procs["engine"].pid not in (None, engine_pid_1) and
                sup.procs["mitm"].pid not in (None, mitm_pid_1),
                timeout=8.0,
            )
            await pilot.pause()
            res.check(
                "tui/process restart e2e",
                restarted,
                f"engine_pid={sup.procs['engine'].pid}, mitm_pid={sup.procs['mitm'].pid}",
            )

            app._btn_stop_engine(None)
            app._btn_stop_mitm(None)
            stopped = await _wait_until(
                lambda: not sup.procs["engine"].running and not sup.procs["mitm"].running and
                not sup.procs["engine"].enabled and not sup.procs["mitm"].enabled,
                timeout=5.0,
            )
            await pilot.pause()
            res.check(
                "tui/process stop e2e",
                stopped,
                f"engine_running={sup.procs['engine'].running}, mitm_running={sup.procs['mitm'].running}",
            )

        await _wait_until(
            lambda: len([row for row in _read_jsonl(engine_events) if row.get("event") == "start"]) >= 2
            and len([row for row in _read_jsonl(engine_events) if row.get("event") == "stop"]) >= 2
            and len([row for row in _read_jsonl(mitm_events) if row.get("event") == "start"]) >= 2
            and len([row for row in _read_jsonl(mitm_events) if row.get("event") == "stop"]) >= 2,
            timeout=3.0,
        )

        engine_rows = _read_jsonl(engine_events)
        mitm_rows = _read_jsonl(mitm_events)
        engine_starts = [row for row in engine_rows if row.get("event") == "start"]
        engine_stops = [row for row in engine_rows if row.get("event") == "stop"]
        mitm_starts = [row for row in mitm_rows if row.get("event") == "start"]
        mitm_stops = [row for row in mitm_rows if row.get("event") == "stop"]
        res.check(
            "tui/process lifecycle logs",
            len(engine_starts) >= 2 and len(engine_stops) >= 2 and len(mitm_starts) >= 2 and len(mitm_stops) >= 2,
            f"engine start/stop={len(engine_starts)}/{len(engine_stops)}, mitm start/stop={len(mitm_starts)}/{len(mitm_stops)}",
        )


async def _amain() -> int:
    print(f"\n{'='*70}")
    print("  GUI 컨트롤 검증")
    print(f"{'='*70}")

    res = _Result()

    with tempfile.TemporaryDirectory(prefix="ai-dlp-gui-checks-") as tmpdir:
        orig_capture_flag = tui._CAPTURE_FLAG
        tui._CAPTURE_FLAG = Path(tmpdir) / "capture-next"
        try:
            with ExitStack() as stack:
                stack.enter_context(_backup_path(tui._CONTROL_FILE))
                stack.enter_context(_backup_path(tui._ASSETS_FILE))

                _write_control(_control_defaults())
                tui._ASSETS_FILE.unlink(missing_ok=True)
                tui._CAPTURE_FLAG.unlink(missing_ok=True)

                print(f"\n{Y}▶ 런타임 정책 검증{W}")
                await _verify_runtime_controls(res)

                _write_control(_control_defaults())
                tui._ASSETS_FILE.unlink(missing_ok=True)
                tui._CAPTURE_FLAG.unlink(missing_ok=True)

                print(f"\n{Y}▶ TUI 위젯/핸들러 검증{W}")
                await _verify_tui_controls(res)

                print(f"\n{Y}▶ TUI 종료 단축키 검증{W}")
                await _verify_quit_shortcut(res)

                print(f"\n{Y}▶ 프로세스 버튼 e2e 검증{W}")
                await _verify_process_buttons_e2e(res)
        finally:
            tui._CAPTURE_FLAG = orig_capture_flag

    return res.summary()


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())