#!/usr/bin/env python3
"""
AI DLP Proxy — TUI Monitor (Textual 기반)

기능:
  - 유저 턴 기반 트래픽 그룹핑 (실시간 + 히스토리)
  - DLP 탐지 결과 (심각도/규칙/신뢰도)
  - JSON 패킷 캡처 on/off
  - 파이프라인/표시/로깅 설정 패널
  - 엔진 연결 상태 모니터링
  - 프로세스 감시자: engine_server · mitmdump 자동 재시작

실행:
    python3 scripts/tui.py                       # engine + mitmproxy 자동 시작/감시
    python3 scripts/tui.py --no-supervisor       # 감시자 비활성화 (외부 실행 사용)
    python3 scripts/tui.py --sock /tmp/dlp-engine.sock
"""

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

# ── 경로 설정 ────────────────────────────────────────────────────────────────
_BASE = Path(__file__).parent.parent
_LOG_DIR = _BASE / "logs"
_DEFAULT_SOCK = "/tmp/dlp-engine.sock"
_CAPTURE_FLAG = Path("/tmp/dlp-capture-next")
_CAPTURE_OUT = _LOG_DIR / "captured_packet.json"
_CONTROL_FILE = Path("/tmp/dlp-control.json")   # inspect_traffic이 읽는 제어 파일

_CTRL_DEFAULTS: dict = {
    "regex_enabled":  True,
    "slm_enabled":    False,
    "mask_on_detect": False,
    "block_on_alert": False,
    "block_on_mask":  False,
    "disabled_rules": [],
}

def _patch_control(key: str | None = None, value: object = None) -> None:
    """제어 파일을 읽어 key/value를 변경 후 다시 씀. key=None 이면 기본값으로 초기화."""
    try:
        try:
            data: dict = json.loads(_CONTROL_FILE.read_text())
        except Exception:
            data = dict(_CTRL_DEFAULTS)
        if key is not None:
            data[key] = value
        _CONTROL_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── 색상 ─────────────────────────────────────────────────────────────────────
SEV_S = {"critical": "bold red", "high": "magenta", "medium": "yellow", "low": "dim"}
ACT_S  = {"pass": "green", "alert": "yellow", "mask": "bold red", "block": "bold red reverse"}
ACT_LB = {"pass": "PASS", "alert": "ALERT", "mask": "MASKED", "block": "BLOCK"}

# ── 마스킹 치환 템플릿 (inspect_traffic.py 동일) ─────────────────────────────
_MASK_TEMPLATES: dict[str, str] = {
    "kr_rrn": "[주민등록번호]", "kr_phone": "[전화번호]",
    "credit_card": "[카드번호]", "us_ssn": "[SSN]",
    "email": "[이메일]", "kr_passport": "[여권번호]",
    "kr_driver_license": "[운전면허]", "aws_access_key": "[AWS_KEY]",
    "aws_secret_key": "[AWS_SECRET]", "api_key_assignment": "[API_KEY]",
    "pem_private_key": "[PRIVATE_KEY]", "jwt_token": "[JWT]",
    "github_pat": "[GH_TOKEN]", "person_name": "[이름]",
    "address": "[주소]", "organization": "[기관]",
    "date_of_birth": "[생년월일]", "account_number": "[계좌번호]",
    "ip_address": "[IP주소]", "device_id": "[기기ID]",
    "medical_info": "[의료정보]", "biometric": "[생체정보]",
    "slm_pii": "[개인정보]",
}

def _simulate_mask(text: str, findings: list[dict], field_path: str) -> str:
    """findings를 이용해 text에 마스킹 시뮬레이션 (오프셋 역순 치환)."""
    relevant = [f for f in findings if f.get("field_path") == field_path]
    if not relevant:
        return text
    for f in sorted(relevant, key=lambda x: x.get("match_start", 0), reverse=True):
        repl = _MASK_TEMPLATES.get(f.get("rule", ""), "[REDACTED]")
        start = f.get("match_start", 0)
        end = f.get("match_end", 0)
        if start < 0 or end <= start or end > len(text):
            mt = f.get("match_text", "")
            if mt:
                text = text.replace(mt, repl, 1)
        else:
            text = text[:start] + repl + text[end:]
    return text


class _ClickToggleTable(DataTable):
    """단일 클릭에도 RowSelected를 발생시키는 DataTable.

    DataTable._on_click 대신 오버라이드. prevent_default()로 부모의
    _on_click 실행을 차단하고, highlight_click 없이 항상 RowSelected 발생.
    """

    async def _on_click(self, event: events.Click) -> None:
        event.prevent_default()  # DataTable._on_click 실행 차단
        event.stop()             # 버블링 차단 (빈 공간 클릭 시 TabbedContent 탭 전환 방지)
        meta = event.style.meta
        if "row" not in meta or "column" not in meta:
            return
        row_index = meta["row"]
        if row_index < 0 or row_index >= self.row_count:
            return
        self._set_hover_cursor(True)
        self.cursor_coordinate = Coordinate(row_index, meta["column"])
        self._post_selected_message()
        self._scroll_cursor_into_view(animate=True)


def _trunc(s: str, n: int = 6) -> str:
    """n자 초과 시 말줄임표(…) 처리."""
    return s[:n] + "…" if len(s) > n else s


# ══════════════════════════════════════════════════════════════════════════════
# 프로세스 감시자
# ══════════════════════════════════════════════════════════════════════════════

class ProcState:
    """감시 대상 프로세스 상태."""
    def __init__(self, name: str, cmd: list[str], cwd: str, restart_delay: float = 3.0):
        self.name = name
        self.cmd = cmd
        self.cwd = cwd
        self.restart_delay = restart_delay
        self.proc: asyncio.subprocess.Process | None = None
        self.pid: int | None = None
        self.running = False
        self.restarts = 0
        self.started_at: str = ""
        self.status = "대기"   # 대기 / 실행 중 / 재시작 중 / 중지
        self.enabled = True


class ProcessSupervisor:
    """engine_server + mitmdump 를 자동 시작/감시/재시작하는 비동기 감시자."""

    def __init__(self, sock: str, log_dir: Path, addon_path: str, on_event=None):
        self._sock = sock
        self._log_dir = log_dir
        self._addon = addon_path
        self._on_event = on_event  # callable(name, msg) — TUI 로그 콜백
        self._venv = str(Path(sys.executable).parent)

        engine_cmd = [sys.executable, str(Path(__file__).parent / "engine_server.py"),
                      "--sock", sock]
        mitm_cmd = [
            str(Path(self._venv) / "mitmdump"),
            "--listen-host", "0.0.0.0",
            "-p", "4001",
            "--set", "connection_strategy=lazy",  # pre-connect Bad Gateway 방지
            "-s", addon_path,
        ]

        self.procs: dict[str, ProcState] = {
            "engine": ProcState("Engine Server", engine_cmd, str(_BASE)),
            "mitm":   ProcState("mitmproxy",    mitm_cmd,   str(_BASE)),
        }
        self._tasks: list[asyncio.Task] = []
        self._running = False

    def _emit(self, name: str, msg: str):
        if self._on_event:
            self._on_event(name, msg)

    async def start(self):
        self._running = True
        for key, ps in self.procs.items():
            t = asyncio.create_task(self._watch(key, ps), name=f"sup-{key}")
            self._tasks.append(t)

    async def stop(self):
        self._running = False
        for ps in self.procs.values():
            ps.enabled = False
            await self._kill(ps)
        for t in self._tasks:
            t.cancel()

    async def restart(self, key: str):
        ps = self.procs.get(key)
        if not ps:
            return
        self._emit(key, f"[yellow]수동 재시작 요청[/]")
        await self._kill(ps)
        # _watch 루프가 알아서 재시작함

    async def _kill(self, ps: ProcState):
        if ps.proc and ps.proc.returncode is None:
            try:
                ps.proc.terminate()
                try:
                    await asyncio.wait_for(ps.proc.wait(), timeout=4.0)
                except asyncio.TimeoutError:
                    ps.proc.kill()
                    await ps.proc.wait()
            except ProcessLookupError:
                pass
        ps.proc = None
        ps.pid = None
        ps.running = False

    async def _watch(self, key: str, ps: ProcState):
        """한 프로세스를 무한 감시. 종료 시 restart_delay 후 재시작."""
        log_file = self._log_dir / f"{key}.log"
        while self._running and ps.enabled:
            ps.status = "시작 중"
            self._emit(key, f"[green]시작:[/] {' '.join(ps.cmd)}")
            try:
                with open(log_file, "ab") as lf:
                    ps.proc = await asyncio.create_subprocess_exec(
                        *ps.cmd,
                        cwd=ps.cwd,
                        stdout=lf,
                        stderr=lf,
                        env={**os.environ, "PYTHONUNBUFFERED": "1"},
                    )
                ps.pid = ps.proc.pid
                ps.running = True
                ps.started_at = datetime.now().strftime("%H:%M:%S")
                ps.status = "실행 중"
                self._emit(key, f"[green]실행 중[/] PID={ps.pid}")
                ret = await ps.proc.wait()
                ps.running = False
                ps.pid = None
                if not self._running or not ps.enabled:
                    ps.status = "중지"
                    return
                ps.restarts += 1
                ps.status = "재시작 중"
                self._emit(key, f"[yellow]종료 (exitcode={ret}) — {ps.restart_delay}초 후 재시작[/]")
            except FileNotFoundError as e:
                ps.running = False
                ps.status = "오류"
                self._emit(key, f"[red]실행 파일 없음: {e}[/]")
                return
            except Exception as e:
                ps.running = False
                ps.status = "오류"
                self._emit(key, f"[red]오류: {e}[/]")
            await asyncio.sleep(ps.restart_delay)


# ══════════════════════════════════════════════════════════════════════════════
# 유저 턴 그룹핑
# ══════════════════════════════════════════════════════════════════════════════

class Turn:
    __slots__ = ("id", "ts", "model", "mc", "reqs", "fc", "wa")
    _R = {"pass": 0, "alert": 1, "mask": 2, "block": 3}

    def __init__(self, tid: int, ts: str, model: str, mc: int):
        self.id = tid
        self.ts = ts
        self.model = model
        self.mc = mc
        self.reqs: list[dict] = []
        self.fc = 0
        self.wa = "pass"

    def add(self, ev: dict):
        self.reqs.append(ev)
        self.fc += ev.get("finding_count") or 0
        pa = ev.get("pipeline_action") or "pass"
        if self._R.get(pa, 0) > self._R.get(self.wa, 0):
            self.wa = pa


class TurnTracker:
    def __init__(self):
        self.turns: list[Turn] = []
        self._prev = -1

    def ingest(self, ev: dict) -> Turn:
        mc = ev.get("msg_count") or 0
        if not self.turns or mc > self._prev:
            t = Turn(len(self.turns) + 1, ev.get("ts", ""),
                     ev.get("model") or "?", mc)
            self.turns.append(t)
        else:
            t = self.turns[-1]
        t.add(ev)
        if mc > 0:
            self._prev = mc
        return t


# ══════════════════════════════════════════════════════════════════════════════
# 위젯
# ══════════════════════════════════════════════════════════════════════════════

class StatsBar(Static):
    total = reactive(0)
    scanned = reactive(0)
    findings = reactive(0)
    masked = reactive(0)
    engine_ok = reactive(False)
    mitm_ok = reactive(False)
    turns = reactive(0)

    def render(self) -> str:
        eng  = "[green]●[/]" if self.engine_ok else "[red]●[/]"
        mitm = "[green]●[/]" if self.mitm_ok  else "[red]●[/]"
        return (
            f"  [bold]턴[/] {self.turns}  "
            f"[bold]요청[/] {self.total}  "
            f"[bold]스캔[/] {self.scanned}  "
            f"[bold]탐지[/] [red]{self.findings}[/]  "
            f"[bold]마스킹[/] [cyan]{self.masked}[/]  "
            f"│  Engine {eng}  mitm {mitm}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 메인 App
# ══════════════════════════════════════════════════════════════════════════════

class DLPApp(App):
    TITLE = "AI DLP Proxy Monitor"
    SUB_TITLE = "실시간 트래픽 감시 · DLP 파이프라인"

    CSS = """
    Screen { layout: vertical; }
    #stats-bar { height: 1; background: $surface; padding: 0 1; }
    #main { height: 1fr; }

    /* 툴바 */
    .tab-toolbar { height: 3; background: $surface; align: right middle; padding: 0 1; }
    .toolbar-title { width: 1fr; color: $text-muted; content-align: left middle; height: 3; }
    .toolbar-btn { min-width: 8; height: 3; }

    /* 트래픽 */
    #hsplit { height: 1fr; }
    #tlist { width: 52; min-width: 42; border-right: tall $surface-lighten-2; }
    #ttable { height: 1fr; overflow-x: hidden; }
    #act-legend { height: 1; padding: 0 1; background: $surface; color: $text-muted; }
    #darea { width: 1fr; }
    #detail-tabs { height: 1fr; }
    #dlog { height: 1fr; }
    #dsent { height: 1fr; }

    /* 탐지 */
    #fsplit { height: 1fr; }
    #flist { width: 54; min-width: 48; border-right: tall $surface-lighten-2; }
    #ftable { height: 1fr; overflow-x: hidden; }
    #fdetail-area { width: 1fr; }
    #fdetail { height: 1fr; }

    /* 로그 */
    #elog { height: 1fr; }

    /* 설정 */
    #settings-scroll { padding: 1 2; }
    .card {
        background: $surface;
        border: round $primary-background-darken-2;
        padding: 1 2;
        margin: 0 0 1 0;
        height: auto;
    }
    .card-title {
        text-style: bold;
        color: $text;
        margin: 0 0 1 0;
        height: 1;
    }
    .opt-row {
        height: 3;
        padding: 0 0 0 1;
        align: left middle;
    }
    .opt-row Label {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }
    .opt-desc {
        height: 1;
        color: $text-disabled;
        padding: 0 0 0 3;
        margin: 0 0 1 0;
    }
    .info-row {
        height: 1;
        padding: 0 0 0 1;
    }
    .info-key { width: 14; color: $text-disabled; }
    .info-val { width: 1fr; }

    /* 프로세스 패널 */
    #proc-scroll { padding: 1 2; }
    .proc-card {
        background: $surface;
        border: round $primary-background-darken-2;
        padding: 1 2;
        margin: 0 0 1 0;
        height: auto;
    }
    .proc-title {
        text-style: bold;
        height: 1;
        margin: 0 0 1 0;
    }
    .proc-row {
        height: 1;
        padding: 0 0 0 1;
    }
    .proc-key { width: 10; color: $text-disabled; }
    .proc-val { width: 1fr; }
    .proc-btn-row {
        height: 3;
        align: left middle;
        padding: 0 0 0 1;
        margin: 1 0 0 0;
    }
    Button { margin: 0 1 0 0; min-width: 12; }

    /* 제어 탭 */
    #ctrl-scroll { padding: 1 2; }
    .ctrl-card {
        background: $surface;
        border: round $primary-background-darken-2;
        padding: 1 2;
        margin: 0 0 1 0;
        height: auto;
    }
    .ctrl-title {
        text-style: bold;
        height: 1;
        margin: 0 0 1 0;
    }
    .ctrl-badge {
        height: 1;
        content-align: right middle;
        color: $text-disabled;
    }
    /* 실시간 패킷 큐 */
    #ctrl-queue-split { height: 26; }
    #ctrl-queue-left { width: 1fr; border-right: tall $surface-lighten-2; }
    #ctrl-qtable { height: 1fr; }
    #ctrl-queue-right { width: 54; min-width: 40; }
    #ctrl-qdetail { height: 1fr; }
    /* 마스킹 규칙 */
    #mask-table { height: 14; }
    .mask-badge {
        height: 1;
        color: $text-disabled;
        padding: 0 0 0 1;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "종료"),
        Binding("c", "toggle_capture", "캡처 토글"),
        Binding("r", "reload", "새로고침"),
        Binding("1", "tab('tab-traffic')",  "트래픽",  show=True),
        Binding("2", "tab('tab-findings')", "탐지",    show=True),
        Binding("3", "tab('tab-control')",  "제어",    show=True),
        Binding("4", "tab('tab-procs')",    "프로세스", show=True),
        Binding("5", "tab('tab-settings')", "설정",    show=True),
        Binding("6", "tab('tab-log')",      "로그",    show=True),
    ]

    def __init__(self, sock: str, jsonl_path: str | None = None, supervise: bool = True):
        super().__init__()
        self._sock = sock
        self._jsonl = jsonl_path or str(_LOG_DIR / "traffic.jsonl")
        self._tk = TurnTracker()
        self._auto = True
        self._show_pass = True
        self._show_tg = False
        self._finding_rows: dict[str, tuple[dict, dict]] = {}  # row_key → (ev, finding)
        self._supervise = supervise
        addon = str(_BASE / "scripts" / "inspect_traffic.py")
        self._sup = ProcessSupervisor(
            sock=sock,
            log_dir=_LOG_DIR,
            addon_path=addon,
            on_event=self._sup_event,
        ) if supervise else None

    # ── compose ───────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsBar(id="stats-bar")
        with TabbedContent(id="main"):
            with TabPane("트래픽", id="tab-traffic"):
                with Horizontal(id="hsplit"):
                    with Vertical(id="tlist"):
                        with Horizontal(classes="tab-toolbar"):
                            yield Label("트래픽", classes="toolbar-title")
                            yield Button("클리어", id="btn-clear-traffic", classes="toolbar-btn")
                        yield DataTable(id="ttable", cursor_type="row")
                        yield Label(
                            "[green]PASS[/] 정상통과  "
                            "[yellow]ALERT[/] 탐지됨  "
                            "[bold cyan]MASKED[/] PII마스킹  "
                            "[bold red]BLOCK[/] 차단",
                            id="act-legend",
                        )
                    with Vertical(id="darea"):
                        with TabbedContent(id="detail-tabs"):
                            with TabPane("탐지 정보", id="tab-detail-info"):
                                yield RichLog(id="dlog", highlight=True, markup=True, wrap=True)
                            with TabPane("전송 내용", id="tab-detail-sent"):
                                yield RichLog(id="dsent", highlight=True, markup=True, wrap=True)
            with TabPane("탐지 목록", id="tab-findings"):
                with Horizontal(id="fsplit"):
                    with Vertical(id="flist"):
                        with Horizontal(classes="tab-toolbar"):
                            yield Label("탐지목록", classes="toolbar-title")
                            yield Button("클리어", id="btn-clear-findings", classes="toolbar-btn")
                        yield DataTable(id="ftable", cursor_type="row")
                    with Vertical(id="fdetail-area"):
                        yield RichLog(id="fdetail", highlight=True, markup=True, wrap=True)
            with TabPane("제어", id="tab-control"):
                with VerticalScroll(id="ctrl-scroll"):
                    # ── 마스킹 규칙 ────────────────────────────────────────
                    with Vertical(classes="ctrl-card"):
                        yield Label("🎭 마스킹 규칙", classes="ctrl-title")
                        yield Label("행 클릭 → 규칙 활성/비활성 토글 | 연두색 탐지된 PII를 치환 텍스트로 교체합니다.", classes="mask-badge")
                        yield _ClickToggleTable(id="mask-table", cursor_type="row")
                    # ── 액션 정책 ──────────────────────────────────────────
                    with Vertical(classes="ctrl-card"):
                        yield Label("🚦 탐지 시 액션 정책", classes="ctrl-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("[cyan]탐지 시 본문 마스킹[/] 후 통과")
                            yield Switch(id="ctrl-sw-mask-on-detect", value=False)
                        yield Label("탐지된 PII를 [치환 텍스트]로 교체 후 LLM에 전달 (Content-Length 자동 재계산)", classes="opt-desc")
                        with Horizontal(classes="opt-row"):
                            yield Label("[yellow]ALERT[/] 탐지 시 요청 차단")
                            yield Switch(id="ctrl-sw-block-alert", value=False)
                        yield Label("마스킹 비활성화 시 ALERT 이상 탐지를 403으로 차단", classes="opt-desc")
                        with Horizontal(classes="opt-row"):
                            yield Label("[bold red]MASK[/] 탐지 시 요청 차단")
                            yield Switch(id="ctrl-sw-block-mask", value=False)
                        yield Label("마스킹 비활성화 시 MASK/BLOCK 탐지를 403으로 차단", classes="opt-desc")
                    # ── 실시간 패킷 큐 ────────────────────────────────────
                    with Vertical(classes="ctrl-card"):
                        with Horizontal():
                            yield Label("📡 실시간 패킷 결정 이력", classes="ctrl-title")
                            yield Label("최근 200건", classes="ctrl-badge")
                        with Horizontal(id="ctrl-queue-split"):
                            with Vertical(id="ctrl-queue-left"):
                                yield DataTable(id="ctrl-qtable", cursor_type="row")
                            with Vertical(id="ctrl-queue-right"):
                                yield RichLog(id="ctrl-qdetail", highlight=True, markup=True, wrap=True)
            with TabPane("프로세스", id="tab-procs"):
                with VerticalScroll(id="proc-scroll"):
                    # engine 카드
                    with Vertical(id="proc-card-engine", classes="proc-card"):
                        yield Label("⚙️  Engine Server", classes="proc-title")
                        with Horizontal(classes="proc-row"):
                            yield Label("상태", classes="proc-key")
                            yield Label("대기", id="proc-status-engine", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("PID", classes="proc-key")
                            yield Label("-", id="proc-pid-engine", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("재시작", classes="proc-key")
                            yield Label("0회", id="proc-restart-engine", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("시각", classes="proc-key")
                            yield Label("-", id="proc-since-engine", classes="proc-val")
                        with Horizontal(classes="proc-btn-row"):
                            yield Button("재시작", id="btn-restart-engine", variant="warning")
                            yield Button("중지",   id="btn-stop-engine",   variant="error")
                            yield Button("시작",   id="btn-start-engine",  variant="success")
                    # mitm 카드
                    with Vertical(id="proc-card-mitm", classes="proc-card"):
                        yield Label("🔀 mitmproxy", classes="proc-title")
                        with Horizontal(classes="proc-row"):
                            yield Label("상태", classes="proc-key")
                            yield Label("대기", id="proc-status-mitm", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("PID", classes="proc-key")
                            yield Label("-", id="proc-pid-mitm", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("재시작", classes="proc-key")
                            yield Label("0회", id="proc-restart-mitm", classes="proc-val")
                        with Horizontal(classes="proc-row"):
                            yield Label("시각", classes="proc-key")
                            yield Label("-", id="proc-since-mitm", classes="proc-val")
                        with Horizontal(classes="proc-btn-row"):
                            yield Button("재시작", id="btn-restart-mitm", variant="warning")
                            yield Button("중지",   id="btn-stop-mitm",   variant="error")
                            yield Button("시작",   id="btn-start-mitm",  variant="success")
            with TabPane("설정", id="tab-settings"):
                with VerticalScroll(id="settings-scroll"):
                    # ── 캡처 카드 ──
                    with Vertical(classes="card"):
                        yield Label("📦 캡처", classes="card-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("JSON 패킷 캡처 (다음 1개)")
                            yield Switch(id="sw-cap", value=_CAPTURE_FLAG.exists())
                        yield Label("다음 요청의 전체 헤더+바디를 JSON으로 저장합니다", classes="opt-desc")
                    # ── 파이프라인 카드 ──
                    with Vertical(classes="card"):
                        yield Label("🔍 파이프라인", classes="card-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("Regex Stage")
                            yield Switch(id="sw-regex", value=True)
                        yield Label("정규식 기반 개인정보 탐지 (주민번호·카드번호 등 13개 규칙)", classes="opt-desc")
                        with Horizontal(classes="opt-row"):
                            yield Label("sLM Stage")
                            yield Switch(id="sw-slm", value=False)
                        yield Label("소형 언어모델 보완 탐지 (이름·주소 등 문맥 PII) — Qwen2.5-1.5B", classes="opt-desc")
                    # ── 표시 카드 ──
                    with Vertical(classes="card"):
                        yield Label("🖥️  표시", classes="card-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("자동 스크롤")
                            yield Switch(id="sw-auto", value=True)
                        with Horizontal(classes="opt-row"):
                            yield Label("PASS 이벤트 표시")
                            yield Switch(id="sw-pass", value=True)
                        yield Label("탐지 없는 정상 요청도 트래픽 탭에 표시", classes="opt-desc")
                        with Horizontal(classes="opt-row"):
                            yield Label("타이틀 생성 요청 표시")
                            yield Switch(id="sw-tg", value=False)
                        yield Label("gpt-5-mini 세션 제목 생성 요청을 포함", classes="opt-desc")
                    # ── 연결 정보 카드 ──
                    with Vertical(classes="card"):
                        yield Label("🔗 연결 정보", classes="card-title")
                        with Horizontal(classes="info-row"):
                            yield Label("Engine", classes="info-key")
                            yield Label(f"{self._sock}", classes="info-val")
                        with Horizontal(classes="info-row"):
                            yield Label("JSONL", classes="info-key")
                            yield Label(f"{self._jsonl}", classes="info-val")
                        with Horizontal(classes="info-row"):
                            yield Label("캡처 파일", classes="info-key")
                            yield Label(f"{_CAPTURE_OUT}", classes="info-val")
            with TabPane("엔진 로그", id="tab-log"):
                with Vertical():
                    with Horizontal(classes="tab-toolbar"):
                        yield Label("엔진 로그", classes="toolbar-title")
                        yield Button("클리어", id="btn-clear-log", classes="toolbar-btn")
                    yield RichLog(id="elog", highlight=True, markup=True, wrap=True)
        yield Footer()

    # ── mount ─────────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        tt = self.query_one("#ttable", DataTable)
        tt.add_column("턴",   width=5)
        tt.add_column("시각",  width=8)
        tt.add_column("모델",  width=16)
        tt.add_column("요청",  width=5)
        tt.add_column("탐지",  width=5)
        tt.add_column("액션",  width=9)
        ft = self.query_one("#ftable", DataTable)
        ft.add_column("시각",   width=8)
        ft.add_column("심각도", width=8)
        ft.add_column("규칙",   width=16)
        ft.add_column("신뢰도", width=5)
        ft.add_column("모델",   width=9)
        # 제어 탭 — 패킷 큐 테이블
        qt = self.query_one("#ctrl-qtable", DataTable)
        qt.add_columns("시각", "모델", "대상", "탐지", "액션", "결정")
        # 제어 탭 — 마스킹 규칙 테이블 (placeholder)
        mt = self.query_one("#mask-table", DataTable)
        mt.add_column("규칙",       key="rule",   width=22)
        mt.add_column("심각도",     key="sev",    width=10)
        mt.add_column("치환 텍스트", key="repl",   width=18)
        mt.add_column("상태",       key="status", width=10)
        self._init_mask_rules()
        self._init_control_file()
        self._load_history()
        self._subscribe()
        self._poll()
        if self._sup:
            self._start_supervisor()
            self._poll_procs()

    async def on_unmount(self) -> None:
        if self._sup:
            await self._sup.stop()

    # ── 감시자 시작/상태 폴링 ─────────────────────────────────────────────────

    @work(exclusive=True)
    async def _start_supervisor(self):
        await self._sup.start()
        # watch 태스크들은 supervisor 내부에서 영속 실행됨

    @work(exclusive=True)
    async def _poll_procs(self):
        """2초마다 프로세스 카드 UI 갱신."""
        while True:
            await asyncio.sleep(2)
            if not self._sup:
                return
            for key, ps in self._sup.procs.items():
                try:
                    status_lbl = self.query_one(f"#proc-status-{key}", Label)
                    pid_lbl    = self.query_one(f"#proc-pid-{key}",    Label)
                    rst_lbl    = self.query_one(f"#proc-restart-{key}", Label)
                    since_lbl  = self.query_one(f"#proc-since-{key}",  Label)

                    color = "green" if ps.running else ("yellow" if "중" in ps.status else "red")
                    status_lbl.update(f"[{color}]{ps.status}[/]")
                    pid_lbl.update(str(ps.pid) if ps.pid else "-")
                    rst_lbl.update(f"{ps.restarts}회")
                    since_lbl.update(ps.started_at or "-")
                except Exception:
                    pass
            # StatsBar engine/mitm 상태 반영
            try:
                bar = self.query_one(StatsBar)
                if self._sup:
                    bar.engine_ok = self._sup.procs["engine"].running
                    bar.mitm_ok   = self._sup.procs["mitm"].running
            except Exception:
                pass

    def _sup_event(self, key: str, msg: str):
        """감시자 이벤트 → 엔진 로그 탭에 출력. async context에서 직접 호출됨."""
        name = self._sup.procs[key].name if self._sup else key
        # call_later: Textual 이벤트 루프에서 안전하게 스케줄
        self.call_later(self._lg, f"[bold][Supervisor/{name}][/] {msg}")

    # ── 제어 탭 ───────────────────────────────────────────────────────────────

    # (inspect_traffic._MASK_TEMPLATES와 동기화) 규칙명 → (severity, 치환 텍스트)
    _MASK_RULES_DATA: list[tuple[str, str, str]] = [
        ("kr_rrn",            "critical", "[주민등록번호]"),
        ("credit_card",       "critical", "[카드번호]"),
        ("us_ssn",            "critical", "[SSN]"),
        ("aws_access_key",    "critical", "[AWS_KEY]"),
        ("aws_secret_key",    "critical", "[AWS_SECRET]"),
        ("pem_private_key",   "critical", "[PRIVATE_KEY]"),
        ("github_pat",        "critical", "[GH_TOKEN]"),
        ("kr_passport",       "high",     "[여권번호]"),
        ("kr_driver_license", "high",     "[운전면허]"),
        ("jwt_token",         "high",     "[JWT]"),
        ("api_key_assignment","high",     "[API_KEY]"),
        ("kr_phone",          "medium",   "[전화번호]"),
        ("email",             "low",      "[이메일]"),
    ]

    def _mask_rule_row(self, rule: str, sev: str, replacement: str, enabled: bool) -> tuple:
        """DataTable에 적재할 행 튜플. enabled 여부로 색상 구분."""
        status = "[green bold]✅ ON[/]" if enabled else "[dim]⚫ OFF[/]"
        name_col = rule if enabled else f"[dim]{rule}[/]"
        repl_col = replacement if enabled else f"[dim]{replacement}[/]"
        return (
            name_col,
            f"[{SEV_S.get(sev, '')}]{sev.upper()}[/]",
            repl_col,
            status,
        )

    # 메모리 내 disabled_rules 상태 (파일 read/write 경쟁 방지)
    _disabled_rules: set = set()

    def _init_mask_rules(self):
        self._disabled_rules = set(self._read_control().get("disabled_rules", []))
        mt = self.query_one("#mask-table", DataTable)
        for rule, sev, repl in self._MASK_RULES_DATA:
            mt.add_row(*self._mask_rule_row(rule, sev, repl, rule not in self._disabled_rules), key=rule)

    def _refresh_mask_table(self):
        """disabled_rules 변경 후 테이블 갱신.
        remove_row+add_row로 layout을 강제 갱신해 실제 터미널에서도 시각적으로 반영됨.
        _disabled_rules 메모리 상태 사용 (파일 재읽기 없음).
        """
        mt = self.query_one("#mask-table", DataTable)
        cursor_row = mt.cursor_coordinate.row  # 커서 위치 저장
        self._refreshing = True
        mt.show_cursor = False
        try:
            for rule, sev, repl in self._MASK_RULES_DATA:
                enabled = rule not in self._disabled_rules
                vals = self._mask_rule_row(rule, sev, repl, enabled)
                if rule in mt.rows:
                    mt.remove_row(rule)
                mt.add_row(*vals, key=rule)
        finally:
            mt.show_cursor = True
            self._refreshing = False
        # 커서 위치 복원
        if mt.row_count > 0:
            mt.move_cursor(row=min(cursor_row, mt.row_count - 1), animate=False)

    _last_toggle_ts: float = 0.0  # 더블 토글 방지
    _refreshing: bool = False     # _refresh_mask_table 중 RowSelected 차단

    @on(DataTable.RowSelected, "#mask-table")
    def _toggle_mask_rule(self, e: DataTable.RowSelected):
        """클릭/Enter → disabled_rules 토글 (150ms 디바운스로 더블 토글 방지)."""
        if self._refreshing:
            return
        now = time.monotonic()
        if now - self._last_toggle_ts < 0.15:
            self._lg(f"[dim][mask] debounce skip: {e.row_key.value!r}[/]")
            return
        self._last_toggle_ts = now
        rule_key = str(e.row_key.value)
        if rule_key in self._disabled_rules:
            self._disabled_rules.discard(rule_key)
            flag = True
        else:
            self._disabled_rules.add(rule_key)
            flag = False
        self._lg(f"[cyan][mask] toggle: {rule_key!r} → {'ON' if flag else 'OFF'} (disabled={sorted(self._disabled_rules)})[/]")
        _patch_control("disabled_rules", list(self._disabled_rules))
        self._refresh_mask_table()
        self._lg(f"[{'green' if flag else 'dim'}]{rule_key} 마스킹 {'ON' if flag else 'OFF'}[/]")

    def _init_control_file(self):
        """제어 파일 초기화 — 없으면 기본값으로 생성, 있으면 스위치 동기화."""
        if not _CONTROL_FILE.exists():
            _patch_control()
        # 제어 파일 → 스위치 값 동기화
        ctrl = self._read_control()
        try:
            self.query_one("#ctrl-sw-mask-on-detect", Switch).value = bool(ctrl.get("mask_on_detect", False))
            self.query_one("#ctrl-sw-block-alert", Switch).value = bool(ctrl.get("block_on_alert", False))
            self.query_one("#ctrl-sw-block-mask", Switch).value = bool(ctrl.get("block_on_mask", False))
            # 설정 탭 스위치도 동기화
            self.query_one("#sw-regex", Switch).value = bool(ctrl.get("regex_enabled", True))
            self.query_one("#sw-slm", Switch).value = bool(ctrl.get("slm_enabled", False))
        except Exception:
            pass

    def _read_control(self) -> dict:
        try:
            return json.loads(_CONTROL_FILE.read_text())
        except Exception:
            return {"regex_enabled": True, "slm_enabled": False,
                    "mask_on_detect": False, "disabled_rules": [],
                    "block_on_alert": False, "block_on_mask": False}

    # 패킷 큐 행 보관 (최근 200건) → (row_key, ev_dict)
    _ctrl_queue_rows: list = []

    def _ctrl_add_packet(self, ev: dict):
        """실시간 패킷을 제어 탭 큐 테이블에 추가."""
        try:
            qt = self.query_one("#ctrl-qtable", DataTable)
        except Exception:
            return
        pa = ev.get("pipeline_action") or "pass"
        fc = ev.get("finding_count") or 0
        ctrl = self._read_control()
        decided = "blocked" if (
            (pa in ("mask", "block") and ctrl.get("block_on_mask")) or
            (pa == "alert" and ctrl.get("block_on_alert"))
        ) else "pass"
        decided_markup = "[bold red]✗ 차단[/]" if decided == "blocked" else "[green]✓ 허용[/]"

        rk = f"q{len(self._ctrl_queue_rows)}"
        self._ctrl_queue_rows.append((rk, ev))
        if len(self._ctrl_queue_rows) > 200:
            old_rk, _ = self._ctrl_queue_rows.pop(0)
            if old_rk in qt.rows:
                qt.remove_row(old_rk)

        qt.add_row(
            _sts(ev.get("ts", "")),
            (ev.get("model") or "?")[:16],
            str(ev.get("target_count", 0)),
            f"[red]{fc}[/]" if fc else "0",
            f"[{ACT_S.get(pa, '')}]{pa.upper()}[/]",
            decided_markup,
            key=rk,
        )
        if self._auto:
            qt.move_cursor(row=qt.row_count - 1)

    @on(DataTable.RowSelected, "#ctrl-qtable")
    def _sel_ctrl_packet(self, e: DataTable.RowSelected):
        rk = str(e.row_key.value)
        ev = next((ev for k, ev in self._ctrl_queue_rows if k == rk), None)
        if ev is None:
            return
        d = self.query_one("#ctrl-qdetail", RichLog)
        d.clear()
        pa = ev.get("pipeline_action") or "pass"
        fc = ev.get("finding_count") or 0
        d.write("[bold]═══ 패킷 상세 ═══[/]")
        d.write(f"  시각   : {ev.get('ts', '')}")
        d.write(f"  모델   : [green]{ev.get('model', '?')}[/]")
        d.write(f"  제공자 : {ev.get('provider', '?')}")
        d.write(f"  대상   : {ev.get('target_count', 0)}개  {ev.get('total_text_len', 0):,}자")
        d.write(f"  액션   : [{ACT_S.get(pa, '')}]{pa.upper()}[/]  탐지={fc}")
        d.write(f"  스캔   : [dim]{ev.get('elapsed_ms', 0)}ms[/]")
        if fc:
            d.write("")
            d.write("[bold]── 탐지 목록 ──[/]")
            for f in ev.get("findings", []):
                sev = f.get("severity") or "?"
                d.write(f"  [{SEV_S.get(sev, '')}]{sev.upper()}[/] {f.get('rule', '?')} "
                        f"conf={f.get('confidence', 0):.1f}")
                d.write(f"    {f.get('match_text', '')!r}")
                d.write(f"    [dim]{f.get('field_path', '')}[/]")

    @on(Switch.Changed, "#sw-regex")
    def _sw_regex(self, e: Switch.Changed):
        _patch_control("regex_enabled", e.value)
        self._lg(f"[{'green' if e.value else 'yellow'}]Regex Stage {'ON' if e.value else 'OFF'}[/]")

    @on(Switch.Changed, "#sw-slm")
    def _sw_slm(self, e: Switch.Changed):
        _patch_control("slm_enabled", e.value)
        self._lg(f"[{'green' if e.value else 'yellow'}]sLM Stage {'ON' if e.value else 'OFF'}[/]")

    @on(Switch.Changed, "#ctrl-sw-mask-on-detect")
    def _ctrl_sw_mask_on_detect(self, e: Switch.Changed):
        _patch_control("mask_on_detect", e.value)
        self._lg(
            f"[{'cyan' if e.value else 'dim'}]마스킹 {'활성화 — 탐지된 PII를 치환 후 전달' if e.value else '비활성화'}[/]"
        )

    @on(Switch.Changed, "#ctrl-sw-block-alert")
    def _ctrl_sw_block_alert(self, e: Switch.Changed):
        _patch_control("block_on_alert", e.value)
        self._lg(f"[{'red' if e.value else 'green'}]ALERT 차단 {'활성화' if e.value else '비활성화'}[/]")

    @on(Switch.Changed, "#ctrl-sw-block-mask")
    def _ctrl_sw_block_mask(self, e: Switch.Changed):
        _patch_control("block_on_mask", e.value)
        self._lg(f"[{'red' if e.value else 'green'}]MASK 차단 {'활성화' if e.value else '비활성화'}[/]")

    # ── 버튼 핸들러 (프로세스 탭) ─────────────────────────────────────────────

    @on(Button.Pressed, "#btn-restart-engine")
    def _btn_restart_engine(self, _): self._proc_restart("engine")

    @on(Button.Pressed, "#btn-restart-mitm")
    def _btn_restart_mitm(self, _):   self._proc_restart("mitm")

    @on(Button.Pressed, "#btn-stop-engine")
    def _btn_stop_engine(self, _):    self._proc_toggle("engine", False)

    @on(Button.Pressed, "#btn-stop-mitm")
    def _btn_stop_mitm(self, _):      self._proc_toggle("mitm", False)

    @on(Button.Pressed, "#btn-start-engine")
    def _btn_start_engine(self, _):   self._proc_toggle("engine", True)

    @on(Button.Pressed, "#btn-start-mitm")
    def _btn_start_mitm(self, _):     self._proc_toggle("mitm", True)

    @on(Button.Pressed, "#btn-clear-log")
    def _btn_clear_log(self, _):
        self.query_one("#elog", RichLog).clear()

    @on(Button.Pressed, "#btn-clear-traffic")
    def _btn_clear_traffic(self, _):
        # JSONL 히스토리 파일도 비워야 재시작 시 되살아나지 않음
        try:
            open(self._jsonl, "w").close()
        except Exception:
            pass
        self._tk = TurnTracker()
        self._finding_rows.clear()
        self.query_one("#ttable", DataTable).clear()
        self.query_one("#ftable", DataTable).clear()
        try:
            self.query_one("#dlog", RichLog).clear()
        except Exception:
            pass
        try:
            self.query_one("#fdetail", RichLog).clear()
        except Exception:
            pass

    @on(Button.Pressed, "#btn-clear-findings")
    def _btn_clear_findings(self, _):
        self._finding_rows.clear()
        self.query_one("#ftable", DataTable).clear()
        try:
            self.query_one("#fdetail", RichLog).clear()
        except Exception:
            pass

    @work
    async def _proc_restart(self, key: str):
        if not self._sup:
            return
        ps = self._sup.procs.get(key)
        if not ps:
            return
        self._lg(f"[yellow][Supervisor/{ps.name}] 재시작 요청[/]")
        # 기존 _watch 태스크가 살아있으면 kill 후 루프에서 자동 재시작
        await self._sup._kill(ps)
        # 만약 _watch 태스크가 없다면(disabled 상태) 새로 시작
        if not ps.enabled:
            ps.enabled = True
            self._start_watch(key)

    @work
    async def _proc_toggle(self, key: str, enable: bool):
        if not self._sup:
            return
        ps = self._sup.procs.get(key)
        if not ps:
            return
        if enable:
            if not ps.running:
                ps.enabled = True
                if not ps.proc or ps.proc.returncode is not None:
                    self._start_watch(key)
                self._lg(f"[green][Supervisor/{ps.name}] 시작 요청[/]")
        else:
            ps.enabled = False
            await self._sup._kill(ps)
            ps.status = "중지"
            self._lg(f"[yellow][Supervisor/{ps.name}] 중지[/]")

    @work(exclusive=False)
    async def _start_watch(self, key: str):
        """단일 프로세스 _watch 루프를 Textual worker로 실행."""
        if self._sup:
            await self._sup._watch(key, self._sup.procs[key])

    # ── 히스토리 ──────────────────────────────────────────────────────────────

    @work(thread=True)
    def _load_history(self):
        p = Path(self._jsonl)
        if not p.exists():
            return
        evs = []
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("type") != "request":
                    continue
                ev = _rec2ev(rec)
                if ev:
                    evs.append(ev)
        self.call_from_thread(self._batch, evs, True)

    def _batch(self, evs: list[dict], hist: bool = False):
        for ev in evs:
            self._one(ev, hist)
        if hist:
            self._lg(f"[dim]히스토리: {len(evs)}건, {len(self._tk.turns)}개 턴[/]")

    def _one(self, ev: dict, hist: bool = False):
        model = ev.get("model") or "?"
        if not self._show_tg and model == "gpt-5-mini":
            return
        pa = ev.get("pipeline_action") or "pass"
        fc = ev.get("finding_count") or 0
        if not self._show_pass and pa == "pass" and fc == 0 and not hist:
            return
        turn = self._tk.ingest(ev)
        self._utt(turn)
        for f in ev.get("findings", []):
            self._aft(ev, f)
        self.query_one(StatsBar).turns = len(self._tk.turns)
        if not hist:
            self._ctrl_add_packet(ev)

    # ── 턴 테이블 ─────────────────────────────────────────────────────────────

    def _utt(self, t: Turn):
        tb = self.query_one("#ttable", DataTable)
        rk = f"t{t.id}"
        vals = (
            f"#{t.id}",
            _sts(t.ts),
            (t.model or "?")[:14],
            str(len(t.reqs)),
            f"[red]{t.fc}[/]" if t.fc else "0",
            f"[{ACT_S.get(t.wa, '')}]{ACT_LB.get(t.wa, t.wa.upper())}[/]",
        )
        if rk in tb.rows:
            tb.remove_row(rk)
        tb.add_row(*vals, key=rk)
        if self._auto:
            tb.move_cursor(row=tb.row_count - 1)
            self._show_turn_detail(t.id)

    def _aft(self, ev: dict, f: dict):
        tb = self.query_one("#ftable", DataTable)
        sev = f.get("severity") or "?"
        c = f.get("confidence", 0)
        rk = f"f{len(self._finding_rows)}"
        self._finding_rows[rk] = (ev, f)
        tb.add_row(
            _sts(ev.get("ts", "")),
            f"[{SEV_S.get(sev, '')}]{sev.upper()}[/]",
            f.get("rule", "?"),
            f"{c:.1f}" if isinstance(c, (int, float)) else str(c),
            _trunc(ev.get("model") or "?"),
            key=rk,
        )
        if self._auto:
            tb.move_cursor(row=tb.row_count - 1)

    # ── 턴 디테일 ─────────────────────────────────────────────────────────────

    @on(DataTable.RowSelected, "#ttable")
    def _sel(self, e: DataTable.RowSelected):
        rk = str(e.row_key.value)
        if not rk.startswith("t"):
            return
        try:
            tid = int(rk[1:])
        except ValueError:
            return
        self._show_turn_detail(tid)

    def _show_turn_detail(self, tid: int):
        if tid < 1 or tid > len(self._tk.turns):
            return
        t = self._tk.turns[tid - 1]
        # ── 탐지 정보 탭 ─────────────────────────────────────────────────
        d = self.query_one("#dlog", RichLog)
        d.clear()
        d.write(f"[bold]═══ Turn #{t.id} ═══[/]")
        d.write(f"  시작   : {t.ts}")
        d.write(f"  모델   : [green]{t.model}[/]")
        d.write(f"  msgs   : {t.mc}")
        d.write(f"  요청 수: {len(t.reqs)}")
        d.write(f"  탐지   : [red]{t.fc}[/]")
        d.write(f"  액션   : [{ACT_S.get(t.wa, '')}]{t.wa.upper()}[/]")
        d.write("")
        for i, rq in enumerate(t.reqs):
            d.write(f"[bold]── 요청 #{rq.get('id','?')} ({i+1}/{len(t.reqs)}) ──[/]")
            d.write(f"  model: {rq.get('model','?')}  target: {rq.get('target_count',0)}개  "
                    f"text: {rq.get('total_text_len',0):,}자")
            rpa = rq.get("pipeline_action") or "pass"
            d.write(f"  [{ACT_S.get(rpa,'')}]{rpa.upper()}[/]  "
                    f"탐지={rq.get('finding_count',0)}  "
                    f"[dim]{rq.get('elapsed_ms',0)}ms[/]")
            for f in rq.get("findings", []):
                sev = f.get("severity") or "?"
                d.write(f"    [{SEV_S.get(sev,'')}][{sev.upper()}][/] "
                        f"{f.get('rule','?')} conf={f.get('confidence',0):.1f}")
                d.write(f"      매치: {f.get('match_text','')!r}")
                d.write(f"      경로: [dim]{f.get('field_path','')}[/]")
                cb = f.get("context_before", "")
                ca = f.get("context_after", "")
                if cb or ca:
                    d.write(f"      …{cb[-40:]}[bold red]<<<{f.get('match_text','')[:30]}>>>[/]{ca[:40]}…")
            d.write("")
        # ── 전송 내용 탭 ─────────────────────────────────────────────────
        ds = self.query_one("#dsent", RichLog)
        ds.clear()
        ds.write(f"[bold]═══ Turn #{t.id} — 전송된 프롬프트 ═══[/]")
        ds.write(f"  모델: [green]{t.model}[/]  msgs: {t.mc}")
        ds.write("")
        for i, rq in enumerate(t.reqs):
            targets = rq.get("targets", [])
            if not targets:
                ds.write(f"[dim]── 요청 #{rq.get('id','?')} — 전송 내용 없음 (히스토리) ──[/]")
                ds.write("")
                continue
            findings = rq.get("findings", [])
            pa = rq.get("pipeline_action") or "pass"
            ds.write(f"[bold]── 요청 #{rq.get('id','?')} ({i+1}/{len(t.reqs)}) [{ACT_S.get(pa, '')}]{pa.upper()}[/] ──[/]")
            if findings:
                ds.write(f"  [cyan]▶ 마스킹 {len(findings)}건 적용[/]")
            for tgt in targets:
                fp = tgt.get("field_path", "")
                role = tgt.get("role", "?")
                text = tgt.get("text", "")
                # 탐지된 건이 있으면 마스킹 시뮬레이션 적용
                if findings:
                    text = _simulate_mask(text, findings, fp)
                role_color = "cyan" if role == "system" else "green" if role == "assistant" else "yellow"
                ds.write(f"  [{role_color}]{role}[/] [dim]({fp})[/]")
                if len(text) > 2000:
                    ds.write(f"    {text[:2000]}")
                    ds.write(f"    [dim]… ({len(text):,}자 중 2000자만 표시)[/]")
                else:
                    ds.write(f"    {text}")
                ds.write("")

    # ── 탐지 상세 ─────────────────────────────────────────────────────────────

    @on(DataTable.RowSelected, "#ftable")
    def _sel_finding(self, e: DataTable.RowSelected):
        rk = str(e.row_key.value)
        pair = self._finding_rows.get(rk)
        if not pair:
            return
        ev, f = pair
        d = self.query_one("#fdetail", RichLog)
        d.clear()
        sev = f.get("severity") or "?"
        c = f.get("confidence", 0)
        pa = ev.get("pipeline_action") or "pass"
        d.write(f"[bold]═══ 탐지 상세 ═══[/]")
        d.write(f"  시각    : {ev.get('ts', '')}")
        d.write(f"  모델    : [green]{ev.get('model', '?')}[/]")
        d.write(f"  제공자  : {ev.get('provider', '?')}")
        d.write(f"  액션    : [{ACT_S.get(pa, '')}]{pa.upper()}[/]")
        d.write(f"  스캔 시간: [dim]{ev.get('elapsed_ms', 0)}ms[/]")
        d.write("")
        d.write(f"[bold]── 탐지 규칙 ──[/]")
        d.write(f"  규칙    : [bold]{f.get('rule', '?')}[/]")
        d.write(f"  심각도  : [{SEV_S.get(sev, '')}]{sev.upper()}[/]")
        d.write(f"  신뢰도  : {c:.2f}" if isinstance(c, (int, float)) else f"  신뢰도  : {c}")
        d.write(f"  Stage   : [dim]{f.get('stage', '?')}[/]")
        d.write(f"  역할    : [dim]{f.get('role', '?')}[/]")
        d.write(f"  경로    : [dim]{f.get('field_path', '')}[/]")
        d.write("")
        d.write(f"[bold]── 매치 내용 ──[/]")
        mt = f.get('match_text') or ''
        d.write(f"  [{SEV_S.get(sev, '')}]{mt!r}[/]")
        d.write("")
        cb = f.get("context_before") or ""
        ca = f.get("context_after") or ""
        if cb or ca:
            d.write(f"[bold]── 컨텍스트 ──[/]")
            d.write(f"  [dim]…{cb[-60:]}[/][bold red]{mt[:40]}[/][dim]{ca[:60]}…[/]")

    # ── 엔진 구독 ────────────────────────────────────────────────────────────

    @work(exclusive=True)
    async def _subscribe(self):
        while True:
            w = None
            try:
                r, w = await asyncio.open_unix_connection(self._sock)
                w.write(json.dumps({"action": "subscribe", "id": 0}).encode() + b"\n")
                await w.drain()
                ack = await asyncio.wait_for(r.readline(), timeout=5)
                if not (ack and json.loads(ack).get("ok")):
                    continue
                self._lg("[green]엔진 구독 연결됨[/]")
                while True:
                    line = await r.readline()
                    if not line:
                        break
                    try:
                        ev = json.loads(line)
                        if ev.get("type") == "scan_result":
                            self._one(ev)
                            self._log_ev(ev)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass
            except asyncio.CancelledError:
                return
            except Exception:
                pass
            finally:
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass
            self._lg("[yellow]엔진 재연결 3초…[/]")
            try:
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                return

    def _log_ev(self, ev: dict):
        pa = ev.get("pipeline_action") or "pass"
        fc = ev.get("finding_count") or 0
        self._lg(
            f"[bold]#{ev.get('id','?')}[/] {ev.get('provider','?')} "
            f"[green]{ev.get('model','?')}[/] "
            f"[{ACT_S.get(pa,'')}][{pa.upper()}][/] "
            f"findings=[red]{fc}[/] [dim]{ev.get('elapsed_ms',0)}ms[/]")
        for f in ev.get("findings", []):
            sev = f.get("severity") or "?"
            self._lg(
                f"  [{SEV_S.get(sev,'')}][{sev.upper()}][/] "
                f"{f.get('rule','?')} conf={f.get('confidence',0):.1f}: "
                f"{f.get('match_text','')[:60]!r} "
                f"[dim]@ {f.get('field_path','?')}[/]")

    # ── 통계 폴링 (persistent 연결) ──────────────────────────────────────────

    @work(exclusive=True)
    async def _poll(self):
        await asyncio.sleep(1)  # 마운트 완료 대기
        while True:
            try:
                # 매번 새 연결 사용 — 엔진 재시작 시도 확실히 감지
                r, w = await asyncio.wait_for(
                    asyncio.open_unix_connection(self._sock), timeout=2.0)
                try:
                    w.write(json.dumps({"action": "stats", "id": -1}).encode() + b"\n")
                    await w.drain()
                    line = await asyncio.wait_for(r.readline(), timeout=3)
                    if not line:
                        raise ConnectionResetError
                    s = json.loads(line)
                    bar = self.query_one(StatsBar)
                    bar.total    = s.get("total", 0)
                    bar.scanned  = s.get("scanned", 0)
                    bar.findings = s.get("findings", 0)
                    bar.masked   = s.get("masked", 0)
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass
            except (ConnectionRefusedError, ConnectionResetError,
                    FileNotFoundError, OSError, asyncio.TimeoutError):
                pass
            except asyncio.CancelledError:
                return
            except Exception:
                pass
            try:
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                return

    # ── 스위치 ────────────────────────────────────────────────────────────────

    @on(Switch.Changed, "#sw-cap")
    def _sw_cap(self, e: Switch.Changed):
        if e.value:
            _CAPTURE_FLAG.touch()
            self._lg("[green]패킷 캡처 ON[/] — 다음 1개 저장")
        else:
            _CAPTURE_FLAG.unlink(missing_ok=True)
            self._lg("[yellow]패킷 캡처 OFF[/]")

    @on(Switch.Changed, "#sw-auto")
    def _sw_auto(self, e: Switch.Changed):
        self._auto = e.value

    @on(Switch.Changed, "#sw-pass")
    def _sw_pass(self, e: Switch.Changed):
        self._show_pass = e.value

    @on(Switch.Changed, "#sw-tg")
    def _sw_tg(self, e: Switch.Changed):
        self._show_tg = e.value

    # ── 액션 ──────────────────────────────────────────────────────────────────

    def action_toggle_capture(self):
        try:
            sw = self.query_one("#sw-cap", Switch)
            sw.value = not sw.value
        except Exception:
            pass

    def action_tab(self, tab_id: str):
        self.query_one(TabbedContent).active = tab_id

    def action_reload(self):
        self._tk = TurnTracker()
        self._finding_rows.clear()
        self.query_one("#ttable", DataTable).clear()
        self.query_one("#ftable", DataTable).clear()
        self.query_one("#fdetail", RichLog).clear()
        self._load_history()
        self._lg("[dim]새로고침…[/]")

    # ── 유틸 ──────────────────────────────────────────────────────────────────

    def _lg(self, msg: str):
        try:
            self.query_one("#elog", RichLog).write(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] {msg}")
        except Exception:
            pass


def _sts(ts: str) -> str:
    return ts.split(" ")[-1][:8] if " " in ts else ts[:8]


def _rec2ev(rec: dict) -> dict | None:
    s = rec.get("dlp_summary") or {}
    model = s.get("model")
    if not model:
        return None
    eng = rec.get("engine") or {}
    return {
        "id": rec.get("id", "?"),
        "ts": rec.get("ts", ""),
        "provider": rec.get("provider", "?"),
        "model": model,
        "msg_count": s.get("msg_count", 0),
        "body_size": rec.get("body_size", 0),
        "pipeline_action": eng.get("pipeline_action", "pass"),
        "finding_count": eng.get("finding_count", 0),
        "findings": eng.get("findings", []),
        "elapsed_ms": eng.get("elapsed_ms", 0),
        "target_count": eng.get("target_count", 0),
        "total_text_len": eng.get("total_text_len", 0),
        "targets": eng.get("targets", []),
        "dlp_applied": rec.get("dlp_applied", "pass"),
    }


def main():
    p = argparse.ArgumentParser(description="AI DLP Proxy TUI")
    p.add_argument("--sock", default=_DEFAULT_SOCK)
    p.add_argument("--jsonl", default=None)
    p.add_argument("--no-supervisor", action="store_true",
                   help="engine/mitmproxy 자동 시작·감시 비활성화")
    a = p.parse_args()
    DLPApp(sock=a.sock, jsonl_path=a.jsonl, supervise=not a.no_supervisor).run()


if __name__ == "__main__":
    main()
