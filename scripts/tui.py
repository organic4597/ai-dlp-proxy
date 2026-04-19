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
import re
import signal
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

_SRC_DIR = Path(__file__).parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from engine.pipeline import get_runtime_warning_lines
from engine.pipeline.default_assets import ensure_default_assets_file
from engine.pipeline.masking import (
    DEFAULT_MASK_TEMPLATES,
    EDITABLE_MASK_RULES,
    merge_mask_templates,
)

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)
from rich.console import Group
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ── 경로 설정 ────────────────────────────────────────────────────────────────
_BASE = Path(__file__).parent.parent
_LOG_DIR = _BASE / "logs"
_DEFAULT_SOCK = "/tmp/dlp-engine.sock"
_CAPTURE_FLAG = Path("/tmp/dlp-capture-next")
_CAPTURE_OUT = _LOG_DIR / "captured_packet.json"
_CONTROL_FILE = Path("/tmp/dlp-control.json")   # inspect_traffic이 읽는 제어 파일
_AUDIT_DIR = Path.home() / ".config" / "ai-dlp-proxy"
_AUDIT_FILE = _AUDIT_DIR / "audit.jsonl"
_AUDIT_ROTATED = _AUDIT_DIR / "audit.jsonl.1"
_AUDIT_MAX_BYTES = 10 * 1024 * 1024
_ASSETS_FILE = _AUDIT_DIR / "assets.json"   # 보호 자산 정의 파일


def _read_assets() -> list[dict]:
    """보호 자산 파일 읽기. 없으면 기본 목록으로 초기화."""
    ensure_default_assets_file(_ASSETS_FILE)
    try:
        return json.loads(_ASSETS_FILE.read_text(encoding="utf-8")).get("assets", [])
    except Exception:
        return []


def _write_assets(assets: list[dict]) -> None:
    """보호 자산 파일 저장."""
    _ASSETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ASSETS_FILE.write_text(
        json.dumps({"assets": assets}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

_CTRL_DEFAULTS: dict = {
    "regex_enabled":  True,
    "asset_enabled":  True,
    "slm_enabled":    False,
    "mask_on_detect": False,
    "block_on_alert": False,
    "block_on_mask":  False,
    "disabled_rules": [],
    "mask_templates": {},
    "confidence_threshold": 0.5,
    "context_penalty_enabled": True,
    "allowlist": [],
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


def _normalize_allowlist_value(value: str) -> str:
    return re.sub(r"[\W_]+", "", value).casefold()


def _find_asset(assets: list[dict], asset_id: str | None) -> tuple[int, dict] | tuple[None, None]:
    if not asset_id:
        return None, None
    for index, asset in enumerate(assets):
        if str(asset.get("id", "")) == asset_id:
            return index, asset
    return None, None


# ── 색상 ─────────────────────────────────────────────────────────────────────
SEV_S = {"critical": "bold red", "high": "magenta", "medium": "yellow", "low": "dim"}
ACT_S  = {"pass": "green", "alert": "yellow", "mask": "bold red", "block": "bold red reverse"}
ACT_LB = {"pass": "PASS", "alert": "ALERT", "mask": "MASKED", "block": "BLOCK"}

def _simulate_mask(
    text: str,
    findings: list[dict],
    field_path: str,
    threshold: float,
    mask_templates: dict[str, str],
) -> str:
    """findings를 이용해 text에 마스킹 시뮬레이션 (오프셋 역순 치환)."""
    relevant = [
        f for f in findings
        if f.get("field_path") == field_path
        and not f.get("suppressed", False)
        and isinstance(f.get("confidence"), (int, float))
        and f.get("confidence", 0.0) >= threshold
    ]
    if not relevant:
        return text
    for f in sorted(relevant, key=lambda x: x.get("match_start", 0), reverse=True):
        repl = mask_templates.get(f.get("rule", ""), "[REDACTED]")
        start = f.get("match_start", 0)
        end = f.get("match_end", 0)
        if start < 0 or end <= start or end > len(text):
            mt = f.get("match_text", "")
            if mt:
                text = text.replace(mt, repl, 1)
        else:
            text = text[:start] + repl + text[end:]
    return text


# ── 보호 자산 추가 다이얼로그 ─────────────────────────────────────────────────

class AssetAddScreen(ModalScreen):
    """보호 자산 추가/편집 폼 모달."""

    CSS = """
    AssetAddScreen {
        align: center middle;
    }
    #asset-add-dialog {
        width: 60;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $accent;
    }
    #asset-add-dialog Label { margin-bottom: 0; color: $text-muted; }
    #asset-add-dialog Input { margin-bottom: 1; }
    #asset-add-dialog Select { margin-bottom: 1; }
    #asset-add-btns { margin-top: 1; align-horizontal: right; }
    #asset-add-btns Button { margin-left: 1; }
    """

    BINDINGS = [("escape", "cancel", "취소")]

    def __init__(self, initial: dict | None = None):
        super().__init__()
        self._initial = dict(initial or {})
        self._editing = bool(self._initial)

    def compose(self) -> ComposeResult:
        title = "🛡️ 보호 자산 편집" if self._editing else "🛡️ 보호 자산 추가"
        submit_label = "저장" if self._editing else "추가"
        keywords_value = ", ".join(str(k) for k in self._initial.get("keywords", []) if str(k).strip())
        examples_value = "; ".join(str(e) for e in self._initial.get("examples", []) if str(e).strip())
        try:
            threshold_value = f"{float(self._initial.get('embedding_threshold', 0.80)):.2f}"
        except (TypeError, ValueError):
            threshold_value = "0.80"
        with Vertical(id="asset-add-dialog"):
            yield Label(title, classes="ctrl-title")
            yield Label("자산 이름 *")
            yield Input(placeholder="예: SSH 키", id="asset-name", value=str(self._initial.get("name", "")))
            yield Label("심각도")
            yield Select(
                [("critical", "critical"), ("high", "high"),
                 ("medium", "medium"), ("low", "low")],
                value=str(self._initial.get("severity", "high") or "high"),
                id="asset-sev",
            )
            yield Label("키워드 (쉼표 구분) *")
            yield Input(placeholder="예: id_rsa, .ssh, authorized_keys", id="asset-keywords", value=keywords_value)
            yield Label("예시 문장 (세미콜론 구분)")
            yield Input(placeholder="예: SSH 키 첨부합니다; 키 파일 보내드립니다", id="asset-examples", value=examples_value)
            yield Label("임베딩 임계값 (0.0~1.0)")
            yield Input(placeholder="0.80", id="asset-threshold", value=threshold_value)
            with Horizontal(id="asset-add-btns"):
                yield Button("취소", id="btn-asset-cancel", variant="default")
                yield Button(submit_label, id="btn-asset-ok", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-asset-cancel":
            self.dismiss(None)
            return
        name = self.query_one("#asset-name", Input).value.strip()
        keywords_raw = self.query_one("#asset-keywords", Input).value.strip()
        if not name or not keywords_raw:
            return  # 필수 필드 미입력
        examples_raw = self.query_one("#asset-examples", Input).value.strip()
        try:
            threshold = float(self.query_one("#asset-threshold", Input).value or "0.80")
            threshold = min(max(threshold, 0.0), 1.0)
        except ValueError:
            threshold = 0.80
        sev_select = self.query_one("#asset-sev", Select)
        severity = str(sev_select.value) if sev_select.value != Select.BLANK else "high"
        keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]
        examples = [e.strip() for e in examples_raw.split(";") if e.strip()]
        import uuid
        self.dismiss({
            "id": str(self._initial.get("id", "")).strip() or str(uuid.uuid4())[:8],
            "name": name,
            "severity": severity,
            "keywords": keywords,
            "examples": examples,
            "embedding_threshold": threshold,
        })

    def action_cancel(self) -> None:
        self.dismiss(None)


class CustomRuleAddScreen(ModalScreen):
    """커스텀 탐지 규칙 추가/편집 폼 모달."""

    CSS = """
    CustomRuleAddScreen {
        align: center middle;
    }
    #crule-dialog {
        width: 70;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $accent;
    }
    #crule-dialog Label { margin-bottom: 0; color: $text-muted; }
    #crule-dialog Input { margin-bottom: 1; }
    #crule-dialog Select { margin-bottom: 1; }
    #crule-dialog #crule-test-result { color: $text-muted; margin-bottom: 1; }
    #crule-btns { margin-top: 1; align-horizontal: right; }
    #crule-btns Button { margin-left: 1; }
    """

    BINDINGS = [("escape", "cancel", "취소")]

    def __init__(self, initial: dict | None = None):
        super().__init__()
        self._initial = dict(initial or {})
        self._editing = bool(self._initial)

    def compose(self) -> ComposeResult:
        title = "✏️ 커스텀 규칙 편집" if self._editing else "➕ 커스텀 탐지 규칙 추가"
        submit_label = "저장" if self._editing else "추가"
        with Vertical(id="crule-dialog"):
            yield Label(title, classes="ctrl-title")
            yield Label("규칙 이름 * (영문·숫자·_·-, 중복 불가)")
            yield Input(placeholder="예: internal_code", id="crule-name",
                        value=self._initial.get("name", ""))
            yield Label("정규식 패턴 * (Python re 문법)")
            yield Input(placeholder="예: PRJ-[0-9]{4,}", id="crule-pattern",
                        value=self._initial.get("pattern", ""))
            yield Label("심각도")
            yield Select(
                [("critical", "critical"), ("high", "high"),
                 ("medium", "medium"), ("low", "low")],
                value=str(self._initial.get("severity", "high")),
                id="crule-sev",
            )
            yield Label("설명")
            yield Input(placeholder="예: 내부 프로젝트 코드", id="crule-desc",
                        value=self._initial.get("description", ""))
            yield Label("마스킹 텍스트 (비우면 [커스텀])")
            yield Input(placeholder="[내부코드]", id="crule-mask",
                        value=self._initial.get("mask_template", ""))
            yield Label("패턴 테스트 (입력 후 자동 검증)")
            yield Input(placeholder="테스트할 텍스트 입력", id="crule-test-input")
            yield Label("", id="crule-test-result")
            with Horizontal(id="crule-btns"):
                yield Button("취소", id="btn-crule-cancel", variant="default")
                yield Button(submit_label, id="btn-crule-ok", variant="success")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id in ("crule-pattern", "crule-test-input"):
            self._run_test()

    def _run_test(self) -> None:
        import re as _re
        pattern = self.query_one("#crule-pattern", Input).value.strip()
        test_text = self.query_one("#crule-test-input", Input).value
        result_label = self.query_one("#crule-test-result", Label)
        if not pattern:
            result_label.update("")
            return
        try:
            compiled = _re.compile(pattern)
        except _re.error as e:
            result_label.update(f"[red]패턴 오류: {e}[/]")
            return
        if not test_text:
            result_label.update("[dim]테스트 텍스트를 입력하세요[/]")
            return
        matches = list(compiled.finditer(test_text))
        if matches:
            matched = [m.group() for m in matches[:3]]
            result_label.update(f"[green]✅ {len(matches)}개 매치: {matched}[/]")
        else:
            result_label.update("[yellow]⚠ 매치 없음[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-crule-cancel":
            self.dismiss(None)
            return
        name = self.query_one("#crule-name", Input).value.strip()
        pattern = self.query_one("#crule-pattern", Input).value.strip()
        if not name or not pattern:
            return
        import re as _re
        try:
            _re.compile(pattern)
        except _re.error:
            return
        sev_select = self.query_one("#crule-sev", Select)
        severity = str(sev_select.value) if sev_select.value != Select.BLANK else "high"
        desc = self.query_one("#crule-desc", Input).value.strip() or name
        mask = self.query_one("#crule-mask", Input).value.strip() or f"[{name.upper()}]"
        self.dismiss({
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "description": desc,
            "mask_template": mask,
        })

    def action_cancel(self) -> None:
        self.dismiss(None)


class AllowlistAddScreen(ModalScreen):
    """Allowlist 항목 추가/편집 폼 모달."""

    CSS = """
    AllowlistAddScreen {
        align: center middle;
    }
    #allowlist-add-dialog {
        width: 60;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $accent;
    }
    #allowlist-add-dialog Label { margin-bottom: 0; color: $text-muted; }
    #allowlist-add-dialog Input { margin-bottom: 1; }
    #allowlist-add-dialog Select { margin-bottom: 1; }
    #allowlist-add-btns { margin-top: 1; align-horizontal: right; }
    #allowlist-add-btns Button { margin-left: 1; }
    """

    BINDINGS = [("escape", "cancel", "취소")]

    def __init__(
        self,
        initial_rule: str = "*",
        initial_value: str = "",
        title: str = "📝 Allowlist 추가",
        submit_label: str = "추가",
    ):
        super().__init__()
        self._initial_rule = initial_rule or "*"
        self._initial_value = initial_value
        self._title = title
        self._submit_label = submit_label

    def compose(self) -> ComposeResult:
        rule_options = [("전체 룰 (*)", "*")]
        rule_options.extend((rule, rule) for rule, _, _ in DLPApp._MASK_RULES_DATA)
        with Vertical(id="allowlist-add-dialog"):
            yield Label(self._title, classes="ctrl-title")
            yield Label("Allowlist는 정규식 탐지 값에 적용됩니다.")
            yield Label("규칙")
            yield Select(rule_options, value=self._initial_rule, id="allowlist-rule")
            yield Label("값 *")
            yield Input(placeholder="예: support@example.com", id="allowlist-value", value=self._initial_value)
            with Horizontal(id="allowlist-add-btns"):
                yield Button("취소", id="btn-allowlist-cancel", variant="default")
                yield Button(self._submit_label, id="btn-allowlist-ok", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-allowlist-cancel":
            self.dismiss(None)
            return
        rule_select = self.query_one("#allowlist-rule", Select)
        value = self.query_one("#allowlist-value", Input).value.strip()
        if not value:
            return
        rule = str(rule_select.value) if rule_select.value != Select.BLANK else "*"
        self.dismiss({
            "rule": rule or "*",
            "value": value,
        })

    def action_cancel(self) -> None:
        self.dismiss(None)


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

    @staticmethod
    def _port_in_use(port: int) -> bool:
        """해당 TCP 포트가 이미 LISTEN 상태인지 확인."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                return False
            except OSError:
                return True

    @staticmethod
    def _sock_in_use(path: str) -> bool:
        """Unix Domain Socket 파일이 이미 존재하며 연결 가능한지 확인."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(path)
                return True
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            return False

    async def _watch(self, key: str, ps: ProcState):
        """한 프로세스를 무한 감시. 종료 시 restart_delay 후 재시작."""
        log_file = self._log_dir / f"{key}.log"
        while self._running and ps.enabled:
            # ── 이미 실행 중인 외부 프로세스가 포트/소켓을 점유 중이면 띄우지 않음
            if key == "mitm":
                mitm_port = int(next(
                    (ps.cmd[i + 1] for i, a in enumerate(ps.cmd) if a in ("-p", "--listen-port")),
                    4001,
                ))
                if self._port_in_use(mitm_port):
                    ps.status = "외부 실행 중"
                    ps.running = True
                    self._emit(key, f"[cyan]포트 {mitm_port} 이미 사용 중 — 외부 프로세스 감지, 재사용[/]")
                    # 포트가 해제될 때까지 대기
                    while self._running and ps.enabled and self._port_in_use(mitm_port):
                        await asyncio.sleep(5.0)
                    ps.running = False
                    if not self._running or not ps.enabled:
                        ps.status = "중지"
                        return
                    self._emit(key, f"[yellow]외부 mitmproxy 종료 감지 — 내부 인스턴스 시작[/]")
                    continue
            elif key == "engine":
                if self._sock_in_use(self._sock):
                    ps.status = "외부 실행 중"
                    ps.running = True
                    self._emit(key, f"[cyan]소켓 {self._sock} 이미 사용 중 — 외부 프로세스 감지, 재사용[/]")
                    while self._running and ps.enabled and self._sock_in_use(self._sock):
                        await asyncio.sleep(5.0)
                    ps.running = False
                    if not self._running or not ps.enabled:
                        ps.status = "중지"
                        return
                    self._emit(key, f"[yellow]외부 engine_server 종료 감지 — 내부 인스턴스 시작[/]")
                    continue

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
    #act-legend { height: 2; padding: 0 1; background: $surface; color: $text-muted; }
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
    /* 마스킹 규칙 */
    #mask-table { height: 14; }
    #allowlist-table { height: 10; }
    #ctrl-threshold-input { width: 10; margin: 0 1 0 0; }
    #mask-edit-input { width: 18; margin: 0 1 0 0; }
    .mask-action-row {
        height: 3;
        padding: 0 0 0 1;
        align: left middle;
    }
    .mask-action-row Button { min-width: 8; margin: 0 1 0 0; }
    #btn-mask-save    { min-width: 7; }
    #btn-mask-reset   { min-width: 9; }
    #btn-mask-crule-add    { min-width: 11; }
    #btn-mask-crule-edit   { min-width: 8; }
    #btn-mask-crule-delete { min-width: 4; }
    .mask-badge {
        height: 1;
        color: $text-disabled;
        padding: 0 0 0 1;
        margin: 0 0 1 0;
    }
    .selection-label {
        height: 1;
        color: $text-disabled;
        padding: 0 0 0 1;
        margin: 0 0 1 0;
    }

    /* 파이프라인 탭 */
    #pipeline-tab { height: 1fr; layout: horizontal; }
    #pipeline-flow-scroll {
        width: 1fr;
        height: 1fr;
        border: round $primary-background-darken-2;
        background: $surface;
        margin: 1 1 1 0;
    }
    #pipeline-flow { padding: 1 2; }
    #pipeline-right {
        width: 44;
        height: 1fr;
        layout: vertical;
    }
    #pipeline-ctrl-state {
        height: auto;
        border: round $primary-background-darken-2;
        background: $surface;
        padding: 1 2;
        margin: 1 0 0 0;
    }
    #pipeline-conf-hist {
        height: 1fr;
        border: round $primary-background-darken-2;
        background: $surface;
        padding: 1 2;
        margin: 1 0 1 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "종료"),
        Binding("ctrl+q", "quit", "종료", show=False),
        Binding("c", "toggle_capture", "캡처 토글"),
        Binding("r", "reload", "새로고침"),
        Binding("1", "tab('tab-traffic')",   "트래픽",    show=True),
        Binding("2", "tab('tab-findings')",  "탐지",      show=True),
        Binding("3", "tab('tab-pipeline')",  "파이프라인", show=True),
        Binding("4", "tab('tab-control')",   "제어",      show=True),
        Binding("5", "tab('tab-procs')",     "프로세스",   show=True),
        Binding("6", "tab('tab-settings')",  "설정",      show=True),
        Binding("7", "tab('tab-log')",       "로그",      show=True),
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
        self._finding_row_order: list[str] = []  # 삽입 순서 (ftable trim용)
        self._finding_counter: int = 0  # 단조 증가 키 생성용 (trim 후 중복 방지)
        self._selected_finding: tuple[dict, dict] | None = None
        self._selected_turn_id: int | None = None
        self._selected_asset_id: str | None = None
        self._selected_allowlist_index: int | None = None
        self._selected_mask_rule: str | None = None
        self._startup_warnings: list[str] = []
        self._sent_text_cache = ""
        self._live_events_by_request_id: dict[str, dict] = {}
        self._live_event_turns: dict[str, Turn] = {}
        self._mask_rule_hits: dict[str, int] = {}
        self._pipeline_stats: dict = {}
        self._bump_pending: bool = False  # _bump_mask_rule_hit 배치 디바운스
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
                            "[green]PASS[/] 정상통과  [yellow]ALERT[/] 탐지됨\n"
                            "[bold cyan]MASKED[/] 마스킹  [bold red]BLOCK[/] 차단",
                            id="act-legend",
                        )
                    with Vertical(id="darea"):
                        with TabbedContent(id="detail-tabs"):
                            with TabPane("탐지 정보", id="tab-detail-info"):
                                yield RichLog(id="dlog", highlight=True, markup=True, wrap=True, max_lines=500)
                            with TabPane("전송 내용", id="tab-detail-sent"):
                                with Horizontal(classes="tab-toolbar"):
                                    yield Label("전송 내용", classes="toolbar-title")
                                    yield Button("복사", id="btn-copy-sent", classes="toolbar-btn")
                                yield RichLog(id="dsent", highlight=True, markup=True, wrap=True, max_lines=300)
            with TabPane("탐지 목록", id="tab-findings"):
                with Horizontal(id="fsplit"):
                    with Vertical(id="flist"):
                        with Horizontal(classes="tab-toolbar"):
                            yield Label("탐지목록", classes="toolbar-title")
                            yield Button("클리어", id="btn-clear-findings", classes="toolbar-btn")
                        yield DataTable(id="ftable", cursor_type="row")
                    with Vertical(id="fdetail-area"):
                        yield RichLog(id="fdetail", highlight=True, markup=True, wrap=True, max_lines=300)
            with TabPane("제어", id="tab-control"):
                with VerticalScroll(id="ctrl-scroll"):
                    with Vertical(classes="ctrl-card"):
                        yield Label("🎚 탐지 기준", classes="ctrl-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("신뢰도 임계값")
                            yield Input(value="0.50", id="ctrl-threshold-input")
                            yield Button("저장", id="btn-threshold-save", variant="primary")
                        yield Label("0.00 ~ 1.00 범위. Enter 또는 저장 버튼으로 즉시 반영됩니다.", classes="opt-desc")
                    # ── 마스킹 규칙 ────────────────────────────────────────
                    with Vertical(classes="ctrl-card"):
                        yield Label("🎭 마스킹 규칙", classes="ctrl-title")
                        yield Label("행 클릭으로 ON/OFF 토글. 🔧=커스텀(정규식). 선택 후 치환 텍스트 편집 가능.", classes="mask-badge")
                        yield _ClickToggleTable(id="mask-table", cursor_type="row")
                        yield Label("선택된 규칙 없음", id="mask-selection", classes="selection-label")
                        with Horizontal(classes="mask-action-row"):
                            yield Input(placeholder="선택 규칙 치환 텍스트", id="mask-edit-input")
                            yield Button("저장", id="btn-mask-save", variant="primary")
                            yield Button("기본값", id="btn-mask-reset", variant="default")
                            yield Button("➕ 커스텀", id="btn-mask-crule-add", variant="success")
                            yield Button("✏️ 편집", id="btn-mask-crule-edit", variant="primary", disabled=True)
                            yield Button("🗑", id="btn-mask-crule-delete", variant="error", disabled=True)
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
                    # ── 보호 자산 ──────────────────────────────────────────
                    with Vertical(classes="ctrl-card"):
                        yield Label("🛡️ 보호 자산", classes="ctrl-title")
                        yield Label("민감한 자산(SSH키·내부 프로젝트 등)을 등록하면 요청 텍스트에서 탐지합니다.", classes="mask-badge")
                        yield DataTable(id="asset-table", cursor_type="row", show_cursor=True)
                        yield Label("선택된 자산 없음", id="asset-selection", classes="selection-label")
                        with Horizontal(classes="opt-row"):
                            yield Button("➕ 자산 추가", id="btn-asset-add", variant="success")
                            yield Button("✏️ 선택 편집", id="btn-asset-edit", variant="primary")
                            yield Button("🗑 선택 삭제", id="btn-asset-delete", variant="error")
                    with Vertical(classes="ctrl-card"):
                        yield Label("📝 Allowlist", classes="ctrl-title")
                        yield Label("선택 탐지 추가는 현재 열린 탐지 상세의 후보값을 사용합니다. 테이블 행은 선택만 하며, 편집/삭제는 아래 버튼으로 실행합니다.", classes="mask-badge")
                        yield DataTable(id="allowlist-table", cursor_type="row", show_cursor=True)
                        yield Label("선택된 Allowlist 항목 없음", id="allowlist-selection", classes="selection-label")
                        with Horizontal(classes="opt-row"):
                            yield Button("선택 탐지 추가", id="btn-allowlist-add-selected", variant="primary")
                            yield Button("직접 추가", id="btn-allowlist-add", variant="success")
                            yield Button("✏️ 선택 편집", id="btn-allowlist-edit", variant="primary")
                            yield Button("🗑 선택 삭제", id="btn-allowlist-delete", variant="error")
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
                        yield Label("정규식 기반 개인정보 탐지 (주민번호·카드번호 등 12개 규칙)", classes="opt-desc")
                        with Horizontal(classes="opt-row"):
                            yield Label("Asset Stage")
                            yield Switch(id="sw-asset", value=True)
                        yield Label("보호 자산 키워드/임베딩 탐지를 활성화합니다.", classes="opt-desc")
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
                    # ── 스캔 대상 Role 카드 ──
                    with Vertical(classes="card"):
                        yield Label("🎯 스캔 대상 Role", classes="card-title")
                        with Horizontal(classes="opt-row"):
                            yield Label("user (사용자 입력)")
                            yield Switch(id="sw-role-user", value=True)
                        with Horizontal(classes="opt-row"):
                            yield Label("tool_result (파일/명령 실행 결과)")
                            yield Switch(id="sw-role-tool-result", value=True)
                        with Horizontal(classes="opt-row"):
                            yield Label("tool_call (함수 호출 인자)")
                            yield Switch(id="sw-role-tool-call", value=True)
                        with Horizontal(classes="opt-row"):
                            yield Label("system (시스템 프롬프트) [기본: 제외]")
                            yield Switch(id="sw-role-system", value=False)
                        with Horizontal(classes="opt-row"):
                            yield Label("tool_def (함수 정의) [기본: 제외]")
                            yield Switch(id="sw-role-tool-def", value=False)
                        yield Label("OFF = 해당 role은 스캔 제외. system·tool_def는 기본 제외", classes="opt-desc")
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
            with TabPane("파이프라인", id="tab-pipeline"):
                with Horizontal(id="pipeline-tab"):
                    with VerticalScroll(id="pipeline-flow-scroll"):
                        yield Static("", id="pipeline-flow")
                    with Vertical(id="pipeline-right"):
                        yield Static("", id="pipeline-ctrl-state")
                        yield Static("", id="pipeline-conf-hist")
            with TabPane("엔진 로그", id="tab-log"):
                with Vertical():
                    with Horizontal(classes="tab-toolbar"):
                        yield Label("엔진 로그", classes="toolbar-title")
                        yield Button("클리어", id="btn-clear-log", classes="toolbar-btn")
                    yield RichLog(id="elog", highlight=True, markup=True, wrap=True, max_lines=2000)
        yield Footer()

    # ── mount ─────────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        tt = self.query_one("#ttable", DataTable)
        tt.add_column("턴",   key="id",     width=4)
        tt.add_column("시각",  key="ts",     width=8)
        tt.add_column("모델",  key="model",  width=14)
        tt.add_column("요청",  key="reqs",   width=4)
        tt.add_column("탐지",  key="fc",     width=4)
        tt.add_column("액션",  key="action", width=8)
        ft = self.query_one("#ftable", DataTable)
        ft.add_column("시각",   width=8)
        ft.add_column("심각도", width=8)
        ft.add_column("규칙",   width=16)
        ft.add_column("신뢰도", width=5)
        ft.add_column("모델",   width=9)
        # 제어 탭 — 마스킹 규칙 테이블 (placeholder)
        mt = self.query_one("#mask-table", DataTable)
        mt.add_column("규칙",       key="rule",   width=22)
        mt.add_column("심각도",     key="sev",    width=10)
        mt.add_column("탐지",       key="hits",   width=6)
        mt.add_column("치환 텍스트", key="repl",   width=18)
        mt.add_column("상태",       key="status", width=10)
        alt = self.query_one("#allowlist-table", DataTable)
        alt.add_column("규칙", key="rule", width=14)
        alt.add_column("값", key="value", width=28)
        alt.add_column("만료", key="expires", width=20)
        self._init_mask_rules()
        self._init_control_file()
        self._init_asset_table()
        self._init_allowlist_table()
        self._load_history()
        self._init_pipeline_stats()
        self._set_selected_mask_rule(None, quiet=True)
        self._set_selected_asset(None, quiet=True)
        self._set_selected_allowlist(None, quiet=True)
        self._refresh_startup_warnings(show_popup=True)
        self._subscribe()
        self._poll()
        if self._sup:
            self._start_supervisor()
            self._poll_procs()

    async def on_unmount(self) -> None:
        if self._sup:
            await self._sup.stop()

    # ── 감시자 시작/상태 폴링 ─────────────────────────────────────────────────

    @work(exclusive=True, group="supervisor-init")
    async def _start_supervisor(self):
        await self._sup.start()
        # watch 태스크들은 supervisor 내부에서 영속 실행됨

    @work(exclusive=True, group="proc-poll")
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

    # inspect_traffic.py와 동기화되는 편집 가능한 마스킹 규칙 목록
    _MASK_RULES_DATA: list[tuple[str, str, str]] = [
        (rule, severity, DEFAULT_MASK_TEMPLATES.get(rule, "[REDACTED]"))
        for rule, severity in EDITABLE_MASK_RULES
    ]
    _STARTUP_WARNING_TIMEOUT = 4.0

    def _mask_rule_row(self, rule: str, sev: str, replacement: str, enabled: bool, hits: int, is_custom: bool = False) -> tuple:
        """DataTable에 적재할 행 튜플. enabled 여부로 색상 구분."""
        status = "[green bold]✅ ON[/]" if enabled else "[dim]⚫ OFF[/]"
        prefix = "🔧 " if is_custom else ""
        name_col = f"{prefix}{rule}" if enabled else f"[dim]{prefix}{rule}[/]"
        repl_col = replacement if enabled else f"[dim]{replacement}[/]"
        hits_col = f"[cyan]{hits}[/]" if hits else "[dim]0[/]"
        return (
            name_col,
            f"[{SEV_S.get(sev, '')}]{sev.upper()}[/]",
            hits_col,
            repl_col,
            status,
        )

    # 메모리 내 disabled_rules 상태 (파일 read/write 경쟁 방지)
    _disabled_rules: set = set()

    def _init_mask_rules(self):
        self._disabled_rules = set(self._read_control().get("disabled_rules", []))
        self._mask_rule_hits = {rule: 0 for rule, _, _ in self._MASK_RULES_DATA}
        mt = self.query_one("#mask-table", DataTable)
        templates = self._mask_templates()
        # 빌트인 규칙
        for rule, sev, repl in self._MASK_RULES_DATA:
            mt.add_row(
                *self._mask_rule_row(
                    rule, sev,
                    templates.get(rule, repl),
                    rule not in self._disabled_rules,
                    self._mask_rule_hits.get(rule, 0),
                ),
                key=rule,
            )
        # 커스텀 규칙
        for crule in self._read_control().get("custom_rules", []):
            if isinstance(crule, dict) and crule.get("name"):
                name = crule["name"]
                sev = str(crule.get("severity", "high"))
                mask = templates.get(name, str(crule.get("mask_template", f"[{name.upper()}]")))
                self._mask_rule_hits[name] = 0
                mt.add_row(
                    *self._mask_rule_row(name, sev, mask,
                                         name not in self._disabled_rules,
                                         0, is_custom=True),
                    key=name,
                )

    # ── 커스텀 탐지 규칙 ─────────────────────────────────────────────────────

    # ── 커스텀 탐지 규칙 (마스킹 규칙 카드 내 통합) ────────────────────────

    def _selected_custom_name(self) -> str | None:
        """현재 선택된 규칙이 커스텀 규칙이면 이름, 아니면 None."""
        rule = self._selected_mask_rule
        if not rule:
            return None
        for crule in self._read_control().get("custom_rules", []):
            if isinstance(crule, dict) and crule.get("name") == rule:
                return rule
        return None

    def _write_custom_rules(self, ctrl: dict) -> bool:
        """control.json에 커스텀 규칙 저장. 실패 시 False."""
        try:
            _CONTROL_FILE.write_text(json.dumps(ctrl, indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception as e:
            self._lg(f"[red][custom-rule] 파일 저장 실패: {e}[/]")
            return False

    @on(Button.Pressed, "#btn-mask-crule-add")
    def _btn_mask_crule_add(self, _: Button.Pressed) -> None:
        def _on_result(result: dict | None) -> None:
            if not result:
                return
            ctrl = self._read_control()
            rules: list = list(ctrl.get("custom_rules", []))
            names = {r.get("name") for r in rules if isinstance(r, dict)}
            if result["name"] in names:
                self._lg(f"[yellow][custom-rule] 이름 중복: {result['name']!r}[/]")
                return
            overrides = dict(ctrl.get("mask_templates", {}))
            overrides[result["name"]] = result.get("mask_template", f"[{result['name'].upper()}]")
            rules.append({
                "name": result["name"],
                "pattern": result["pattern"],
                "severity": result["severity"],
                "description": result.get("description", result["name"]),
                "mask_template": result.get("mask_template", f"[{result['name'].upper()}]"),
            })
            ctrl["custom_rules"] = rules
            ctrl["mask_templates"] = overrides
            if not self._write_custom_rules(ctrl):
                return
            self._refresh_mask_table()
            self._update_pipeline_tab()
            self._lg(f"[green][custom-rule] 추가: {result['name']!r} pattern={result['pattern']!r}[/]")

        self.push_screen(CustomRuleAddScreen(), _on_result)

    @on(Button.Pressed, "#btn-mask-crule-edit")
    def _btn_mask_crule_edit(self, _: Button.Pressed) -> None:
        name = self._selected_custom_name()
        if not name:
            self._lg("[dim][custom-rule] 커스텀 규칙을 선택하세요.[/]")
            return
        ctrl = self._read_control()
        current = next((r for r in ctrl.get("custom_rules", [])
                        if isinstance(r, dict) and r.get("name") == name), None)
        if not current:
            return

        def _on_result(result: dict | None) -> None:
            if not result:
                return
            ctrl2 = self._read_control()
            rules2: list = list(ctrl2.get("custom_rules", []))
            for i, r in enumerate(rules2):
                if isinstance(r, dict) and r.get("name") == name:
                    rules2[i] = {
                        "name": result["name"],
                        "pattern": result["pattern"],
                        "severity": result["severity"],
                        "description": result.get("description", result["name"]),
                        "mask_template": result.get("mask_template", f"[{result['name'].upper()}]"),
                    }
                    break
            overrides = dict(ctrl2.get("mask_templates", {}))
            if name != result["name"]:
                overrides.pop(name, None)
                if name in self._disabled_rules:
                    self._disabled_rules.discard(name)
                    self._disabled_rules.add(result["name"])
            overrides[result["name"]] = result.get("mask_template", f"[{result['name'].upper()}]")
            ctrl2["custom_rules"] = rules2
            ctrl2["mask_templates"] = overrides
            if not self._write_custom_rules(ctrl2):
                return
            self._refresh_mask_table()
            self._update_pipeline_tab()
            self._lg(f"[cyan][custom-rule] 편집 저장: {result['name']!r}[/]")

        self.push_screen(CustomRuleAddScreen(initial=current), _on_result)

    @on(Button.Pressed, "#btn-mask-crule-delete")
    def _btn_mask_crule_delete(self, _: Button.Pressed) -> None:
        name = self._selected_custom_name()
        if not name:
            self._lg("[dim][custom-rule] 커스텀 규칙을 선택하세요.[/]")
            return
        ctrl = self._read_control()
        ctrl["custom_rules"] = [r for r in ctrl.get("custom_rules", [])
                                 if not (isinstance(r, dict) and r.get("name") == name)]
        overrides = dict(ctrl.get("mask_templates", {}))
        overrides.pop(name, None)
        ctrl["mask_templates"] = overrides
        self._disabled_rules.discard(name)
        if not self._write_custom_rules(ctrl):
            return
        _patch_control("disabled_rules", list(self._disabled_rules))
        self._selected_mask_rule = None
        self._refresh_mask_table()
        self._update_pipeline_tab()
        self._lg(f"[yellow][custom-rule] 삭제: {name!r}[/]")

    def _refresh_mask_table(self):
        """빌트인 + 커스텀 규칙 모두 갱신. clear() 후 전체 재생성."""
        mt = self.query_one("#mask-table", DataTable)
        cursor_row = mt.cursor_coordinate.row
        self._refreshing = True
        mt.show_cursor = False
        templates = self._mask_templates()
        try:
            mt.clear()
            # 빌트인 규칙
            for rule, sev, repl in self._MASK_RULES_DATA:
                enabled = rule not in self._disabled_rules
                mt.add_row(
                    *self._mask_rule_row(rule, sev, templates.get(rule, repl),
                                         enabled, self._mask_rule_hits.get(rule, 0)),
                    key=rule,
                )
            # 커스텀 규칙
            for crule in self._read_control().get("custom_rules", []):
                if isinstance(crule, dict) and crule.get("name"):
                    name = crule["name"]
                    sev = str(crule.get("severity", "high"))
                    mask = templates.get(name, str(crule.get("mask_template", f"[{name.upper()}]")))
                    enabled = name not in self._disabled_rules
                    mt.add_row(
                        *self._mask_rule_row(name, sev, mask, enabled,
                                             self._mask_rule_hits.get(name, 0),
                                             is_custom=True),
                        key=name,
                    )
        finally:
            mt.show_cursor = True
            self._refreshing = False
        if mt.row_count > 0:
            mt.move_cursor(row=min(cursor_row, mt.row_count - 1), animate=False)
        self._set_selected_mask_rule(self._selected_mask_rule, quiet=True)

    _last_toggle_ts: float = 0.0  # 더블 토글 방지
    _refreshing: bool = False     # _refresh_mask_table 중 RowSelected 차단

    def _mask_templates(self) -> dict[str, str]:
        ctrl = self._read_control()
        return merge_mask_templates(ctrl.get("mask_templates", {}), allow_custom=True)

    def _event_request_id(self, ev: dict) -> str:
        return str(ev.get("id", "?"))

    def _pipeline_action_for_event(self, ev: dict) -> str:
        return str(ev.get("pipeline_action", "pass") or "pass").lower()

    def _applied_action_for_event(self, ev: dict) -> str:
        applied = str(ev.get("dlp_applied", "pass") or "pass").lower()
        return applied if applied in {"pass", "masked", "blocked"} else "pass"

    def _all_findings_for_event(self, ev: dict) -> list[dict]:
        return [finding for finding in ev.get("findings", []) if isinstance(finding, dict) and not finding.get("history")]

    def _all_findings_with_history(self, ev: dict) -> list[dict]:
        return [finding for finding in ev.get("findings", []) if isinstance(finding, dict)]

    def _targets_for_event(self, ev: dict) -> list[dict]:
        return [target for target in ev.get("targets", []) if isinstance(target, dict)]

    def _target_text_for_finding(self, ev: dict, finding: dict) -> str:
        field_path = str(finding.get("field_path", "") or "")
        role = str(finding.get("role", "") or "")
        for target in self._targets_for_event(ev):
            if str(target.get("field_path", "") or "") == field_path and str(target.get("role", "") or "") == role:
                return str(target.get("text", "") or "")
        for target in self._targets_for_event(ev):
            if str(target.get("field_path", "") or "") == field_path:
                return str(target.get("text", "") or "")
        return ""

    def _write_plain_block(self, log: RichLog, label: str, text: object, indent: str = "        ") -> None:
        log.write(label)
        raw = "" if text is None else str(text)
        lines = raw.splitlines() or [""]
        for line in lines:
            log.write(Text(f"{indent}{line}"))

    def _effective_findings_for_event(self, ev: dict) -> list[dict]:
        return [
            finding
            for finding in self._all_findings_for_event(ev)
            if not self._is_suppressed(finding) and not self._is_low_conf(finding.get("confidence", 0))
        ]

    def _raw_finding_count(self, ev: dict) -> int:
        value = ev.get("raw_finding_count", ev.get("finding_count"))
        if isinstance(value, (int, float)):
            return int(value)
        return len(self._all_findings_for_event(ev))

    def _effective_finding_count(self, ev: dict) -> int:
        value = ev.get("effective_finding_count")
        if isinstance(value, (int, float)):
            return int(value)
        return len(self._effective_findings_for_event(ev))

    def _suppressed_finding_count(self, ev: dict) -> int:
        value = ev.get("suppressed_finding_count")
        if isinstance(value, (int, float)):
            return int(value)
        return max(0, self._raw_finding_count(ev) - self._effective_finding_count(ev))

    def _display_action_for_event(self, ev: dict) -> str:
        applied = self._applied_action_for_event(ev)
        if applied == "masked":
            return "mask"
        if applied == "blocked":
            return "block"
        return "alert" if self._effective_finding_count(ev) > 0 else "pass"

    def _recompute_turn_state(self, turn: Turn) -> None:
        turn.fc = sum(self._effective_finding_count(req) for req in turn.reqs)
        turn.wa = "pass"
        for req in turn.reqs:
            action = self._display_action_for_event(req)
            if Turn._R.get(action, 0) > Turn._R.get(turn.wa, 0):
                turn.wa = action

    def _traffic_events(self) -> list[dict]:
        return [req for turn in self._tk.turns for req in turn.reqs]

    def _refresh_stats_bar_from_traffic(self) -> None:
        try:
            bar = self.query_one(StatsBar)
        except Exception:
            return
        events = self._traffic_events()
        bar.turns = len(self._tk.turns)
        bar.total = len(events)
        bar.scanned = len(events)
        bar.findings = sum(self._effective_finding_count(ev) for ev in events)
        bar.masked = sum(1 for ev in events if str(ev.get("dlp_applied", "pass") or "pass").lower() == "masked")

    def _apply_live_applied_update(self, request_id: object, dlp_applied: str) -> None:
        key = str(request_id)
        ev = self._live_events_by_request_id.get(key)
        if ev is None:
            return
        new_value = str(dlp_applied or "pass").lower()
        if str(ev.get("dlp_applied", "pass") or "pass").lower() == new_value:
            return
        ev["dlp_applied"] = new_value
        turn = self._live_event_turns.get(key)
        if turn is not None:
            self._recompute_turn_state(turn)
            self._utt(turn)
        self._refresh_stats_bar_from_traffic()
        if turn is not None and self._selected_turn_id == turn.id:
            self._show_turn_detail(turn.id)
        self._lg(f"[cyan][traffic] 적용 결과 갱신: #{key} → {new_value}[/]")

    def _mask_default_for(self, rule: str) -> str:
        # 빌트인 규칙
        if rule in DEFAULT_MASK_TEMPLATES:
            return DEFAULT_MASK_TEMPLATES[rule]
        # 커스텀 규칙: custom_rules에 저장된 mask_template
        for crule in self._read_control().get("custom_rules", []):
            if isinstance(crule, dict) and crule.get("name") == rule:
                return str(crule.get("mask_template", f"[{rule.upper()}]"))
        return f"[{rule.upper()}]"

    def _selected_asset(self) -> dict | None:
        _index, asset = _find_asset(_read_assets(), self._selected_asset_id)
        return asset

    def _selected_allowlist_entry(self) -> tuple[int, object] | None:
        if self._selected_allowlist_index is None:
            return None
        items = list(self._read_control().get("allowlist", []))
        if 0 <= self._selected_allowlist_index < len(items):
            return self._selected_allowlist_index, items[self._selected_allowlist_index]
        return None

    def _describe_allowlist_item(self, item: object) -> str:
        if isinstance(item, str):
            return f"전체:{item}"
        if isinstance(item, dict):
            rule = str(item.get("rule", "*") or "*")
            value = str(item.get("value", "") or "")
            return f"{rule}:{value}"
        return "선택된 항목 없음"

    def _set_selected_mask_rule(self, rule: str | None, quiet: bool = False) -> None:
        builtin_names = {name for name, _, _ in self._MASK_RULES_DATA}
        custom_names = {
            r["name"] for r in self._read_control().get("custom_rules", [])
            if isinstance(r, dict) and r.get("name")
        }
        all_valid = builtin_names | custom_names
        valid_rule = rule if rule in all_valid else None
        self._selected_mask_rule = valid_rule
        label = self.query_one("#mask-selection", Label)
        inp = self.query_one("#mask-edit-input", Input)
        is_custom = valid_rule in custom_names
        # 편집/삭제 버튼 활성·비활성
        try:
            self.query_one("#btn-mask-crule-edit", Button).disabled = not is_custom
            self.query_one("#btn-mask-crule-delete", Button).disabled = not is_custom
        except Exception:
            pass
        if valid_rule is None:
            label.update("선택된 규칙 없음")
            inp.value = ""
            inp.placeholder = "치환 텍스트"
            return
        enabled = valid_rule not in self._disabled_rules
        replacement = self._mask_templates().get(valid_rule, self._mask_default_for(valid_rule))
        badge = " 🔧" if is_custom else ""
        label.update(f"선택: {valid_rule}{badge}  상태: {'ON' if enabled else 'OFF'}")
        inp.value = replacement
        inp.placeholder = replacement
        if not quiet:
            self._lg(f"[cyan][mask] 선택: {valid_rule}[/]")

    def _set_selected_asset(self, asset_id: str | None, quiet: bool = False) -> None:
        _index, asset = _find_asset(_read_assets(), asset_id)
        self._selected_asset_id = str(asset.get("id", "")) if asset else None
        label = self.query_one("#asset-selection", Label)
        if asset is None:
            label.update("선택된 자산 없음")
            return
        keywords = ", ".join(str(k) for k in asset.get("keywords", [])[:3])
        label.update(f"선택: {asset.get('name', '')} ({asset.get('severity', 'high')})  {keywords}")
        if not quiet:
            self._lg(f"[cyan][asset] 선택: {asset.get('name', '')!r}[/]")

    def _set_selected_allowlist(self, index: int | None, quiet: bool = False) -> None:
        items = list(self._read_control().get("allowlist", []))
        self._selected_allowlist_index = index if index is not None and 0 <= index < len(items) else None
        label = self.query_one("#allowlist-selection", Label)
        if self._selected_allowlist_index is None:
            label.update("선택된 Allowlist 항목 없음")
            return
        item = items[self._selected_allowlist_index]
        label.update(f"선택: {self._describe_allowlist_item(item)}")
        if not quiet:
            self._lg(f"[cyan][allowlist] 선택: {self._describe_allowlist_item(item)}[/]")

    def _refresh_startup_warnings(self, show_popup: bool = False) -> None:
        self._startup_warnings = get_runtime_warning_lines()
        if show_popup and self._startup_warnings:
            self.notify(
                "\n".join(self._startup_warnings),
                title="런타임 경고",
                severity="warning",
                timeout=self._STARTUP_WARNING_TIMEOUT,
                markup=False,
            )

    def _toggle_selected_mask_rule(self) -> None:
        """선택된 규칙을 ON/OFF 토글 (150ms 디바운스로 더블 토글 방지)."""
        if not self._selected_mask_rule:
            self._lg("[dim][mask] 먼저 마스킹 규칙을 선택하세요.[/]")
            return
        if self._refreshing:
            return
        now = time.monotonic()
        if now - self._last_toggle_ts < 0.15:
            self._lg(f"[dim][mask] debounce skip: {self._selected_mask_rule!r}[/]")
            return
        self._last_toggle_ts = now
        rule_key = self._selected_mask_rule
        if rule_key in self._disabled_rules:
            self._disabled_rules.discard(rule_key)
            flag = True
        else:
            self._disabled_rules.add(rule_key)
            flag = False
        self._lg(f"[cyan][mask] toggle: {rule_key!r} → {'ON' if flag else 'OFF'} (disabled={sorted(self._disabled_rules)})[/]")
        _patch_control("disabled_rules", list(self._disabled_rules))
        self._refresh_mask_table()
        self._update_pipeline_tab()
        self._lg(f"[{'green' if flag else 'dim'}]{rule_key} 마스킹 {'ON' if flag else 'OFF'}[/]")

    def _save_selected_mask_rule(self) -> None:
        rule = self._selected_mask_rule
        if not rule:
            self._lg("[dim][mask] 먼저 마스킹 규칙을 선택하세요.[/]")
            return
        value = self.query_one("#mask-edit-input", Input).value.strip()
        if not value:
            self._lg("[yellow][mask] 치환 텍스트는 비워둘 수 없습니다.[/]")
            return
        ctrl = self._read_control()
        overrides = dict(ctrl.get("mask_templates", {}))
        if value == self._mask_default_for(rule):
            overrides.pop(rule, None)
        else:
            overrides[rule] = value
        _patch_control("mask_templates", overrides)
        self._refresh_mask_table()
        self._update_pipeline_tab()
        self._lg(f"[green][mask] 치환 텍스트 저장: {rule} → {value!r}[/]")

    @on(DataTable.RowSelected, "#mask-table")
    def _mask_rule_row_selected(self, e: DataTable.RowSelected):
        if self._refreshing:
            return
        self._set_selected_mask_rule(str(e.row_key.value), quiet=True)
        self._toggle_selected_mask_rule()

    @on(Button.Pressed, "#btn-copy-sent")
    def _btn_copy_sent(self, _: Button.Pressed) -> None:
        if not self._sent_text_cache.strip():
            self._lg("[dim][copy] 복사할 전송 내용이 없습니다.[/]")
            return
        self.copy_to_clipboard(self._sent_text_cache)
        self.notify("전송 내용을 클립보드에 복사했습니다.", title="복사 완료", timeout=2.0, markup=False)

    @on(Button.Pressed, "#btn-mask-save")
    def _btn_mask_save(self, _: Button.Pressed) -> None:
        self._save_selected_mask_rule()

    def _btn_mask_toggle(self, _: object) -> None:
        """테스트 호환용 — toggle_selected_mask_rule 직접 호출."""
        self._toggle_selected_mask_rule()

    @on(Input.Submitted, "#mask-edit-input")
    def _mask_edit_submit(self, _: Input.Submitted) -> None:
        self._save_selected_mask_rule()

    @on(Button.Pressed, "#btn-mask-reset")
    def _btn_mask_reset(self, _: Button.Pressed) -> None:
        rule = self._selected_mask_rule
        if not rule:
            self._lg("[dim][mask] 먼저 마스킹 규칙을 선택하세요.[/]")
            return
        ctrl = self._read_control()
        overrides = dict(ctrl.get("mask_templates", {}))
        overrides.pop(rule, None)
        _patch_control("mask_templates", overrides)
        self._refresh_mask_table()
        self._update_pipeline_tab()
        self._lg(f"[yellow][mask] 기본값 복원: {rule}[/]")

    def _init_asset_table(self) -> None:
        """보호 자산 테이블 초기화."""
        at = self.query_one("#asset-table", DataTable)
        at.add_column("이름",   key="name",     width=20)
        at.add_column("심각도", key="severity", width=10)
        at.add_column("키워드", key="keywords", width=30)
        self._refresh_asset_table()

    def _init_allowlist_table(self) -> None:
        self._refresh_allowlist_table()

    def _refresh_allowlist_table(self) -> None:
        alt = self.query_one("#allowlist-table", DataTable)
        alt.clear()
        raw_items = self._read_control().get("allowlist", [])
        for index, item in enumerate(raw_items):
            if isinstance(item, str):
                rule = "*"
                value = item.strip()
                expires_at = "-"
            elif isinstance(item, dict):
                rule = str(item.get("rule", "*") or "*").strip() or "*"
                value = str(item.get("value", "")).strip()
                expires_at = str(item.get("expires_at", "") or "-")
            else:
                continue
            if not value:
                continue
            alt.add_row(
                "전체" if rule == "*" else rule,
                value,
                expires_at,
                key=str(index),
            )
        self._set_selected_allowlist(self._selected_allowlist_index, quiet=True)

    def _append_allowlist_entry(self, rule: str, value: str) -> bool:
        return self._upsert_allowlist_entry(rule, value)

    def _upsert_allowlist_entry(self, rule: str, value: str, index: int | None = None) -> bool:
        clean_rule = (rule or "*").strip() or "*"
        clean_value = value.strip()
        normalized = _normalize_allowlist_value(clean_value)
        if not clean_value or not normalized:
            return False
        ctrl = self._read_control()
        allowlist = list(ctrl.get("allowlist", []))
        current_item = allowlist[index] if index is not None and 0 <= index < len(allowlist) else None
        for existing_index, item in enumerate(allowlist):
            if index is not None and existing_index == index:
                continue
            if isinstance(item, str):
                existing_rule = "*"
                existing_norm = _normalize_allowlist_value(item)
            elif isinstance(item, dict):
                existing_rule = str(item.get("rule", "*") or "*").strip() or "*"
                existing_norm = str(item.get("normalized", "")).strip() or _normalize_allowlist_value(str(item.get("value", "")))
            else:
                continue
            if existing_rule == clean_rule and existing_norm == normalized:
                self._lg(f"[dim][allowlist] 이미 등록됨: {clean_rule}:{clean_value!r}[/]")
                return False
        entry = {
            "rule": clean_rule,
            "value": clean_value,
            "normalized": normalized,
            "added_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        if isinstance(current_item, dict):
            if current_item.get("added_at"):
                entry["added_at"] = current_item.get("added_at")
            if current_item.get("expires_at"):
                entry["expires_at"] = current_item.get("expires_at")
        if index is not None and 0 <= index < len(allowlist):
            allowlist[index] = entry
            selected_index = index
            verb = "수정"
        else:
            allowlist.append(entry)
            selected_index = len(allowlist) - 1
            verb = "추가"
        _patch_control("allowlist", allowlist)
        self._refresh_allowlist_table()
        self._set_selected_allowlist(selected_index, quiet=True)
        self._update_pipeline_tab()
        self._lg(f"[green][allowlist] {verb}: {clean_rule}:{clean_value!r}[/]")
        return True

    def _selected_allowlist_candidate(self, quiet: bool = False) -> tuple[str, str] | None:
        if not self._selected_finding:
            if not quiet:
                self._lg("[dim][allowlist] 먼저 탐지 목록에서 항목 하나를 선택하세요.[/]")
            return None
        _, finding = self._selected_finding
        if finding.get("stage") != "regex":
            if not quiet:
                self._lg("[yellow][allowlist] Allowlist는 현재 정규식 탐지 항목에만 빠르게 추가할 수 있습니다.[/]")
            return None
        meta = finding.get("metadata") or {}
        rule = str(finding.get("rule") or "*").strip() or "*"
        value = str(meta.get("candidate_value") or finding.get("match_text") or "").strip()
        if not value:
            if not quiet:
                self._lg("[yellow][allowlist] 선택한 탐지에서 등록할 값을 찾지 못했습니다.[/]")
            return None
        return rule, value

    def _apply_threshold_input(self) -> None:
        inp = self.query_one("#ctrl-threshold-input", Input)
        raw = inp.value.strip() or "0.50"
        try:
            threshold = float(raw)
        except ValueError:
            self._lg(f"[yellow][control] 임계값이 올바르지 않습니다: {raw!r}[/]")
            inp.value = f"{self._threshold():.2f}"
            return
        threshold = min(max(threshold, 0.0), 1.0)
        _patch_control("confidence_threshold", threshold)
        inp.value = f"{threshold:.2f}"
        self._update_pipeline_tab()
        self._lg(f"[cyan][control] confidence_threshold → {threshold:.2f}[/]")

    def _refresh_asset_table(self) -> None:
        """assets.json을 읽어 자산 테이블 갱신."""
        at = self.query_one("#asset-table", DataTable)
        at.clear()
        sev_color = {"critical": "red", "high": "magenta", "medium": "yellow", "low": "dim"}
        for asset in _read_assets():
            name = asset.get("name", "")
            sev = asset.get("severity", "high")
            keywords = ", ".join(asset.get("keywords", []))
            color = sev_color.get(sev, "white")
            at.add_row(
                f"[bold]{name}[/]",
                f"[{color}]{sev}[/]",
                keywords,
                key=asset.get("id", name),
            )
        self._set_selected_asset(self._selected_asset_id, quiet=True)

    def _upsert_asset(self, asset: dict) -> None:
        assets = _read_assets()
        asset_id = str(asset.get("id", "")).strip()
        existing_index, _existing = _find_asset(assets, asset_id)
        if existing_index is None:
            assets.append(asset)
            verb = "추가"
        else:
            assets[existing_index] = asset
            verb = "수정"
        _write_assets(assets)
        self._refresh_asset_table()
        self._set_selected_asset(asset_id, quiet=True)
        self._update_pipeline_tab()
        self._lg(f"[green][asset] {verb}: {asset.get('name', '')!r}[/]")

    @on(Button.Pressed, "#btn-asset-add")
    def _btn_asset_add(self, _: Button.Pressed) -> None:
        """자산 추가 버튼 → 모달 다이얼로그."""
        def _on_result(result: dict | None) -> None:
            if result is None:
                return
            self._upsert_asset(result)

        self.push_screen(AssetAddScreen(), _on_result)

    @on(Button.Pressed, "#btn-asset-edit")
    def _btn_asset_edit(self, _: Button.Pressed) -> None:
        asset = self._selected_asset()
        if asset is None:
            self._lg("[dim][asset] 먼저 보호 자산을 선택하세요.[/]")
            return

        def _on_result(result: dict | None) -> None:
            if result is None:
                return
            self._upsert_asset(result)

        self.push_screen(AssetAddScreen(initial=asset), _on_result)

    @on(Button.Pressed, "#btn-asset-delete")
    def _btn_asset_delete(self, _: Button.Pressed) -> None:
        asset = self._selected_asset()
        if asset is None:
            self._lg("[dim][asset] 먼저 보호 자산을 선택하세요.[/]")
            return
        assets = [item for item in _read_assets() if str(item.get("id", "")) != str(asset.get("id", ""))]
        _write_assets(assets)
        self._selected_asset_id = None
        self._refresh_asset_table()
        self._set_selected_asset(None, quiet=True)
        self._update_pipeline_tab()
        self._lg(f"[yellow][asset] 삭제: {asset.get('name', '')!r}[/]")

    @on(DataTable.RowSelected, "#asset-table")
    def _asset_row_selected(self, e: DataTable.RowSelected) -> None:
        self._set_selected_asset(str(e.row_key.value))

    @on(DataTable.RowSelected, "#allowlist-table")
    def _allowlist_row_selected(self, e: DataTable.RowSelected) -> None:
        try:
            index = int(str(e.row_key.value))
        except ValueError:
            return
        self._set_selected_allowlist(index)

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
            self.query_one("#ctrl-threshold-input", Input).value = f"{float(ctrl.get('confidence_threshold', 0.5)):.2f}"
            # 설정 탭 스위치도 동기화
            self.query_one("#sw-regex", Switch).value = bool(ctrl.get("regex_enabled", True))
            self.query_one("#sw-asset", Switch).value = bool(ctrl.get("asset_enabled", True))
            self.query_one("#sw-slm", Switch).value = bool(ctrl.get("slm_enabled", False))
            # Role 스캔 스위치 동기화
            _skip = set(ctrl.get("skip_roles", ["system", "tool_def"]))
            self.query_one("#sw-role-user",        Switch).value = "user"        not in _skip
            self.query_one("#sw-role-tool-result", Switch).value = "tool_result" not in _skip
            self.query_one("#sw-role-tool-call",   Switch).value = "tool_call"   not in _skip
            self.query_one("#sw-role-system",      Switch).value = "system"      not in _skip
            self.query_one("#sw-role-tool-def",    Switch).value = "tool_def"    not in _skip
        except Exception:
            pass

    def _read_control(self) -> dict:
        try:
            return json.loads(_CONTROL_FILE.read_text())
        except Exception:
            return dict(_CTRL_DEFAULTS)

    def _threshold(self) -> float:
        try:
            return float(self._read_control().get("confidence_threshold", 0.5))
        except Exception:
            return 0.5

    def _is_low_conf(self, confidence: object) -> bool:
        return isinstance(confidence, (int, float)) and confidence < self._threshold()

    def _is_suppressed(self, finding: dict) -> bool:
        return bool(finding.get("suppressed", False))

    def _finding_prefix(self, finding: dict) -> str:
        tags: list[str] = []
        if self._is_suppressed(finding):
            tags.append("[dim][suppressed][/dim]")
        if self._is_low_conf(finding.get("confidence", 0)):
            tags.append("[dim][low-conf][/dim]")
        return " ".join(tags) + (" " if tags else "")

    def _format_conf(self, confidence: object, digits: int = 1) -> str:
        if not isinstance(confidence, (int, float)):
            return str(confidence)
        text = f"{confidence:.{digits}f}"
        return f"[dim]{text}[/]" if self._is_low_conf(confidence) else f"[bold]{text}[/]"

    def _bump_mask_rule_hit(self, rule: str):
        if rule not in self._mask_rule_hits:
            return
        self._mask_rule_hits[rule] += 1
        # 배치 디바운스: 즉시 전체 테이블 갱신 대신 call_later로 한번만 갱신
        if not self._bump_pending:
            self._bump_pending = True
            self.call_later(self._flush_mask_rule_hits)

    def _flush_mask_rule_hits(self) -> None:
        """디바운스된 마스킹 규칙 hit 카운트 반영 — hits 열만 갱신."""
        self._bump_pending = False
        mt = self.query_one("#mask-table", DataTable)
        for rule, hits in self._mask_rule_hits.items():
            if rule in mt.rows:
                hits_val = f"[cyan]{hits}[/]" if hits else "[dim]0[/]"
                try:
                    mt.update_cell(rule, "hits", hits_val, update_width=False)
                except Exception:
                    pass

    # ── 파이프라인 시각화 탭 ──────────────────────────────────────────────────

    def _init_pipeline_stats(self) -> None:
        self._pipeline_stats = {
            "regex": {"total": 0, "suppressed": 0, "conf_sum": 0.0},
            "asset": {"total": 0, "suppressed": 0, "conf_sum": 0.0},
            "slm":   {"total": 0, "conf_sum": 0.0},
            "nms_suppressed": 0,
            "conf_buckets": [0, 0, 0, 0, 0],  # 0-.3, .3-.5, .5-.7, .7-.9, .9-1.0
            "actions": {"pass": 0, "alert": 0, "mask": 0, "block": 0},
            "total_scans": 0,
        }
        self._update_pipeline_tab()

    def _update_pipeline_stats(self, ev: dict) -> None:
        s = self._pipeline_stats
        s["total_scans"] += 1
        action = ev.get("pipeline_action", ev.get("action", "pass"))
        bucket = s["actions"]
        bucket[action] = bucket.get(action, 0) + 1
        for f in ev.get("findings", []):
            stage     = (f.get("stage") or "").lower()
            conf      = float(f.get("confidence") or 0)
            suppressed = bool(f.get("suppressed", False))
            meta      = f.get("metadata") or {}
            allowlisted = bool(meta.get("allowlisted", False))
            suppressed_reason = str(meta.get("suppressed_reason", ""))
            if stage in s:
                s[stage]["total"] += 1
                s[stage]["conf_sum"] += conf
                if suppressed:
                    s[stage]["suppressed"] = s[stage].get("suppressed", 0) + 1
                    if suppressed_reason == "nms" or (suppressed_reason == "" and not allowlisted):
                        s["nms_suppressed"] += 1
            # 신뢰도 버킷 (억제되지 않은 탐지만)
            if not suppressed:
                if conf < 0.3:
                    s["conf_buckets"][0] += 1
                elif conf < 0.5:
                    s["conf_buckets"][1] += 1
                elif conf < 0.7:
                    s["conf_buckets"][2] += 1
                elif conf < 0.9:
                    s["conf_buckets"][3] += 1
                else:
                    s["conf_buckets"][4] += 1
        self._update_pipeline_tab()

    def _update_pipeline_tab(self) -> None:
        try:
            self.query_one("#pipeline-flow", Static).update(
                self._render_pipeline_flow()
            )
            self.query_one("#pipeline-ctrl-state", Static).update(
                self._render_pipeline_ctrl()
            )
            self.query_one("#pipeline-conf-hist", Static).update(
                self._render_pipeline_conf_hist()
            )
        except Exception:
            pass

    def _render_pipeline_flow(self) -> Group:
        s = self._pipeline_stats
        ctrl = self._read_control()
        threshold = float(ctrl.get("confidence_threshold", 0.5))
        regex_on  = bool(ctrl.get("regex_enabled", True))
        asset_on  = bool(ctrl.get("asset_enabled", True))
        slm_on    = bool(ctrl.get("slm_enabled", False))

        r  = s["regex"]
        a  = s["asset"]
        sl = s["slm"]
        nms_sup = s["nms_suppressed"]
        scans   = s["total_scans"]
        acts    = s["actions"]

        def avg(st: dict) -> str:
            return f"{st['conf_sum'] / st['total']:.2f}" if st["total"] else "  —  "

        def conf_style(st: dict) -> str:
            if not st["total"]:
                return "dim"
            v = st["conf_sum"] / st["total"]
            return "green" if v >= 0.7 else ("yellow" if v >= 0.5 else "dim")

        def stage_panel(icon: str, label: str, on: bool,
                        total: int, suppressed: int, avg_str: str, avg_sty: str) -> Panel:
            color  = "cyan" if on else "dim"
            badge  = Text("● ON", style="bold green") if on else Text("○ OFF", style="dim")
            grid   = Table.grid(padding=(0, 3))
            grid.add_column()
            grid.add_column()
            grid.add_column()
            grid.add_column()
            grid.add_row(
                Text("탐지:", style="dim"),
                Text(f"{total:>5}건", style="white"),
                Text("억제:", style="dim"),
                Text(f"{suppressed:>4}건", style="yellow"),
            )
            grid.add_row(
                Text("평균 신뢰도:", style="dim"),
                Text(avg_str, style=avg_sty),
                Text(""),
                Text(""),
            )
            title = Text()
            title.append(f"{icon} {label}  ")
            title.append_text(badge)
            return Panel(grid, title=title, title_align="left", border_style=color, padding=(0, 1))

        def arrow_text() -> Text:
            return Text("          │\n          ▼", style="dim")

        def nms_rule() -> Rule:
            title = Text()
            title.append(" ✂ NMS ", style="bold yellow")
            title.append("중첩 제거 ", style="dim")
            title.append(f"{nms_sup}건 ", style="yellow")
            title.append("억제 ", style="dim")
            return Rule(title=title, style="dim", characters="─")

        # 액션 카운터 테이블
        act_table = Table.grid(padding=(0, 0))
        act_table.add_column(justify="center", min_width=10)
        act_table.add_column(justify="center", min_width=10)
        act_table.add_column(justify="center", min_width=10)
        act_table.add_column(justify="center", min_width=10)
        act_table.add_row(
            Text("PASS",  style="dim"),
            Text("ALERT", style="bold yellow"),
            Text("MASK",  style="bold cyan"),
            Text("BLOCK", style="bold red"),
        )
        act_table.add_row(
            Text(str(acts.get("pass",  0)), style="dim",        justify="center"),
            Text(str(acts.get("alert", 0)), style="bold yellow", justify="center"),
            Text(str(acts.get("mask",  0)), style="bold cyan",   justify="center"),
            Text(str(acts.get("block", 0)), style="bold red",    justify="center"),
        )
        act_panel = Panel(act_table, title=f"decide_action  threshold={threshold:.2f}",
                          title_align="left", border_style="dim", padding=(0, 1))

        parts: list = [
            Text(f"══ 파이프라인 흐름  (누적 스캔: {scans}회) ══", style="bold"),
            Text(""),
            Text("  요청 텍스트", style="dim"),
            arrow_text(),
            stage_panel("🔍", "RegexStage  (12룰)", regex_on,
                        r["total"], r.get("suppressed", 0), avg(r), conf_style(r)),
            nms_rule(),
            arrow_text(),
            stage_panel("🛡", "AssetStage", asset_on,
                        a["total"], a.get("suppressed", 0), avg(a), conf_style(a)),
            arrow_text(),
            stage_panel("🤖", "SLM Stage  (Gemma 4 2B-IT)", slm_on,
                        sl["total"], 0, avg(sl), conf_style(sl)),
            arrow_text(),
            act_panel,
        ]
        return Group(*parts)

    def _render_pipeline_ctrl(self) -> Group:
        ctrl      = self._read_control()
        threshold = float(ctrl.get("confidence_threshold", 0.5))
        regex_on  = bool(ctrl.get("regex_enabled", True))
        ctx_on    = bool(ctrl.get("context_penalty_enabled", True))
        asset_on  = bool(ctrl.get("asset_enabled", True))
        slm_on    = bool(ctrl.get("slm_enabled", False))
        disabled  = ctrl.get("disabled_rules", [])
        allowlist = ctrl.get("allowlist", [])

        def flag(b: bool) -> Text:
            return Text("✅ ON", style="bold green") if b else Text("⚫ OFF", style="dim")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", min_width=12)
        grid.add_column()
        grid.add_row("신뢰도 임계값",  Text(f"{threshold:.2f}", style="bold cyan"))
        grid.add_row("Regex Stage",    flag(regex_on))
        grid.add_row("문맥 패널티",    flag(ctx_on))
        grid.add_row("보호 자산",      flag(asset_on))
        grid.add_row("SLM Stage",      flag(slm_on))
        grid.add_row("Allowlist",      Text(f"{len(allowlist)}개" if allowlist else "없음",
                                           style="white" if allowlist else "dim"))

        dis_text = Text(", ".join(disabled) if disabled else "없음",
                        style="white" if disabled else "dim")
        dis_grid = Table.grid(padding=(0, 2))
        dis_grid.add_column(style="dim")
        dis_grid.add_column()
        dis_grid.add_row("비활성 룰", dis_text)

        return Group(
            Text("══ 현재 파이프라인 설정 ══", style="bold"),
            Text(""),
            grid,
            Text(""),
            dis_grid,
        )

    def _render_pipeline_conf_hist(self) -> Group:
        buckets = self._pipeline_stats["conf_buckets"]
        total   = sum(buckets)
        labels  = ["0.0–0.3", "0.3–0.5", "0.5–0.7", "0.7–0.9", "0.9–1.0"]
        styles  = ["dim", "dim", "yellow", "green", "bold green"]
        BAR_W   = 12

        grid = Table.grid(padding=(0, 1))
        grid.add_column(min_width=7)   # 범위
        grid.add_column(min_width=BAR_W)  # 막대
        grid.add_column(min_width=7, justify="right")  # 건수
        grid.add_column(min_width=5, justify="right")  # 퍼센트

        for lbl, cnt, sty in zip(labels, buckets, styles):
            pct    = cnt / total if total else 0
            filled = round(pct * BAR_W)
            bar    = "█" * filled + "░" * (BAR_W - filled)
            grid.add_row(
                Text(lbl, style=sty),
                Text(bar, style=sty),
                Text(f"{cnt}건",        style="white"),
                Text(f"({pct:.0%})",    style="dim"),
            )

        suffix = Text(f"\n합계: {total}건", style="dim") if total else Text("(탐지 데이터 없음)", style="dim")

        return Group(
            Text("══ 신뢰도 분포 (억제 제외) ══", style="bold"),
            Text(""),
            grid,
            suffix,
        )

    def _append_audit(self, ev: dict):
        try:
            _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            if _AUDIT_FILE.exists() and _AUDIT_FILE.stat().st_size > _AUDIT_MAX_BYTES:
                if _AUDIT_ROTATED.exists():
                    _AUDIT_ROTATED.unlink()
                _AUDIT_FILE.rename(_AUDIT_ROTATED)
            payload = {
                "ts": ev.get("ts", ""),
                "request_id": ev.get("id", "?"),
                "provider": ev.get("provider", "?"),
                "model": ev.get("model", "?"),
                "action": ev.get("pipeline_action", "pass"),
                "finding_count": ev.get("finding_count", 0),
                "findings": ev.get("findings", []),
                "target_count": ev.get("target_count", 0),
                "total_text_len": ev.get("total_text_len", 0),
            }
            with open(_AUDIT_FILE, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    @on(Switch.Changed, "#sw-regex")
    def _sw_regex(self, e: Switch.Changed):
        _patch_control("regex_enabled", e.value)
        self._update_pipeline_tab()
        self._lg(f"[{'green' if e.value else 'yellow'}]Regex Stage {'ON' if e.value else 'OFF'}[/]")

    @on(Switch.Changed, "#sw-asset")
    def _sw_asset(self, e: Switch.Changed):
        _patch_control("asset_enabled", e.value)
        self._update_pipeline_tab()
        self._lg(f"[{'green' if e.value else 'yellow'}]Asset Stage {'ON' if e.value else 'OFF'}[/]")

    @on(Switch.Changed, "#sw-slm")
    def _sw_slm(self, e: Switch.Changed):
        _patch_control("slm_enabled", e.value)
        self._update_pipeline_tab()
        self._lg(f"[{'green' if e.value else 'yellow'}]sLM Stage {'ON' if e.value else 'OFF'}[/]")

    def _update_skip_roles(self):
        """Role 스위치 상태를 읽어 skip_roles 목록을 control 파일에 저장."""
        role_map = {
            "sw-role-user":        "user",
            "sw-role-tool-result": "tool_result",
            "sw-role-tool-call":   "tool_call",
            "sw-role-system":      "system",
            "sw-role-tool-def":    "tool_def",
        }
        skip: list[str] = []
        for sw_id, role in role_map.items():
            try:
                if not self.query_one(f"#{sw_id}", Switch).value:
                    skip.append(role)
            except Exception:
                pass
        _patch_control("skip_roles", skip)
        self._lg(f"[cyan]스캔 제외 Role: {skip if skip else '없음 (전체 스캔)'}[/]")

    @on(Switch.Changed, "#sw-role-user")
    def _sw_role_user(self, _: Switch.Changed):
        self._update_skip_roles()

    @on(Switch.Changed, "#sw-role-tool-result")
    def _sw_role_tool_result(self, _: Switch.Changed):
        self._update_skip_roles()

    @on(Switch.Changed, "#sw-role-tool-call")
    def _sw_role_tool_call(self, _: Switch.Changed):
        self._update_skip_roles()

    @on(Switch.Changed, "#sw-role-system")
    def _sw_role_system(self, _: Switch.Changed):
        self._update_skip_roles()

    @on(Switch.Changed, "#sw-role-tool-def")
    def _sw_role_tool_def(self, _: Switch.Changed):
        self._update_skip_roles()

    @on(Input.Submitted, "#ctrl-threshold-input")
    def _ctrl_threshold_submit(self, _: Input.Submitted):
        self._apply_threshold_input()

    @on(Button.Pressed, "#btn-threshold-save")
    def _btn_threshold_save(self, _: Button.Pressed):
        self._apply_threshold_input()

    @on(Button.Pressed, "#btn-allowlist-add")
    def _btn_allowlist_add(self, _: Button.Pressed) -> None:
        candidate = self._selected_allowlist_candidate(quiet=True)
        initial_rule = candidate[0] if candidate else "*"
        initial_value = candidate[1] if candidate else ""

        def _on_result(result: dict | None) -> None:
            if not result:
                return
            self._upsert_allowlist_entry(str(result.get("rule", "*")), str(result.get("value", "")))

        self.push_screen(AllowlistAddScreen(initial_rule=initial_rule, initial_value=initial_value), _on_result)

    @on(Button.Pressed, "#btn-allowlist-add-selected")
    def _btn_allowlist_add_selected(self, _: Button.Pressed) -> None:
        candidate = self._selected_allowlist_candidate()
        if not candidate:
            return
        rule, value = candidate
        self._upsert_allowlist_entry(rule, value)

    @on(Button.Pressed, "#btn-allowlist-edit")
    def _btn_allowlist_edit(self, _: Button.Pressed) -> None:
        selected = self._selected_allowlist_entry()
        if selected is None:
            self._lg("[dim][allowlist] 먼저 Allowlist 항목을 선택하세요.[/]")
            return
        index, item = selected
        if isinstance(item, str):
            initial_rule = "*"
            initial_value = item
        else:
            initial_rule = str(item.get("rule", "*") or "*")
            initial_value = str(item.get("value", "") or "")

        def _on_result(result: dict | None) -> None:
            if not result:
                return
            self._upsert_allowlist_entry(
                str(result.get("rule", "*")),
                str(result.get("value", "")),
                index=index,
            )

        self.push_screen(
            AllowlistAddScreen(
                initial_rule=initial_rule,
                initial_value=initial_value,
                title="📝 Allowlist 편집",
                submit_label="저장",
            ),
            _on_result,
        )

    @on(Button.Pressed, "#btn-allowlist-delete")
    def _btn_allowlist_delete(self, _: Button.Pressed) -> None:
        selected = self._selected_allowlist_entry()
        if selected is None:
            self._lg("[dim][allowlist] 먼저 Allowlist 항목을 선택하세요.[/]")
            return
        index, removed = selected
        raw_items = list(self._read_control().get("allowlist", []))
        if not (0 <= index < len(raw_items)):
            self._set_selected_allowlist(None, quiet=True)
            return
        raw_items.pop(index)
        _patch_control("allowlist", raw_items)
        self._selected_allowlist_index = None
        self._refresh_allowlist_table()
        self._set_selected_allowlist(None, quiet=True)
        self._update_pipeline_tab()
        self._lg(f"[yellow][allowlist] 삭제: {self._describe_allowlist_item(removed)}[/]")

    @on(Switch.Changed, "#ctrl-sw-mask-on-detect")
    def _ctrl_sw_mask_on_detect(self, e: Switch.Changed):
        _patch_control("mask_on_detect", e.value)
        self._update_pipeline_tab()
        self._lg(
            f"[{'cyan' if e.value else 'dim'}]마스킹 {'활성화 — 탐지된 PII를 치환 후 전달' if e.value else '비활성화'}[/]"
        )

    @on(Switch.Changed, "#ctrl-sw-block-alert")
    def _ctrl_sw_block_alert(self, e: Switch.Changed):
        _patch_control("block_on_alert", e.value)
        self._update_pipeline_tab()
        self._lg(f"[{'red' if e.value else 'green'}]ALERT 차단 {'활성화' if e.value else '비활성화'}[/]")

    @on(Switch.Changed, "#ctrl-sw-block-mask")
    def _ctrl_sw_block_mask(self, e: Switch.Changed):
        _patch_control("block_on_mask", e.value)
        self._update_pipeline_tab()
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
        self._live_events_by_request_id.clear()
        self._live_event_turns.clear()
        self._finding_rows.clear()
        self._selected_finding = None
        self._selected_turn_id = None
        self._sent_text_cache = ""
        self._init_pipeline_stats()
        self.query_one("#ttable", DataTable).clear()
        self.query_one("#ftable", DataTable).clear()
        self._refresh_stats_bar_from_traffic()
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
        self._selected_finding = None
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
        if hist:
            # 1단계: 모든 이벤트를 turn/stats 계산 (ftable 삽입 제외)
            with self.batch_update():
                for ev in evs:
                    self._one(ev, hist, skip_ftable=True)
            # 2단계: 마지막 _FTABLE_MAX_ROWS개 finding만 ftable에 삽입
            all_findings: list[tuple[dict, dict]] = []
            for ev in evs:
                for f in ev.get("findings", []):
                    all_findings.append((ev, f))
            tail = all_findings[-self._FTABLE_MAX_ROWS:]
            with self.batch_update():
                for ev, f in tail:
                    self._aft(ev, f)
            self._lg(f"[dim]히스토리: {len(evs)}건, {len(self._tk.turns)}개 턴 (탐지 {len(tail)}/{len(all_findings)}건 표시)[/]")
        else:
            with self.batch_update():
                for ev in evs:
                    self._one(ev, hist)

    def _one(self, ev: dict, hist: bool = False, skip_ftable: bool = False):
        model = ev.get("model") or "?"
        if not self._show_tg and model == "gpt-5-mini":
            return
        pa = self._display_action_for_event(ev)
        fc = self._effective_finding_count(ev)
        if not self._show_pass and pa == "pass" and fc == 0 and not hist:
            return
        turn = self._tk.ingest(ev)
        self._recompute_turn_state(turn)
        if not hist:
            req_id = self._event_request_id(ev)
            self._live_events_by_request_id[req_id] = ev
            self._live_event_turns[req_id] = turn
        self._utt(turn)
        if not skip_ftable:
            for f in ev.get("findings", []):
                if f.get("history"):
                    continue  # 이전 턴 히스토리 finding은 ftable에 표시하지 않음
                self._aft(ev, f)
        else:
            # skip_ftable=True 시에도 마스킹 규칙 히트 카운트는 집계
            for f in ev.get("findings", []):
                if f.get("history"):
                    continue
                c = f.get("confidence", 0)
                if not self._is_suppressed(f) and not self._is_low_conf(c):
                    self._mask_rule_hits[f.get("rule", "")] += 1
        self._refresh_stats_bar_from_traffic()
        if not hist:
            self._append_audit(ev)
        self._update_pipeline_stats(ev)

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
            # 기존 행 제자리 갱신 — remove+add보다 훨씬 빠르고 커서 위치 유지
            cols = ("id", "ts", "model", "reqs", "fc", "action")
            for col, val in zip(cols, vals):
                try:
                    tb.update_cell(rk, col, val, update_width=False)
                except Exception:
                    pass
        else:
            tb.add_row(*vals, key=rk)
        if self._auto:
            tb.move_cursor(row=tb.row_count - 1)
            self._show_turn_detail(t.id)

    _FTABLE_MAX_ROWS = 200  # ftable 최대 보관 행수, 초과 시 오래된 것부터 제거

    def _aft(self, ev: dict, f: dict):
        tb = self.query_one("#ftable", DataTable)
        sev = f.get("severity") or "?"
        c = f.get("confidence", 0)
        rk = f"f{self._finding_counter}"
        self._finding_counter += 1
        self._finding_rows[rk] = (ev, f)
        self._finding_row_order.append(rk)
        if not self._is_suppressed(f) and not self._is_low_conf(c):
            self._bump_mask_rule_hit(f.get("rule", ""))
        muted = self._is_low_conf(c) or self._is_suppressed(f)
        tb.add_row(
            _sts(ev.get("ts", "")),
            f"[dim]{sev.upper()}[/]" if muted else f"[{SEV_S.get(sev, '')}]{sev.upper()}[/]",
            f"[dim]{f.get('rule', '?')}[/]" if self._is_low_conf(c) or self._is_suppressed(f) else f.get("rule", "?"),
            self._format_conf(c, digits=1),
            _trunc(ev.get("model") or "?"),
            key=rk,
        )
        if self._auto:
            tb.move_cursor(row=tb.row_count - 1)
        # 오래된 행 제거 (500행 초과 시 앞에서부터 trim)
        while len(self._finding_row_order) > self._FTABLE_MAX_ROWS:
            old_rk = self._finding_row_order.pop(0)
            self._finding_rows.pop(old_rk, None)
            try:
                if old_rk in tb.rows:
                    tb.remove_row(old_rk)
            except Exception:
                pass

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
        self._selected_turn_id = None  # 강제 재렌더
        self._show_turn_detail(tid)

    def _show_turn_detail(self, tid: int):
        if tid < 1 or tid > len(self._tk.turns):
            return
        # 동일 턴 재선택이고 auto가 아닌 경우 중복 렌더 스킵
        if tid == self._selected_turn_id and not self._auto:
            return
        self._selected_turn_id = tid
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
        d.write(f"  액션   : [{ACT_S.get(t.wa, '')}]{ACT_LB.get(t.wa, t.wa.upper())}[/]")
        d.write("")
        for i, rq in enumerate(t.reqs):
            display_pa = self._display_action_for_event(rq)
            pipeline_pa = self._pipeline_action_for_event(rq)
            applied = self._applied_action_for_event(rq)
            effective_fc = self._effective_finding_count(rq)
            suppressed_fc = self._suppressed_finding_count(rq)
            history_fc = sum(1 for f in self._all_findings_with_history(rq) if f.get("history"))
            effective_findings = self._effective_findings_for_event(rq)
            suppressed_findings = [
                finding for finding in self._all_findings_for_event(rq)
                if finding not in effective_findings
            ]
            d.write(f"[bold]── 요청 #{rq.get('id','?')} ({i+1}/{len(t.reqs)}) ──[/]")
            d.write(f"  model: {rq.get('model','?')}  target: {rq.get('target_count',0)}개  "
                    f"text: {rq.get('total_text_len',0):,}자")
            status_line = (
                f"  최종 상태: [{ACT_S.get(display_pa,'')}]{ACT_LB.get(display_pa, display_pa.upper())}[/]  "
                f"유효탐지={effective_fc}"
            )
            if suppressed_fc:
                status_line += f"  [dim]억제={suppressed_fc}[/]"
            if history_fc:
                status_line += f"  [dim]히스토리={history_fc}[/]"
            status_line += f"  [dim]{rq.get('elapsed_ms',0)}ms[/]"
            d.write(status_line)
            if pipeline_pa != display_pa or applied != "pass":
                applied_label = {"pass": "PASS", "masked": "MASKED", "blocked": "BLOCKED"}.get(applied, applied.upper())
                applied_style = "green" if applied == "pass" else "cyan" if applied == "masked" else "bold red"
                d.write(
                    f"  엔진 판정: [{ACT_S.get(pipeline_pa,'')}]{ACT_LB.get(pipeline_pa, pipeline_pa.upper())}[/]  "
                    f"실제 처리: [{applied_style}]{applied_label}[/]"
                )
            if effective_findings:
                d.write(f"  [bold]유효 탐지 ({len(effective_findings)})[/]")
            for f in effective_findings:
                sev = f.get("severity") or "?"
                prefix = self._finding_prefix(f)
                d.write(f"    {prefix}[{SEV_S.get(sev,'')}]{sev.upper()}[/] "
                    f"{f.get('rule','?')} conf={f.get('confidence',0):.1f}")
                d.write(f"      경로: [dim]{markup_escape(f.get('field_path',''))}[/]")
                self._write_plain_block(d, "      매치 원문:", f.get("match_text", ""))
                cb = f.get("context_before", "")
                ca = f.get("context_after", "")
                if cb:
                    self._write_plain_block(d, "      앞 컨텍스트:", cb)
                if ca:
                    self._write_plain_block(d, "      뒤 컨텍스트:", ca)
            if suppressed_findings:
                d.write(f"  [dim]억제된 탐지 ({len(suppressed_findings)})[/]")
            for f in suppressed_findings:
                sev = f.get("severity") or "?"
                prefix = self._finding_prefix(f)
                d.write(f"    {prefix}[dim]{sev.upper()}[/] [dim]{f.get('rule','?')} conf={f.get('confidence',0):.1f}[/]")
                d.write(f"      [dim]경로: {markup_escape(f.get('field_path',''))}[/]")
                self._write_plain_block(d, "      [dim]매치 원문:[/]", f.get("match_text", ""))
                cb = f.get("context_before", "")
                ca = f.get("context_after", "")
                if cb:
                    self._write_plain_block(d, "      [dim]앞 컨텍스트:[/]", cb)
                if ca:
                    self._write_plain_block(d, "      [dim]뒤 컨텍스트:[/]", ca)
            event_targets = self._targets_for_event(rq)
            if event_targets:
                d.write("  [bold]대상 전체 내용[/]")
            for target in event_targets:
                role = str(target.get("role", "?") or "?")
                field_path = str(target.get("field_path", "") or "")
                self._write_plain_block(
                    d,
                    f"    {role} [dim]({markup_escape(field_path)})[/]",
                    target.get("text", ""),
                    indent="      ",
                )
            d.write("")
        # ── 전송 내용 탭 ─────────────────────────────────────────────────
        ds = self.query_one("#dsent", RichLog)
        ds.clear()
        sent_lines = [f"═══ Turn #{t.id} — 전송된 프롬프트 ═══", f"모델: {t.model}  msgs: {t.mc}", ""]
        ds.write(f"[bold]═══ Turn #{t.id} — 전송된 프롬프트 ═══[/]")
        ds.write(f"  모델: [green]{t.model}[/]  msgs: {t.mc}")
        ds.write("")
        for i, rq in enumerate(t.reqs):
            targets = rq.get("targets", [])
            applied = self._applied_action_for_event(rq)
            if not targets:
                ds.write(f"[dim]── 요청 #{rq.get('id','?')} — 전송 내용 없음 (히스토리) ──[/]")
                sent_lines.append(f"── 요청 #{rq.get('id','?')} — 전송 내용 없음 (히스토리) ──")
                sent_lines.append("")
                ds.write("")
                continue
            effective_findings = self._effective_findings_for_event(rq)
            effective_fc = len(effective_findings)
            suppressed_fc = self._suppressed_finding_count(rq)
            pipeline_pa = self._pipeline_action_for_event(rq)
            pa = self._display_action_for_event(rq)
            label = ACT_LB.get(pa, pa.upper())
            ds.write(f"[bold]── 요청 #{rq.get('id','?')} ({i+1}/{len(t.reqs)}) [{ACT_S.get(pa, '')}]{label}[/] ──[/]")
            sent_lines.append(f"── 요청 #{rq.get('id','?')} ({i+1}/{len(t.reqs)}) [{label}] ──")
            if applied == "blocked":
                ds.write("  [bold red]▶ 정책에 의해 차단되어 업스트림으로 전송되지 않음[/]")
                ds.write("")
                sent_lines.append("  ▶ 정책에 의해 차단되어 업스트림으로 전송되지 않음")
                sent_lines.append("")
                continue
            if applied == "masked":
                ds.write("  [cyan]▶ 실제 적용: 마스킹 후 전달[/]")
                sent_lines.append("  ▶ 실제 적용: 마스킹 후 전달")
            elif effective_fc > 0:
                if pipeline_pa in ("mask", "block"):
                    note = f"탐지는 있었지만 차단/마스킹 정책이 꺼져 있어 원문 그대로 전달 (엔진 판정: {ACT_LB.get(pipeline_pa, pipeline_pa.upper())})"
                else:
                    note = "탐지는 있었지만 원문 그대로 전달"
                ds.write(f"  [yellow]▶ {note}[/]")
                sent_lines.append(f"  ▶ {note}")
            elif suppressed_fc > 0:
                note = f"억제된 탐지 {suppressed_fc}건 — 최종 전송은 원문 PASS"
                ds.write(f"  [dim]▶ {note}[/]")
                sent_lines.append(f"  ▶ {note}")
            for tgt in targets:
                fp = tgt.get("field_path", "")
                role = tgt.get("role", "?")
                text = tgt.get("text", "")
                # 실제 마스킹이 적용된 요청만 전송 내용에 치환 텍스트 반영
                if applied == "masked" and effective_findings:
                    text = _simulate_mask(text, effective_findings, fp, self._threshold(), self._mask_templates())
                role_color = "cyan" if role == "system" else "green" if role == "assistant" else "yellow"
                ds.write(f"  [{role_color}]{role}[/] [dim]({markup_escape(fp)})[/]")
                sent_lines.append(f"  {role} ({fp})")
                if len(text) > 2000:
                    ds.write(Text(f"    {text[:2000]}"))
                    ds.write(f"    [dim]… ({len(text):,}자 중 2000자만 표시)[/]")
                    sent_lines.append(f"    {text[:2000]}")
                    sent_lines.append(f"    … ({len(text):,}자 중 2000자만 표시)")
                else:
                    ds.write(Text(f"    {text}"))
                    sent_lines.append(f"    {text}")
                ds.write("")
                sent_lines.append("")
        self._sent_text_cache = "\n".join(sent_lines).strip()

    # ── 탐지 상세 ─────────────────────────────────────────────────────────────

    @on(DataTable.RowSelected, "#ftable")
    def _sel_finding(self, e: DataTable.RowSelected):
        rk = str(e.row_key.value)
        pair = self._finding_rows.get(rk)
        if not pair:
            return
        self._selected_finding = pair
        ev, f = pair
        d = self.query_one("#fdetail", RichLog)
        d.clear()
        sev = f.get("severity") or "?"
        c = f.get("confidence", 0)
        pa = self._display_action_for_event(ev)
        pipeline_pa = self._pipeline_action_for_event(ev)
        applied = self._applied_action_for_event(ev)
        effective_fc = self._effective_finding_count(ev)
        suppressed_fc = self._suppressed_finding_count(ev)
        d.write(f"[bold]═══ 탐지 상세 ═══[/]")
        d.write(f"  시각    : {ev.get('ts', '')}")
        d.write(f"  모델    : [green]{ev.get('model', '?')}[/]")
        d.write(f"  제공자  : {ev.get('provider', '?')}")
        d.write(f"  최종 상태: [{ACT_S.get(pa, '')}]{ACT_LB.get(pa, pa.upper())}[/]")
        d.write(f"  엔진 판정: [{ACT_S.get(pipeline_pa, '')}]{ACT_LB.get(pipeline_pa, pipeline_pa.upper())}[/]")
        d.write(f"  실제 처리: [{'green' if applied == 'pass' else 'cyan' if applied == 'masked' else 'bold red'}]{ {'pass': 'PASS', 'masked': 'MASKED', 'blocked': 'BLOCKED'}.get(applied, applied.upper()) }[/]")
        d.write(f"  유효 탐지: [red]{effective_fc}[/]  [dim]억제={suppressed_fc}[/]")
        d.write(f"  스캔 시간: [dim]{ev.get('elapsed_ms', 0)}ms[/]")
        d.write("")
        d.write(f"[bold]── 탐지 규칙 ──[/]")
        d.write(f"  규칙    : [bold]{f.get('rule', '?')}[/]")
        d.write(f"  심각도  : [{SEV_S.get(sev, '')}]{sev.upper()}[/]")
        d.write(f"  신뢰도  : {self._format_conf(c, digits=2)}")
        d.write(f"  억제    : {'[dim]yes[/]' if self._is_suppressed(f) else 'no'}")
        d.write(f"  Stage   : [dim]{f.get('stage', '?')}[/]")
        d.write(f"  역할    : [dim]{f.get('role', '?')}[/]")
        d.write(f"  경로    : [dim]{markup_escape(f.get('field_path', ''))}[/]")
        d.write("")
        d.write(f"[bold]── 매치 내용 ──[/]")
        mt = f.get('match_text') or ''
        self._write_plain_block(d, f"  [{SEV_S.get(sev, '')}]매치 원문:[/]", mt, indent="    ")
        _f_rule = f.get('rule', '') or ''
        _repl = self._mask_templates().get(_f_rule, self._mask_default_for(_f_rule))
        d.write("")
        d.write(f"[bold]── 치환 미리보기 ──[/]")
        self._write_plain_block(d, "  원문:", mt, indent="    ")
        if applied == "masked":
            repl_label = "  [cyan]치환 결과[/] [dim](실제 전송됨)[/]"
        elif applied == "blocked":
            repl_label = "  [dim]치환 결과 (차단 — 미전송)[/]"
        else:
            repl_label = "  [dim]치환 결과 (시뮬레이션)[/]"
        self._write_plain_block(d, repl_label, _repl, indent="    ")
        # ── 파이프라인 처리 과정 (메타데이터) ─────────────────────────────
        meta = f.get("metadata") or {}
        stage = f.get("stage", "")
        if meta:
            d.write("")
            d.write(f"[bold]── 파이프라인 처리 과정 [dim](왜 이 신뢰도?)[/] ──[/]")
            if stage == "regex":
                # 코드 문맥 감지
                code_ctx = meta.get("code_context")
                if code_ctx is not None:
                    code_label = "[red]코드 문맥 감지됨 → ×0.3 패널티 적용[/]" if code_ctx else "[green]일반 텍스트[/]"
                    d.write(f"  코드 문맥  : {code_label}")
                # PII 키워드 배율
                mult = meta.get("context_multiplier")
                if mult is not None:
                    if mult >= 1.3:
                        mult_label = f"[bold green]×{mult:.1f}[/] (PII 키워드 2개 이상 — 확실한 PII 문맥)"
                    elif mult >= 1.0:
                        mult_label = f"[green]×{mult:.1f}[/] (PII 키워드 1개 — 중립)"
                    elif mult >= 0.7:
                        mult_label = f"[yellow]×{mult:.1f}[/] (미등록 룰 기본값)"
                    else:
                        mult_label = f"[dim]×{mult:.1f}[/] (PII 키워드 없음 — 의심도 낮음)"
                    d.write(f"  키워드 배율: {mult_label}")
                # validator floor
                vf = meta.get("validator_floor")
                if vf is not None:
                    d.write(f"  Validator 하한: [cyan]{vf}[/] (체크섬/Luhn 통과 시 최소 신뢰도)")
                # 후보값 (value_group)
                cand = meta.get("candidate_value")
                if cand and cand != mt:
                    d.write(f"  후보값     : [dim]{cand!r}[/] (allowlist 비교 대상)")
                # allowlist
                allowlisted = meta.get("allowlisted")
                if allowlisted is not None:
                    al_label = "[dim]yes — allowlist 일치 → 액션 제외[/]" if allowlisted else "no"
                    d.write(f"  Allowlist  : {al_label}")
            elif stage == "asset":
                # 자산 탐지 방식
                match_type = meta.get("match_type", "?")
                if match_type == "keyword":
                    kw = meta.get("keyword", "?")
                    d.write(f"  탐지 방식  : [bold cyan]키워드 매칭[/]")
                    d.write(f"  일치 키워드: [cyan]{kw!r}[/]  conf=1.0 (확정)")
                elif match_type == "embedding":
                    sim = meta.get("similarity", 0)
                    d.write(f"  탐지 방식  : [bold magenta]임베딩 유사도[/]")
                    d.write(f"  코사인 유사도: [magenta]{sim:.4f}[/]")
                    asset_id = meta.get("asset_id", "?")
                    d.write(f"  자산 ID    : [dim]{asset_id}[/]")
            elif stage == "slm":
                slm_conf = meta.get("slm_confidence") or c
                d.write(f"  SLM 확신도 : [cyan]{slm_conf:.4f}[/]")
            suppressed_reason = meta.get("suppressed_reason")
            if suppressed_reason == "nms":
                by_stage = meta.get("suppressed_by_stage", "?")
                by_rule = meta.get("suppressed_by_rule", "?")
                by_conf = meta.get("suppressed_by_confidence")
                by_match = meta.get("suppressed_by_match_text")
                d.write(f"  억제 사유  : [yellow]NMS 중첩 제거[/]")
                d.write(f"  유지 탐지  : [dim]{by_stage}:{by_rule}[/]")
                if isinstance(by_conf, (int, float)):
                    d.write(f"  유지 신뢰도: [cyan]{by_conf:.2f}[/]")
                if by_match:
                    d.write(f"  비교 대상  : [dim]{by_match!r}[/]")
        cb = f.get("context_before") or ""
        ca = f.get("context_after") or ""
        if cb or ca:
            d.write("")
            d.write(f"[bold]── 주변 컨텍스트 ──[/]")
            if cb:
                self._write_plain_block(d, "  앞 컨텍스트:", cb, indent="    ")
            if ca:
                self._write_plain_block(d, "  뒤 컨텍스트:", ca, indent="    ")

    # ── 엔진 구독 ────────────────────────────────────────────────────────────

    @work(exclusive=True, group="engine-subscribe")
    async def _subscribe(self):
        while True:
            w = None
            try:
                r, w = await asyncio.open_unix_connection(self._sock, limit=4 * 1024 * 1024)
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
                        elif ev.get("type") == "scan_applied":
                            self._apply_live_applied_update(ev.get("id"), str(ev.get("dlp_applied", "pass")))
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
        pa = self._display_action_for_event(ev)
        fc = self._effective_finding_count(ev)
        suppressed_fc = self._suppressed_finding_count(ev)
        pipeline_pa = self._pipeline_action_for_event(ev)
        suffix = f" [dim](engine={ACT_LB.get(pipeline_pa, pipeline_pa.upper())})[/]" if pipeline_pa != pa else ""
        suppressed_text = f" [dim]suppressed={suppressed_fc}[/]" if suppressed_fc else ""
        self._lg(
            f"[bold]#{ev.get('id','?')}[/] {ev.get('provider','?')} "
            f"[green]{ev.get('model','?')}[/] "
            f"[{ACT_S.get(pa,'')}]{ACT_LB.get(pa, pa.upper())}[/] "
            f"effective=[red]{fc}[/]{suppressed_text}{suffix} [dim]{ev.get('elapsed_ms',0)}ms[/]")
        for f in ev.get("findings", []):
            sev = f.get("severity") or "?"
            low_tag = self._finding_prefix(f)
            self._lg(
                f"  {low_tag}[{SEV_S.get(sev,'')}]{sev.upper()}[/] "
                f"{f.get('rule','?')} conf={f.get('confidence',0):.1f}: "
                f"{f.get('match_text','')[:60]!r} "
                f"[dim]@ {markup_escape(f.get('field_path','?'))}[/]")

    # ── 통계 폴링 (persistent 연결) ──────────────────────────────────────────

    @work(exclusive=True, group="engine-poll")
    async def _poll(self):
        await asyncio.sleep(1)  # 마운트 완료 대기
        while True:
            engine_ok = False
            try:
                # 매번 새 연결 사용 — 엔진 재시작 시도 확실히 감지
                r, w = await asyncio.wait_for(
                    asyncio.open_unix_connection(self._sock, limit=4 * 1024 * 1024), timeout=2.0)
                try:
                    w.write(json.dumps({"action": "ping", "id": -1}).encode() + b"\n")
                    await w.drain()
                    line = await asyncio.wait_for(r.readline(), timeout=3)
                    if not line:
                        raise ConnectionResetError
                    s = json.loads(line)
                    engine_ok = bool(s.get("ok"))
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
                self.query_one(StatsBar).engine_ok = engine_ok
            except Exception:
                pass
            self._update_pipeline_tab()
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
        self._live_events_by_request_id.clear()
        self._live_event_turns.clear()
        self._finding_rows.clear()
        self._finding_row_order.clear()
        self._finding_counter = 0
        self._selected_finding = None
        self._selected_turn_id = None
        self._sent_text_cache = ""
        self._init_pipeline_stats()
        self._refresh_startup_warnings()
        self.query_one("#ttable", DataTable).clear()
        self.query_one("#ftable", DataTable).clear()
        self.query_one("#fdetail", RichLog).clear()
        self._refresh_stats_bar_from_traffic()
        self._load_history()
        self._lg("[dim]새로고침…[/]")

    def action_quit(self):
        self.exit()

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
        "raw_finding_count": eng.get("raw_finding_count", eng.get("finding_count", 0)),
        "effective_finding_count": eng.get("effective_finding_count", 0),
        "suppressed_finding_count": eng.get("suppressed_finding_count", 0),
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
