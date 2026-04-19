"""
Phase 1 — 패킷 구조 확인용 mitmproxy addon (v2)
외부 LLM API 호출 시 나가는 요청/응답을 복호화해서 콘솔 및 로그 파일에 기록.
수정·차단 없이 read-only 관찰만 수행.

실행:
    mitmdump --listen-host 0.0.0.0 -p 4001 -s scripts/inspect_traffic.py
"""

import asyncio
import json
import logging
import re
import socket
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

_SRC_DIR = Path(__file__).parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from engine.pipeline.masking import merge_mask_templates

from mitmproxy import ctx, http

# ── 엔진 서버 연결 설정 (별도 프로세스, UDS) ──────────────────────────────────
_ENGINE_SOCK = "/tmp/dlp-engine.sock"
_ENGINE_TIMEOUT = 5.0  # 초
_ENGINE_STREAM_LIMIT = 4 * 1024 * 1024  # asyncio StreamReader 라인 버퍼 (서버와 동일)

# 영속 연결 관리
_engine_reader: asyncio.StreamReader | None = None
_engine_writer: asyncio.StreamWriter | None = None
_engine_lock = asyncio.Lock()


async def _engine_connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """엔진 서버에 UDS 연결. 실패 시 None."""
    global _engine_reader, _engine_writer
    try:
        _engine_reader, _engine_writer = await asyncio.wait_for(
            asyncio.open_unix_connection(_ENGINE_SOCK, limit=_ENGINE_STREAM_LIMIT),
            timeout=2.0,
        )
        return _engine_reader, _engine_writer
    except (ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError, OSError, FileNotFoundError):
        _engine_reader = _engine_writer = None
        return None


async def _engine_request(payload: dict) -> dict | None:
    """엔진 서버에 NDJSON 요청을 보내고 응답 수신. 연결 실패 시 None."""
    global _engine_reader, _engine_writer
    async with _engine_lock:
        # 연결이 없거나 닫혔으면 재연결
        if _engine_writer is None or _engine_writer.is_closing():
            if await _engine_connect() is None:
                return None

        try:
            data = json.dumps(payload, ensure_ascii=False).encode() + b"\n"
            _engine_writer.write(data)
            await _engine_writer.drain()
            line = await asyncio.wait_for(_engine_reader.readline(), timeout=_ENGINE_TIMEOUT)
            if not line:
                _engine_reader = _engine_writer = None
                return None
            return json.loads(line)
        except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError, OSError):
            _engine_reader = _engine_writer = None
            return None
        except Exception:
            _engine_reader = _engine_writer = None
            return None

# ── 로그 파일 설정 ────────────────────────────────────────────────────────────
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "traffic.log"

# JSON Lines 형식의 구조화된 로그 (파싱/분석용)
JSONL_FILE = LOG_DIR / "traffic.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(stream=open(sys.stderr.fileno(), mode="w", encoding="utf-8", buffering=1, closefd=False)),
    ],
)
log = logging.getLogger("dlp.inspect")

# 구조화된 로그용 별도 로거
_jsonl_handler = logging.FileHandler(JSONL_FILE, encoding="utf-8")
_jsonl_handler.setFormatter(logging.Formatter("%(message)s"))
jsonl_log = logging.getLogger("dlp.jsonl")
jsonl_log.addHandler(_jsonl_handler)
jsonl_log.setLevel(logging.INFO)
jsonl_log.propagate = False

# ── 감시 대상 도메인 ──────────────────────────────────────────────────────────
TARGET_HOSTS = {
    # OpenAI 계열
    "api.openai.com":                       "OpenAI",
    # Anthropic
    "api.anthropic.com":                    "Anthropic",
    # Google Gemini
    "generativelanguage.googleapis.com":    "Gemini",
    # GitHub Copilot
    "api.githubcopilot.com":                "GitHub Copilot",
    "api.individual.githubcopilot.com":     "GitHub Copilot",
    "copilot-proxy.githubusercontent.com":  "GitHub Copilot",
    # Groq / Together / Mistral / OpenRouter
    "api.groq.com":                         "Groq",
    "api.together.ai":                      "Together",
    "api.mistral.ai":                       "Mistral",
    "openrouter.ai":                        "OpenRouter",
    # DeepSeek
    "api.deepseek.com":                     "DeepSeek",
    # xAI
    "api.x.ai":                             "xAI",
}

# Azure OpenAI 패턴: *.openai.azure.com
AZURE_SUFFIX = ".openai.azure.com"

# GitHub Copilot 토큰 교환 (api.github.com) — 경로 필터링 필요
GITHUB_TOKEN_PATHS = {
    "/copilot_internal/v2/token",
    "/login/oauth/access_token",
    "/login/device/code",
}

# ── 헤더 중 로깅에서 제외할 민감 키 ─────────────────────────────────────────
REDACT_HEADERS = {
    "authorization", "x-api-key", "api-key",
    "cookie", "set-cookie",
    "copilot-integration-id",
}

# ── ANSI 색상 (터미널 출력용) ────────────────────────────────────────────────
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

SEPARATOR = f"{C.DIM}{'═' * 90}{C.RESET}"

_MASK_DEFAULT = "[REDACTED]"


def _parse_field_path(path: str) -> list:
    """
    "messages[2].content[0].text" → ["messages", 2, "content", 0, "text"]
    """
    import re as _re
    tokens: list = []
    for segment in path.split("."):
        m = _re.match(r'^([^\[]+)((?:\[\d+\])*)$', segment)
        if not m:
            tokens.append(segment)
            continue
        key = m.group(1)
        if key:
            tokens.append(key)
        for idx_str in _re.findall(r'\[(\d+)\]', m.group(2)):
            tokens.append(int(idx_str))
    return tokens


def _get_nested(obj, tokens: list):
    """tokens 경로로 nested dict/list 값 반환. 실패 시 None."""
    cur = obj
    for tok in tokens:
        try:
            cur = cur[tok]
        except (KeyError, IndexError, TypeError):
            return None
    return cur


def _set_nested(obj, tokens: list, value) -> bool:
    """tokens 경로의 마지막 키에 value 설정. 성공 여부 반환."""
    if not tokens:
        return False
    cur = obj
    for tok in tokens[:-1]:
        try:
            cur = cur[tok]
        except (KeyError, IndexError, TypeError):
            return False
    try:
        cur[tokens[-1]] = value
        return True
    except (KeyError, IndexError, TypeError):
        return False


def _apply_mask(body_obj: dict, findings: list[dict], mask_templates: dict[str, str]) -> dict:
    """
    findings의 field_path/match_start/match_end를 이용해
    body_obj를 deep copy 없이 직접 수정 — 마스킹 텍스트로 교체.
    같은 field에 여러 finding이 있으면 뒤 offset부터 역순 적용하여
    앞 offset이 밀리지 않도록 함.
    """
    # field_path 별로 findings를 그룹화
    by_path: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("field_path", "")
        by_path.setdefault(fp, []).append(f)

    for path, path_findings in by_path.items():
        tokens = _parse_field_path(path)
        text = _get_nested(body_obj, tokens)
        if not isinstance(text, str):
            continue
        # offset 역순으로 적용 (큰 offset 먼저 교체 → 앞 offset 불변)
        for f in sorted(path_findings, key=lambda x: x.get("match_start", 0), reverse=True):
            rule = f.get("rule", "")
            replacement = mask_templates.get(rule, _MASK_DEFAULT)
            start = f.get("match_start", 0)
            end   = f.get("match_end",   0)
            if start < 0 or end <= start or end > len(text):
                # offset 이상 시 match_text 기반 단순 대체
                match_text = f.get("match_text", "")
                if match_text:
                    text = text.replace(match_text, replacement, 1)
            else:
                text = text[:start] + replacement + text[end:]
        _set_nested(body_obj, tokens, text)

    return body_obj


# ── 요청 시작 시간 추적 ─────────────────────────────────────────────────────
_flow_timings: dict[str, float] = {}
_request_counter = 0

# ── 패킷 캡처 플래그 ─────────────────────────────────────────────────────────
# /tmp/dlp-capture-next 파일이 존재하면 다음 LLM 요청 1개를 JSON으로 저장하고 삭제
_CAPTURE_FLAG = Path("/tmp/dlp-capture-next")
CAPTURE_OUT = LOG_DIR / "captured_packet.json"


def _provider(host: str, path: str = "") -> str | None:
    """호스트 이름으로 LLM 제공자 판별. 대상 아니면 None."""
    if host in TARGET_HOSTS:
        return TARGET_HOSTS[host]
    if host.endswith(AZURE_SUFFIX):
        return "Azure OpenAI"
    # api.github.com 토큰 교환 — 감시 대상 제외
    return None


def _safe_headers(headers) -> dict:
    """민감 헤더 값을 [REDACTED]로 치환한 딕셔너리 반환."""
    return {
        k: ("[REDACTED]" if k.lower() in REDACT_HEADERS else v)
        for k, v in headers.items()
    }


def _fmt_json(raw: bytes) -> str:
    """바이트 → pretty JSON 문자열. 파싱 실패 시 원본 텍스트 반환."""
    try:
        obj = json.loads(raw)
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return raw.decode("utf-8", errors="replace")


def _truncate(text: str, max_len: int = 4000) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... [truncated {len(text) - max_len} chars]"


def _provider_color(provider: str) -> str:
    """프로바이더별 색상 반환."""
    colors = {
        "OpenAI":                C.GREEN,
        "Anthropic":             C.MAGENTA,
        "Gemini":                C.BLUE,
        "GitHub Copilot":        C.CYAN,
        "GitHub Copilot (Auth)": C.CYAN,
        "Azure OpenAI":          C.BLUE,
        "Groq":                  C.YELLOW,
        "DeepSeek":              C.GREEN,
        "xAI":                   C.RED,
    }
    return colors.get(provider, C.YELLOW)


def _write_jsonl(record: dict) -> None:
    """구조화된 JSON Lines 로그 기록."""
    try:
        jsonl_log.info(json.dumps(record, ensure_ascii=False, default=str))
    except Exception:
        pass


# ── mitmproxy addon 클래스 ───────────────────────────────────────────────────
class InspectAddon:

    def running(self) -> None:
        """프록시 시작 후 1회 호출 — HTTP/2 비활성화, IPv4 강제."""
        # IPv6 차단 — getaddrinfo에서 AF_INET6 결과 제거
        _orig_getaddrinfo = socket.getaddrinfo
        def _ipv4_only_getaddrinfo(*args, **kwargs):
            results = _orig_getaddrinfo(*args, **kwargs)
            ipv4 = [r for r in results if r[0] == socket.AF_INET]
            return ipv4 if ipv4 else results  # IPv4 없으면 원본 반환
        socket.getaddrinfo = _ipv4_only_getaddrinfo
        log.info("[CONFIG] ✓ IPv6 차단 → 업스트림 IPv4 전용")

        try:
            ctx.options.http2 = False
            log.info("[CONFIG] ✓ HTTP/2 비활성화 → 업스트림 연결 HTTP/1.1 강제")
        except Exception as e:
            log.warning(f"[CONFIG] HTTP/2 옵션 설정 실패 (무시): {e}")

        # 타겟 호스트만 TLS 인터셉트 — 나머지는 mitmproxy가 투명하게 터널링
        # allow_hosts에 없는 호스트는 TLS 복호화 없이 TCP 터널로 그대로 통과
        try:
            _target_patterns = [
                re.escape(host) for host in TARGET_HOSTS
            ] + [r".*\.openai\.azure\.com"]  # Azure OpenAI 와일드카드
            ctx.options.allow_hosts = _target_patterns
            log.info(
                f"[CONFIG] ✓ TLS 인터셉트 대상 {len(_target_patterns)}개 호스트로 제한"
            )
            for p in _target_patterns:
                log.debug(f"[CONFIG]   allow: {p}")
        except Exception as e:
            log.warning(f"[CONFIG] allow_hosts 설정 실패 (무시): {e}")

        log.info(f"[CONFIG] DLP Engine 서버: UDS {_ENGINE_SOCK} (별도 프로세스)")

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path
        provider = _provider(host, path)
        if provider is None:
            return

        # ── 헬스체크/토큰 교환 요청 건너뜀 ──────────────────────────────────
        # body가 없거나 GitHub 토큰 경로면 실제 LLM 요청이 아님 → 기록/검사 생략
        body_check = flow.request.content or b""
        content_type_check = flow.request.headers.get("content-type", "")
        if not body_check or "json" not in content_type_check:
            return

        global _request_counter
        _request_counter += 1
        req_id = _request_counter

        # 타이밍 시작
        _flow_timings[flow.id] = time.monotonic()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        method = flow.request.method
        url = flow.request.pretty_url
        headers = _safe_headers(flow.request.headers)
        headers_raw = dict(flow.request.headers)  # 원본 (redact 전)
        body_raw = flow.request.content or b""

        # ── 패킷 전체 캡처 (플래그 파일이 있을 때 1회) ───────────────────────
        if _CAPTURE_FLAG.exists():
            try:
                _CAPTURE_FLAG.unlink()  # 플래그 삭제 (1회만)
                content_type_raw = flow.request.headers.get("content-type", "")
                body_parsed = None
                if "json" in content_type_raw and body_raw:
                    try:
                        body_parsed = json.loads(body_raw)
                    except Exception:
                        pass
                capture = {
                    "captured_at": ts,
                    "method": method,
                    "url": url,
                    "http_version": flow.request.http_version,
                    "headers": headers_raw,
                    "body_size": len(body_raw),
                    "body": body_parsed if body_parsed is not None else body_raw.decode("utf-8", errors="replace"),
                }
                CAPTURE_OUT.write_text(json.dumps(capture, ensure_ascii=False, indent=2), encoding="utf-8")
                log.info(f"[CAPTURE] ✓ 패킷 저장 완료 → {CAPTURE_OUT}")
            except Exception as _ce:
                log.warning(f"[CAPTURE] 저장 실패: {_ce}")

        # Content-Type 판별
        content_type = flow.request.headers.get("content-type", "")
        if "json" in content_type:
            body_fmt = _fmt_json(body_raw)
        elif "multipart" in content_type:
            body_fmt = f"[multipart/form-data — {len(body_raw)} bytes]"
        else:
            body_fmt = body_raw.decode("utf-8", errors="replace")

        pc = _provider_color(provider)
        lines = [
            SEPARATOR,
            f"{C.BOLD}[REQ #{req_id}]{C.RESET}  {ts}  {C.BOLD}▶{C.RESET}  {pc}{provider}{C.RESET}",
            f"  {C.CYAN}{method}{C.RESET} {url}",
            f"  {C.DIM}Content-Length: {len(body_raw)}  Content-Type: {content_type}{C.RESET}",
            f"  {C.DIM}Headers:{C.RESET}",
            *[f"    {C.DIM}{k}: {v}{C.RESET}" for k, v in headers.items()],
            f"  {C.BOLD}Body:{C.RESET}",
            textwrap.indent(_truncate(body_fmt), "    "),
        ]

        # JSON 바디의 핵심 필드 요약 출력
        dlp_summary = {}
        if "json" in content_type and body_raw:
            lines.append(f"  {C.YELLOW}── DLP 대상 필드 요약 ──{C.RESET}")
            try:
                obj = json.loads(body_raw)
                dlp_summary = _summarize_request(obj, provider, lines)
            except Exception:
                pass

        # ── DLP Engine 서버 호출 (별도 프로세스, UDS) ─────────────────────────
        result = None
        body_obj = None
        if "json" in content_type and body_raw:
            try:
                body_obj = json.loads(body_raw)
                result = await _engine_request({
                    "action": "scan",
                    "id": req_id,
                    "host": host,
                    "url": flow.request.pretty_url,
                    "content_type": content_type,
                    "body": body_obj,
                    "msg_count": dlp_summary.get("msg_count", 0),
                    "messages": _extract_messages(body_obj, provider),
                })
                if result is None:
                    lines.append(f"  {C.DIM}[Engine 미연결 — UDS {_ENGINE_SOCK}]{C.RESET}")
                elif result.get("matched"):
                    tc = result.get("target_count", 0)
                    tl = result.get("total_text_len", 0)
                    ems = result.get("elapsed_ms", "?")
                    pa = result.get("pipeline_action", "pass")
                    fc = result.get("finding_count", 0)
                    efc = result.get("effective_finding_count", fc)

                    action_c = {
                        "pass": C.GREEN, "alert": C.YELLOW,
                        "mask": C.RED, "block": C.RED,
                    }.get(pa, C.RESET)

                    lines.append(
                        f"  {C.BOLD}── Engine: {tc}개 대상 ({tl:,}자) "
                        f"{action_c}[{pa.upper()}]{C.RESET} "
                        f"findings={fc} effective={efc}  {C.DIM}{ems}ms{C.RESET} ──"
                    )
                    for f in result.get("findings", []):
                        sev_c = {
                            "critical": C.RED, "high": C.MAGENTA,
                            "medium": C.YELLOW, "low": C.DIM,
                        }.get(f.get("severity", ""), C.RESET)
                        prefix = ""
                        if f.get("suppressed"):
                            prefix = f"{C.DIM}[suppressed]{C.RESET} "
                        lines.append(
                            f"    {prefix}{sev_c}[{f.get('severity','?').upper()}]{C.RESET} "
                            f"{f.get('rule','?')}: {f.get('match_text','')[:60]!s} "
                            f"@ {C.DIM}{f.get('field_path','')}{C.RESET}"
                        )
            except Exception as _eng_err:
                lines.append(f"  {C.RED}[Engine 오류] {_eng_err}{C.RESET}")

        # ── 제어 파일 기반 마스킹/차단 정책 적용 ─────────────────────────────
        # 정책 키:
        #   mask_on_detect  — 탐지 시 본문 마스킹 후 통과 (우선순위 높음)
        #   block_on_mask   — pipeline_action=mask/block 일 때 403 차단
        #   block_on_alert  — pipeline_action=alert 일 때 403 차단
        _applied_action = "pass"
        if result and result.get("matched") and body_obj is not None:
            try:
                _ctrl: dict = json.loads(Path("/tmp/dlp-control.json").read_text())
            except Exception:
                _ctrl = {}
            _mask_templates = merge_mask_templates(_ctrl.get("mask_templates", {}), allow_custom=True)
            _pa = result.get("pipeline_action", "pass")
            _findings = result.get("findings", [])
            try:
                _threshold = float(_ctrl.get("confidence_threshold", 0.5))
            except (TypeError, ValueError):
                _threshold = 0.5
            _effective_findings = [
                finding
                for finding in _findings
                if float(finding.get("confidence", 0.0)) >= _threshold and not finding.get("suppressed", False)
            ]

            _do_mask  = bool(_ctrl.get("mask_on_detect") and _pa in ("mask", "alert"))
            _do_block = (
                not _do_mask and (
                    (_pa in ("mask", "block") and _ctrl.get("block_on_mask")) or
                    (_pa == "alert"           and _ctrl.get("block_on_alert"))
                )
            )

            if _do_mask and _effective_findings:
                # 마스킹 적용 후 flow.request.content 교체
                masked_body = _apply_mask(body_obj, _effective_findings, _mask_templates)
                masked_bytes = json.dumps(masked_body, ensure_ascii=False).encode("utf-8")
                flow.request.content = masked_bytes
                # Content-Length 재계산 (mitmproxy는 bytes length 기준)
                flow.request.headers["content-length"] = str(len(masked_bytes))
                _applied_action = "masked"
                # 엔진 카운터 증가 (fire-and-forget)
                asyncio.ensure_future(
                    _engine_request({"action": "masked_inc", "id": req_id})
                )
                lines.append(
                    f"  {C.CYAN}{C.BOLD}[DLP MASKED] {len(_effective_findings)}개 필드 마스킹 후 통과"
                    f"  ({len(body_raw)}B → {len(masked_bytes)}B){C.RESET}"
                )
                for f in _effective_findings:
                    lines.append(
                        f"    {C.CYAN}▸ {f.get('rule','?')}: "
                        f"{f.get('match_text','')[:40]!r} → "
                        f"{_mask_templates.get(f.get('rule',''), _MASK_DEFAULT)}{C.RESET}"
                    )

            elif _do_block:
                flow.response = http.Response.make(
                    403,
                    b'{"error":"DLP policy: request blocked"}',
                    {"Content-Type": "application/json"},
                )
                _applied_action = "blocked"
                lines.append(
                    f"  {C.RED}{C.BOLD}[DLP BLOCKED] "
                    f"action={_pa.upper()} → 403 반환{C.RESET}"
                )

            if _applied_action in ("masked", "blocked"):
                asyncio.ensure_future(
                    _engine_request({
                        "action": "applied_result",
                        "id": req_id,
                        "dlp_applied": _applied_action,
                    })
                )

        log.info("\n".join(lines))

        # 구조화된 JSONL 로그 (엔진 결과 포함)
        jsonl_record = {
            "type": "request",
            "id": req_id,
            "ts": ts,
            "provider": provider,
            "method": method,
            "url": url,
            "host": host,
            "path": path,
            "content_type": content_type,
            "body_size": len(body_raw),
            "dlp_applied": _applied_action,
            "dlp_summary": dlp_summary,
        }
        if "json" in content_type and body_raw:
            jsonl_record["engine"] = result if result else None
            # 실제 메시지 내용 로깅
            try:
                _raw_obj = json.loads(body_raw) if body_obj is None else body_obj
                jsonl_record["messages"] = _extract_messages(_raw_obj, provider)
            except Exception:
                pass
        _write_jsonl(jsonl_record)

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path
        provider = _provider(host, path)
        if provider is None:
            return

        # 응답 시간 계산
        start = _flow_timings.pop(flow.id, None)
        elapsed_ms = round((time.monotonic() - start) * 1000) if start else None

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        status = flow.response.status_code
        content_type = flow.response.headers.get("content-type", "")
        body_raw = flow.response.content or b""

        if "event-stream" in content_type:
            body_fmt = f"[SSE stream — Content-Type: text/event-stream]"
        elif "json" in content_type:
            body_fmt = _fmt_json(body_raw)
        else:
            body_fmt = body_raw.decode("utf-8", errors="replace")

        pc = _provider_color(provider)
        # 상태 코드 색상
        if status < 300:
            sc = C.GREEN
        elif status < 400:
            sc = C.YELLOW
        else:
            sc = C.RED

        elapsed_str = f"  {C.DIM}({elapsed_ms}ms){C.RESET}" if elapsed_ms is not None else ""

        lines = [
            f"{C.BOLD}[RES]{C.RESET}     {ts}  {C.BOLD}◀{C.RESET}  {pc}{provider}{C.RESET}  {sc}HTTP {status}{C.RESET}{elapsed_str}",
            f"  Content-Type: {content_type}",
            f"  Body ({len(body_raw)} bytes):",
            textwrap.indent(_truncate(body_fmt), "    "),
        ]
        log.info("\n".join(lines))

        # 구조화된 JSONL 로그
        _write_jsonl({
            "type": "response",
            "ts": ts,
            "provider": provider,
            "status": status,
            "content_type": content_type,
            "body_size": len(body_raw),
            "elapsed_ms": elapsed_ms,
            "is_stream": "event-stream" in content_type,
        })

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """SSE 스트리밍 응답은 stream=True 설정해야 응답 소실 방지 (Bug #4469)."""
        content_type = flow.response.headers.get("content-type", "")
        if "event-stream" in content_type:
            flow.response.stream = True


def _summarize_request(obj: dict, provider: str, lines: list) -> dict:
    """요청 JSON에서 DLP 검사 대상 필드를 요약해서 lines에 추가. 구조화된 요약 반환."""
    summary: dict = {}

    if provider in ("OpenAI", "Azure OpenAI", "Groq", "Together", "OpenRouter",
                     "Mistral", "GitHub Copilot", "DeepSeek", "xAI"):
        model = obj.get("model", "N/A")
        stream = obj.get("stream", False)
        messages = obj.get("messages", [])
        tools = obj.get("tools", [])
        summary = {"model": model, "stream": stream, "msg_count": len(messages), "tool_count": len(tools)}
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  stream={stream}  messages={len(messages)}개  tools={len(tools)}개")
        for i, msg in enumerate(messages):
            role = msg.get("role", "?")
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = [p.get("text", "") for p in content if p.get("type") == "text"]
                img_count = sum(1 for p in content if p.get("type") == "image_url")
                content_preview = " | ".join(text_parts)
                if img_count:
                    content_preview += f" + [image×{img_count}]"
            else:
                content_preview = str(content)
            preview = content_preview[:200].replace("\n", "↵")
            role_color = C.CYAN if role == "system" else C.GREEN if role == "assistant" else C.YELLOW
            lines.append(f"    messages[{i}] {role_color}role={role}{C.RESET}: {preview}")

    elif provider == "Anthropic":
        model = obj.get("model", "N/A")
        stream = obj.get("stream", False)
        system = obj.get("system", "")
        messages = obj.get("messages", [])
        summary = {"model": model, "stream": stream, "msg_count": len(messages)}
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  stream={stream}  messages={len(messages)}개")
        if system:
            lines.append(f"    {C.CYAN}system{C.RESET}: {str(system)[:200].replace(chr(10), '↵')}")
        for i, msg in enumerate(messages):
            role = msg.get("role", "?")
            content = msg.get("content", "")
            preview = str(content)[:200].replace("\n", "↵")
            lines.append(f"    messages[{i}] role={role}: {preview}")

    elif provider == "Gemini":
        model = obj.get("model", "N/A")
        contents = obj.get("contents", [])
        sys_inst = obj.get("systemInstruction", {})
        summary = {"model": model, "content_count": len(contents)}
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  contents={len(contents)}개")
        if sys_inst:
            parts = sys_inst.get("parts", [])
            text = " ".join(p.get("text", "") for p in parts)
            lines.append(f"    {C.CYAN}systemInstruction{C.RESET}: {text[:200].replace(chr(10), '↵')}")
        for i, c in enumerate(contents):
            role = c.get("role", "?")
            parts = c.get("parts", [])
            text = " ".join(p.get("text", "") for p in parts if "text" in p)
            lines.append(f"    contents[{i}] role={role}: {text[:200].replace(chr(10), '↵')}")

    elif provider == "GitHub Copilot (Auth)":
        # 토큰 교환 요청 — 민감 정보이므로 존재 여부만 기록
        lines.append(f"    {C.RED}[AUTH TOKEN EXCHANGE]{C.RESET}")
        summary = {"auth_exchange": True}

    return summary


# ── 메시지 내용 추출 (JSONL 로그용) ─────────────────────────────────────────

_MSG_MAX = 2000  # 메시지 하나당 최대 문자 수 (로그 용량 절약)


def _extract_messages(obj: dict, provider: str) -> list[dict]:
    """요청 바디에서 실제 대화 메시지를 추출해 [{role, content}] 리스트로 반환.

    content가 긴 경우 _MSG_MAX 자로 truncate.
    system / tool_result / tool_use 등 비-사용자 메시지도 포함.
    """
    msgs: list[dict] = []

    def _clip(text: str) -> str:
        if len(text) <= _MSG_MAX:
            return text
        return text[:_MSG_MAX] + f"…[+{len(text) - _MSG_MAX}chars]"

    def _content_str(content) -> str:
        if isinstance(content, str):
            return _clip(content)
        if isinstance(content, list):
            parts = []
            for part in content:
                if not isinstance(part, dict):
                    continue
                t = part.get("type", "")
                if t == "text":
                    parts.append(part.get("text", ""))
                elif t == "image_url":
                    parts.append("[image]")
                elif t == "tool_use":
                    parts.append(f"[tool_use: {part.get('name', '?')}]")
                elif t == "tool_result":
                    inner = part.get("content", "")
                    if isinstance(inner, list):
                        inner = " ".join(p.get("text", "") for p in inner if isinstance(p, dict))
                    parts.append(f"[tool_result: {str(inner)[:200]}]")
                else:
                    parts.append(f"[{t}]")
            return _clip(" ".join(parts))
        return _clip(str(content))

    # OpenAI 호환 (OpenAI, Azure, Groq, Together, Mistral, OpenRouter,
    #               GitHub Copilot, DeepSeek, xAI)
    if provider in (
        "OpenAI", "Azure OpenAI", "Groq", "Together", "Mistral",
        "OpenRouter", "GitHub Copilot", "DeepSeek", "xAI",
    ):
        for msg in obj.get("messages", []):
            role    = msg.get("role", "?")
            content = msg.get("content", "")
            name    = msg.get("name")
            entry: dict = {"role": role, "content": _content_str(content)}
            if name:
                entry["name"] = name
            msgs.append(entry)

    # Anthropic
    elif provider == "Anthropic":
        sys_prompt = obj.get("system", "")
        if sys_prompt:
            msgs.append({"role": "system", "content": _clip(str(sys_prompt))})
        for msg in obj.get("messages", []):
            msgs.append({
                "role":    msg.get("role", "?"),
                "content": _content_str(msg.get("content", "")),
            })

    # Google Gemini
    elif provider == "Gemini":
        si = obj.get("systemInstruction", {})
        if si:
            parts = si.get("parts", [])
            text  = " ".join(p.get("text", "") for p in parts if "text" in p)
            if text:
                msgs.append({"role": "system", "content": _clip(text)})
        for c in obj.get("contents", []):
            role  = c.get("role", "?")
            parts = c.get("parts", [])
            text  = " ".join(p.get("text", "") for p in parts if "text" in p)
            if text:
                msgs.append({"role": role, "content": _clip(text)})

    return msgs


# mitmproxy가 로드할 addon 인스턴스
addons = [InspectAddon()]
