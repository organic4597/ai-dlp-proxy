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
from engine.extractor import summarize_request, extract_messages as _extract_msgs_by_provider

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
    "zen.anthropic.com":                    "Anthropic",
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

TARGET_IP_PATTERNS: list[str] = []  # IP 기반 판별 미사용 — SNI 도메인으로만 처리

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


def _next_request_id() -> tuple[int, str]:
    """화면 표시용 순번과 DB/SSE용 고유 request_id를 함께 생성."""
    global _request_counter
    _request_counter += 1
    display_id = _request_counter
    unique_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
    return display_id, f"{unique_id}-{display_id:06d}"

# ── 패킷 캡처 플래그 ─────────────────────────────────────────────────────────
# /tmp/dlp-capture-next 파일이 존재하면 다음 LLM 요청 1개를 JSON으로 저장하고 삭제
_CAPTURE_FLAG = Path("/tmp/dlp-capture-next")
CAPTURE_OUT = LOG_DIR / "captured_packet.json"


def _provider(host: str, path: str = "") -> str | None:
    """SNI/도메인으로 LLM 제공자 판별. 대상 아니면 None."""
    if host in TARGET_HOSTS:
        return TARGET_HOSTS[host]
    if host.endswith(AZURE_SUFFIX):
        return "Azure OpenAI"
    return None


def _infer_provider_from_path_and_body(path: str, body: bytes) -> str | None:
    """URL 경로 + body의 model 필드로 provider 추정.
    SNI/Host 헤더로 도메인을 알 수 없을 때 사용하는 fallback.
    IP 주소로 provider를 추정하지 않음.
    """
    LLM_PATHS = ("/v1/messages", "/v1/chat/completions", "/v1/completions", "/v1/embeddings")
    if not any(p in path for p in LLM_PATHS):
        return None

    model = ""
    if body:
        try:
            obj = json.loads(body)
            model = str(obj.get("model", "")).lower()
        except Exception:
            pass

    # model 이름으로 판별 (가장 정확)
    if "claude" in model:
        return "Anthropic"
    if any(k in model for k in ("gpt-", "o1-", "o3-", "o4-", "text-davinci")):
        return "OpenAI"
    if any(k in model for k in ("gemini", "palm", "bison")):
        return "Gemini"
    if "deepseek" in model:
        return "DeepSeek"
    if "llama" in model:
        return "Meta"
    if "mistral" in model or "mixtral" in model:
        return "Mistral"
    if "grok" in model:
        return "xAI"

    # model 이름이 없거나 모르면 API 형식으로 추정
    if "/v1/messages" in path:
        return "Anthropic"       # Messages API = Anthropic 형식
    if "/v1/chat/completions" in path:
        return "OpenAI"          # Chat Completions = OpenAI 형식
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

        # TLS 인터셉트 범위 설정 — allow_hosts는 어떤 TLS를 복호화할지 결정
        # ※ provider 판별과 무관 — SNI/Host/URL/model로 별도 판별
        # SNI가 없는 클라이언트(IP 직접 연결)를 위해 알려진 IP 대역도 포함
        try:
            _target_patterns = [
                re.escape(host) for host in TARGET_HOSTS
            ] + [
                r".*\.openai\.azure\.com",
                # GitHub / Copilot IP 대역 — SNI 없이 IP로 직접 연결하는 클라이언트용
                # (intercept 범위 설정일 뿐, provider는 Host헤더/URL/model로 판별)
                r"140\.82\.\d{1,3}\.\d{1,3}",
                r"185\.199\.\d{1,3}\.\d{1,3}",
                r"192\.30\.\d{1,3}\.\d{1,3}",
            ]
            ctx.options.allow_hosts = _target_patterns
            log.info(
                f"[CONFIG] ✓ TLS 인터셉트 대상 {len(_target_patterns)}개 패턴으로 제한"
            )
            for p in _target_patterns:
                log.debug(f"[CONFIG]   allow: {p}")
        except Exception as e:
            log.warning(f"[CONFIG] allow_hosts 설정 실패 (무시): {e}")

        log.info(f"[CONFIG] DLP Engine 서버: UDS {_ENGINE_SOCK} (별도 프로세스)")

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path

        # 1단계: SNI/도메인으로 판별 (pretty_host는 SNI가 있으면 도메인 반환)
        provider = _provider(host, path)

        if provider is None:
            # 2단계: Host 헤더로 판별 (IP 직접 연결이지만 Host 헤더에 도메인 있는 경우)
            host_header = flow.request.headers.get("host", "").split(":")[0].lower()
            if host_header and host_header != host:
                provider = _provider(host_header, path)

        if provider is None:
            # 3단계: URL 경로 + body model 필드로 판별 (IP 기반 추정 없음)
            provider = _infer_provider_from_path_and_body(path, flow.request.content or b"")

        if provider is None:
            return

        # ── 헬스체크/토큰 교환 요청 건너뜀 ──────────────────────────────────
        # body가 없거나 GitHub 토큰 경로면 실제 LLM 요청이 아님 → 기록/검사 생략
        body_check = flow.request.content or b""
        content_type_check = flow.request.headers.get("content-type", "")
        if not body_check or "json" not in content_type_check:
            return

        display_id, req_id = _next_request_id()

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
            f"{C.BOLD}[REQ #{display_id}]{C.RESET}  {ts}  {C.BOLD}▶{C.RESET}  {pc}{provider}{C.RESET}",
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
                dlp_summary = _summarize_request(obj, provider, lines, url=url)
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
                    "messages": _extract_messages(body_obj, provider, url=url),
                    "provider": provider,
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
            _pa = result.get("protection_action", result.get("pipeline_action", "pass"))
            _findings = result.get("protection_findings") or result.get("findings", [])
            try:
                _threshold = float(_ctrl.get("confidence_threshold", 0.5))
            except (TypeError, ValueError):
                _threshold = 0.5
            _effective_findings = [
                finding
                for finding in _findings
                if (
                    float(finding.get("confidence", 0.0)) >= _threshold
                    and not finding.get("suppressed", False)
                    and not finding.get("history", False)
                )
            ]

            # mask_on_detect: suppressed 여부 무관하게 threshold 이상 탐지 마스킹
            # (ML FP 필터가 억제해도 사용자가 명시적으로 마스킹 요청한 경우 적용)
            _mask_candidates = (
                _effective_findings
                if not _ctrl.get("mask_on_detect")
                else [
                    f for f in _findings
                    if float(f.get("confidence", 0.0)) >= _threshold
                ]
            )
            _has_effective = bool(_effective_findings)
            _do_mask  = bool(_ctrl.get("mask_on_detect") and _mask_candidates)
            _do_block = (
                _has_effective and not _do_mask and (
                    (_pa in ("mask", "block") and _ctrl.get("block_on_mask")) or
                    (_pa == "alert"           and _ctrl.get("block_on_alert"))
                )
            )

            if not _has_effective and _findings:
                lines.append(
                    f"  {C.DIM}[DLP] effective finding 없음(억제/히스토리/threshold 미달) → policy 미적용{C.RESET}"
                )

            if _do_mask and _mask_candidates:
                # 마스킹 적용 후 flow.request.content 교체
                masked_body = _apply_mask(body_obj, _mask_candidates, _mask_templates)
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
                    f"  {C.CYAN}{C.BOLD}[DLP MASKED] {len(_mask_candidates)}개 필드 마스킹 후 통과"
                    f"  ({len(body_raw)}B → {len(masked_bytes)}B){C.RESET}"
                )
                for f in _mask_candidates:
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
            "request_id": req_id,
            "display_id": display_id,
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
                jsonl_record["messages"] = _extract_messages(_raw_obj, provider, url=url)
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
            return
        # 요청 body에 stream:true 포함 시 (타겟 호스트 스트리밍 API)
        host = flow.request.pretty_host
        # stream 여부: HOST 헤더도 확인
        _h = host if host in TARGET_HOSTS else flow.request.headers.get("host", "").split(":")[0].lower()
        if _h in TARGET_HOSTS and flow.request.content:
            try:
                req_body = json.loads(flow.request.content)
                if req_body.get("stream") is True:
                    flow.response.stream = True
            except Exception:
                pass


def _summarize_request(obj: dict, provider: str, lines: list, url: str = "") -> dict:
    """공급자별 파서의 summarize()로 위임. 로그 라인(터미널 출력)은 여기서 포맷."""
    if provider == "GitHub Copilot (Auth)":
        lines.append(f"    {C.RED}[AUTH TOKEN EXCHANGE]{C.RESET}")
        return {"auth_exchange": True}

    # /v1/messages 경로는 Anthropic 포맷으로 파싱하되, Copilot은 전용 어댑터를 사용
    effective_provider = "Anthropic" if "/v1/messages" in url and provider != "GitHub Copilot" else provider
    summary = summarize_request(effective_provider, obj)
    if not summary:
        return {}

    # OpenAI 계열
    if "msg_count" in summary and "tool_count" in summary:
        model    = summary.get("model", "N/A")
        stream   = summary.get("stream", False)
        msg_key  = summary.get("msg_key", "messages")
        messages = summary.get("messages", [])
        tools_n  = summary.get("tool_count", 0)
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  stream={stream}  {msg_key}={len(messages)}개  tools={tools_n}개")
        for i, msg in enumerate(messages):
            role    = msg.get("role", "?")
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = [p.get("text", "") for p in content
                              if p.get("type") in ("text", "input_text", "output_text")]
                img_count = sum(1 for p in content if p.get("type") in ("image_url", "input_image"))
                content_preview = " | ".join(text_parts)
                if img_count:
                    content_preview += f" + [image×{img_count}]"
            else:
                content_preview = str(content)
            preview    = content_preview[:200].replace("\n", "↵")
            role_color = C.CYAN if role == "system" else C.GREEN if role == "assistant" else C.YELLOW
            lines.append(f"    {msg_key}[{i}] {role_color}role={role}{C.RESET}: {preview}")
        return {"model": model, "stream": stream, "msg_count": len(messages), "tool_count": tools_n}

    # Anthropic
    if "system" in summary and "messages" in summary and "content_count" not in summary:
        model    = summary.get("model", "N/A")
        stream   = summary.get("stream", False)
        messages = summary.get("messages", [])
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  stream={stream}  messages={len(messages)}개")
        sys_text = summary.get("system", "")
        if sys_text:
            lines.append(f"    {C.CYAN}system{C.RESET}: {sys_text}")
        for i, msg in enumerate(messages):
            role    = msg.get("role", "?")
            content = msg.get("content", "")
            lines.append(f"    messages[{i}] role={role}: {str(content)[:200].replace(chr(10), '↵')}")
        return {"model": model, "stream": stream, "msg_count": len(messages)}

    # Gemini
    if "content_count" in summary:
        model    = summary.get("model", "N/A")
        contents = summary.get("contents", [])
        lines.append(f"    {C.GREEN}model={model}{C.RESET}  contents={len(contents)}개")
        sys_text = summary.get("system", "")
        if sys_text:
            lines.append(f"    {C.CYAN}systemInstruction{C.RESET}: {sys_text}")
        for i, c in enumerate(contents):
            role  = c.get("role", "?")
            parts = c.get("parts", [])
            text  = " ".join(p.get("text", "") for p in parts if "text" in p)
            lines.append(f"    contents[{i}] role={role}: {text[:200].replace(chr(10), '↵')}")
        return {"model": model, "content_count": len(contents)}

    return summary


def _extract_messages(obj: dict, provider: str, url: str = "") -> list[dict]:
    """공급자별 파서의 extract_messages()로 위임."""
    # /v1/messages 경로는 Anthropic 포맷으로 파싱하되, Copilot은 전용 어댑터를 사용
    effective_provider = "Anthropic" if "/v1/messages" in url and provider != "GitHub Copilot" else provider
    return _extract_msgs_by_provider(effective_provider, obj)




# mitmproxy가 로드할 addon 인스턴스
addons = [InspectAddon()]
