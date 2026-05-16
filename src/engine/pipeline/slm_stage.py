"""
SLM Stage — llama-cpp-python 기반 소형 언어 모델 PII 보완 탐지.

Regex Stage가 놓친 문맥 의존적 PII(예: 이름+소속 조합, 자유형식 주소 등)를
SLM(Gemma 4 2B-IT)으로 검증·보완합니다.

동작 방식
---------
1. 입력 텍스트를 CHUNK_CHARS 단위로 분할
2. 각 청크를 프롬프트로 감싸 SLM에 전달
3. SLM이 JSON 배열로 PII 위치/종류 반환
4. Regex Stage findings와 중복 제거 후 Finding 객체 생성

GBNF grammar으로 JSON 출력 강제 → hallucination 방지
"""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any

from .base import Finding, Severity, Stage

log = logging.getLogger(__name__)

# ── 상수 ─────────────────────────────────────────────────────────────────────

DEFAULT_MODEL_PATH = str(
    Path(__file__).parents[3] / "models" / "gemma-4-2b-it-q4_k_m.gguf"
)
DEFAULT_ADAPTER_MODEL_PATH = str(
    Path(__file__).parents[3] / "fine-tunning" / "sLM" / "merged_v5"
)

CHUNK_CHARS   = 1500   # 청크 최대 길이 (문자)
OVERLAP_CHARS = 30     # 청크 간 겹침 (경계 보정 + 중복 토큰 절감)
MAX_TOKENS    = 512    # SLM 출력 최대 토큰
TEMPERATURE   = 0.0    # 결정적 출력
CONFIDENCE_THRESHOLD = 0.5  # 이 값 미만 finding 무시


class ComputeMode(Enum):
    """런타임 컴퓨팅 환경."""
    APPLE_SILICON = "apple_silicon"  # Metal GPU — ~300~600 ms/req
    CUDA_GPU      = "cuda_gpu"       # NVIDIA CUDA — ~100~300 ms/req
    CPU_ONLY      = "cpu_only"       # CPU 전용    — ~3~10 s/req (경고)


def _detect_compute_mode() -> ComputeMode:
    """플랫폼을 자동 감지하여 ComputeMode 반환."""
    system = platform.system()
    machine = platform.machine()
    if system == "Darwin" and machine == "arm64":
        return ComputeMode.APPLE_SILICON
    if system == "Linux" and shutil.which("nvidia-smi") is not None:
        return ComputeMode.CUDA_GPU
    return ComputeMode.CPU_ONLY


def _gpu_layers_for(mode: ComputeMode) -> int:
    """ComputeMode에 맞는 n_gpu_layers 값 반환."""
    return -1 if mode != ComputeMode.CPU_ONLY else 0


_CPU_ONLY_WARNING_LINES = [
    "[SLM] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    "[SLM] ⚠  경고: GPU 없는 CPU 전용 환경에서 SLM 실행",
    "[SLM]    요청당 처리 시간이 3~10초 소요될 수 있습니다.",
    "[SLM]    권장: Apple Silicon Mac 또는 NVIDIA GPU 환경",
    "[SLM]    SLM 비활성화: 제어 파일에 \"slm_enabled\": false 설정",
    "[SLM] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
]


# GBNF grammar — JSON 배열만 출력하도록 강제
# grammar 파일로 분리하여 문자열 이스케이프 문제 회피
_GRAMMAR_LINES = [
    'root   ::= "[]" | "[" ws item (ws "," ws item)* ws "]"',
    'item   ::= "{" ws kv-rule "," ws kv-start "," ws kv-end "," ws kv-text "," ws kv-conf ws "}"',
    r'kv-rule  ::= "\"rule\""        ws ":" ws string',
    r'kv-start ::= "\"start\""       ws ":" ws number',
    r'kv-end   ::= "\"end\""         ws ":" ws number',
    r'kv-text  ::= "\"text\""        ws ":" ws string',
    r'kv-conf  ::= "\"confidence\""  ws ":" ws number',
    r'string ::= "\"" ([^"\\] | "\\" .)* "\""',
    'number ::= "-"? [0-9]+ ("." [0-9]+)?',
    r'ws     ::= [ \t\n]*',
]
_GRAMMAR = "\n".join(_GRAMMAR_LINES) + "\n"

_SYSTEM_PROMPT = """\
You are a PII detection assistant. Analyze the given text and find all \
personally identifiable information (PII) that was NOT already marked with <<<...>>>.

Detect these PII types if present:
- person_name: full name of a real individual
- address: physical address (street, city, country)
- organization: company or institution name combined with a person reference
- date_of_birth: birth date
- account_number: bank account or financial account numbers
- ip_address: IP addresses
- device_id: device serial numbers or MAC addresses
- medical_info: health or medical data
- biometric: biometric identifiers

Return JSON array of findings. Each item: {"rule": "<type>", "start": <int>, "end": <int>, "text": "<matched>", "confidence": <0.0-1.0>}
"start" and "end" are byte offsets in the input text.
If no PII found, return [].
Do NOT wrap in markdown. Return raw JSON only.\
"""


class SLMStage(Stage):
    """
    SLM 기반 PII 보완 탐지 스테이지.

    Parameters
    ----------
    model_path : GGUF 모델 파일 경로. None이면 DEFAULT_MODEL_PATH 사용.
    n_ctx      : 컨텍스트 길이 (토큰)
    n_threads    : CPU 스레드 수 (None이면 자동)
    n_gpu_layers : GPU 오프로드 레이어 수.
                   -1 = 전 레이어 GPU (Apple Silicon Metal / CUDA 권장),
                    0 = CPU 전용 (기본값, 명시적 설정 없을 시 플랫폼 자동 감지)
    verbose      : llama.cpp 내부 로그 출력 여부
    """

    _lock = threading.Lock()  # 모델은 싱글톤, 멀티스레드 직렬화

    # ── 추론 통계 (클래스 레벨, 싱글톤 공유) ─────────────────────────────────
    _infer_stats: dict = {
        "total_calls": 0,
        "chunk_count": 0,
        "total_findings": 0,
        "errors": 0,
        "elapsed_ms_sum": 0,
        "elapsed_ms_p95_buf": [],  # 최근 100개 보관 (p95 계산용)
        "backend": "uninitialized",
    }

    def __init__(
        self,
        model_path: str | None = None,
        adapter_model_path: str | None = None,
        n_ctx: int = 2048,
        n_threads: int | None = None,
        n_gpu_layers: int | None = None,
        verbose: bool = False,
        backend: str | None = None,
    ):
        self._model_path = model_path or DEFAULT_MODEL_PATH
        self._adapter_model_path = adapter_model_path or DEFAULT_ADAPTER_MODEL_PATH
        self._n_ctx = n_ctx
        self._n_threads = n_threads or max(1, (os.cpu_count() or 4) // 2)
        self._compute_mode = _detect_compute_mode()
        self._n_gpu_layers = n_gpu_layers if n_gpu_layers is not None else _gpu_layers_for(self._compute_mode)
        self._verbose = verbose
        self._backend_preference = (backend or os.getenv("DLP_SLM_BACKEND", "auto")).lower()
        self._api_url = os.getenv("DLP_SLM_API_URL", "http://localhost:8766").rstrip("/")
        self._active_backend = "uninitialized"
        self._llm: Any = None  # Llama 인스턴스 (지연 로드)
        self._load_error: str | None = None
        self._adapter: Any = None
        self._adapter_error: str | None = None
        self._adapter_stats_prev = {"chunks": 0, "infer_ms": 0.0, "errors": 0}

        # 컴퓨팅 환경 로그
        if self._backend_preference == "api":
            log.info("[SLM] API 모드 — 로컬 모델 미로드, URL: %s", self._api_url)
        elif self._compute_mode == ComputeMode.CPU_ONLY:
            for line in _CPU_ONLY_WARNING_LINES:
                log.warning(line)
        elif self._compute_mode == ComputeMode.APPLE_SILICON:
            log.info("[SLM] Apple Silicon 감지 → Metal GPU 전 레이어 오프로드")
        else:
            log.info("[SLM] NVIDIA GPU 감지 → CUDA 전 레이어 오프로드")

    @property
    def name(self) -> str:
        return "slm"

    def runtime_warning_lines(self) -> list[str]:
        if self._backend_preference == "api":
            return []  # API 모드: 로컬 CPU 경고 불필요
        if self._compute_mode == ComputeMode.CPU_ONLY:
            return list(_CPU_ONLY_WARNING_LINES)
        return []

    def _adapter_device(self) -> str:
        forced = os.getenv("DLP_SLM_DEVICE")
        if forced:
            return forced
        if self._compute_mode == ComputeMode.CUDA_GPU:
            return "cuda"
        if self._compute_mode == ComputeMode.APPLE_SILICON:
            return "mps"
        return "cpu"

    def _should_prefer_adapter(self) -> bool:
        if self._backend_preference == "gguf":
            return False
        if self._backend_preference == "adapter":
            return True
        return Path(self._adapter_model_path).exists() and self._compute_mode == ComputeMode.CUDA_GPU

    def _ensure_adapter_loaded(self) -> bool:
        if self._adapter is not None:
            return True
        if self._adapter_error:
            return False
        if not Path(self._adapter_model_path).exists():
            self._adapter_error = f"어댑터 모델 디렉터리 없음: {self._adapter_model_path}"
            return False
        try:
            from .slm_adapter import SLMAdapter

            device = self._adapter_device()
            log.info("[SLM] adapter 로딩 중: %s (%s)", self._adapter_model_path, device)
            self._adapter = SLMAdapter(self._adapter_model_path, device=device)
            self._active_backend = "adapter"
            SLMStage._infer_stats["backend"] = self._active_backend
            return True
        except Exception as exc:
            self._adapter_error = str(exc)
            log.warning("[SLM] adapter 로드 실패: %s", exc)
            return False

    def _should_use_api(self) -> bool:
        """API 백엔드 사용 여부 (제어 파일 > env var 순으로 읽음)."""
        return self._current_backend() == "api"

    def _current_backend(self) -> str:
        """현재 유효한 백엔드 값. 우선순위: env var(auto 제외) > 제어 파일 > 초기화 값."""
        env_val = os.getenv("DLP_SLM_BACKEND", "").lower()
        if env_val and env_val != "auto":
            return env_val
        try:
            data = json.loads(Path("/tmp/dlp-control.json").read_text(encoding="utf-8"))
            b = str(data.get("slm_backend", "")).lower()
            if b and b != "auto":
                return b
        except Exception:
            pass
        return self._backend_preference  # 초기화 시 저장된 값

    def _current_api_url(self) -> str:
        """현재 유효한 API URL. 우선순위: env var > 제어 파일 > 초기화 값."""
        env_val = os.getenv("DLP_SLM_API_URL", "")
        if env_val:
            return env_val.rstrip("/")
        try:
            data = json.loads(Path("/tmp/dlp-control.json").read_text(encoding="utf-8"))
            url = str(data.get("slm_api_url", "")).strip()
            if url:
                return url.rstrip("/")
        except Exception:
            pass
        return self._api_url  # 초기화 시 저장된 기본값

    def _ensure_api_ready(self) -> bool:
        """API 서버 연결 확인 (비차단, 실패해도 경고만 출력)."""
        import urllib.request
        import urllib.error
        url = self._current_api_url()
        try:
            with urllib.request.urlopen(
                f"{url}/health", timeout=2
            ) as resp:
                data = json.loads(resp.read().decode())
                return data.get("status") in ("ok", "loading")
        except Exception as exc:
            log.warning("[SLM] API 서버 연결 확인 실패: %s — %s", url, exc)
            return False

    def _scan_with_api(self, targets: list, prior_findings: list[Finding]) -> list[Finding]:
        """API 서버(/detect_batch)를 통한 일괄 PII 탐지."""
        import urllib.request
        import urllib.error

        api_url = self._current_api_url()
        texts = [getattr(t, "text", "") or "" for t in targets]
        prior_ranges_per_text = [
            [[s, e] for s, e in self._prior_ranges_for_target(t, prior_findings)]
            for t in targets
        ]

        payload_obj: dict[str, object] = {"texts": texts}
        # 일부 구버전 API 서버는 다중 텍스트 + prior_ranges_per_text 조합에서 500을 반환할 수 있음.
        # prior 정보가 실제로 있을 때만 필드를 포함한다.
        if any(prior_ranges_per_text):
            payload_obj["prior_ranges_per_text"] = prior_ranges_per_text

        t0 = time.monotonic()

        def _post_detect_batch(obj: dict[str, object]) -> dict:
            payload = json.dumps(obj).encode("utf-8")
            req = urllib.request.Request(
                f"{api_url}/detect_batch",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())

        try:
            result = _post_detect_batch(payload_obj)
        except Exception as exc:
            if "prior_ranges_per_text" not in payload_obj:
                log.warning("[SLM] API 호출 실패: %s — %s", api_url, exc)
                SLMStage._infer_stats["errors"] += 1
                return []
            # 호환성 fallback: prior_ranges_per_text 제외 후 1회 재시도
            log.warning(
                "[SLM] API 호출 실패(우선 요청): %s — %s; prior_ranges_per_text 제외 후 재시도",
                api_url,
                exc,
            )
            try:
                result = _post_detect_batch({"texts": texts})
            except Exception as retry_exc:
                log.warning("[SLM] API 호출 실패(재시도): %s — %s", api_url, retry_exc)
                SLMStage._infer_stats["errors"] += 1
                return []

        elapsed_ms = round((time.monotonic() - t0) * 1000)
        SLMStage._infer_stats["total_calls"] += 1
        SLMStage._infer_stats["elapsed_ms_sum"] += elapsed_ms
        buf = SLMStage._infer_stats["elapsed_ms_p95_buf"]
        buf.append(elapsed_ms)
        if len(buf) > 100:
            buf.pop(0)
        SLMStage._infer_stats["backend"] = "api"
        self._active_backend = "api"

        findings: list[Finding] = []
        for target, detections in zip(targets, result.get("results", [])):
            text = getattr(target, "text", "") or ""
            base_offset = int(getattr(target, "base_offset", 0))
            for item in detections:
                rule = str(item.get("rule", "slm_pii"))
                start = int(item.get("start", -1))
                end = int(item.get("end", -1))
                if not (0 <= start < end <= len(text)):
                    continue
                match_text = str(item.get("text", "")).strip() or text[start:end]
                confidence = float(item.get("confidence", 0.85))
                if confidence < CONFIDENCE_THRESHOLD:
                    continue
                ctx_before = text[max(0, start - 60): start]
                ctx_after = text[end: end + 60]
                findings.append(Finding(
                    stage="slm",
                    rule=rule,
                    severity=Severity.HIGH,
                    field_path=getattr(target, "field_path", ""),
                    role=getattr(target, "role", ""),
                    match_text=match_text,
                    match_start=base_offset + start,
                    match_end=base_offset + end,
                    context_before=ctx_before,
                    context_after=ctx_after,
                    confidence=confidence,
                    history=getattr(target, "history", False),
                    metadata={"slm_rule": rule, "slm_backend": "api"},
                ))

        SLMStage._infer_stats["total_findings"] += len(findings)
        return findings

    # ── 모델 로드 (최초 scan 호출 시 1회) ────────────────────────────────────

    def _ensure_loaded(self) -> bool:
        if self._backend_preference == "api":
            return True  # API 모드: 로컬 모델 로드 불필요
        if self._should_prefer_adapter() and self._ensure_adapter_loaded():
            return True
        if self._llm is not None:
            self._active_backend = "gguf"
            SLMStage._infer_stats["backend"] = self._active_backend
            return True
        if self._load_error:
            return False

        if not Path(self._model_path).exists():
            self._load_error = f"모델 파일 없음: {self._model_path}"
            log.error("[SLM] %s", self._load_error)
            return False

        try:
            from llama_cpp import Llama
            log.info("[SLM] 모델 로딩 중: %s", self._model_path)
            t0 = time.monotonic()
            self._llm = Llama(
                model_path=self._model_path,
                n_ctx=self._n_ctx,
                n_threads=self._n_threads,
                n_gpu_layers=self._n_gpu_layers,
                verbose=self._verbose,
            )
            elapsed = round((time.monotonic() - t0) * 1000)
            log.info("[SLM] 모델 로드 완료 (%dms, gpu_layers=%d)", elapsed, self._n_gpu_layers)
            self._active_backend = "gguf"
            SLMStage._infer_stats["backend"] = self._active_backend
            return True
        except Exception as e:
            self._load_error = str(e)
            log.error("[SLM] 모델 로드 실패: %s", e)
            return False

    def _prior_ranges_for_target(self, target, prior_findings: list[Finding]) -> list[tuple[int, int]]:
        base_offset = int(getattr(target, "base_offset", 0))
        window_end = base_offset + len(getattr(target, "text", "") or "")
        ranges: list[tuple[int, int]] = []
        for finding in prior_findings:
            if finding.field_path != getattr(target, "field_path", ""):
                continue
            start = max(base_offset, finding.match_start)
            end = min(window_end, finding.match_end)
            if end > start:
                ranges.append((start - base_offset, end - base_offset))
        return ranges

    def _scan_with_adapter(self, targets: list, prior_findings: list[Finding]) -> list[Finding]:
        texts = [getattr(target, "text", "") for target in targets]
        prior_ranges_per_text = [
            self._prior_ranges_for_target(target, prior_findings)
            for target in targets
        ]
        results_per_target = self._adapter.detect_combined(texts, prior_ranges_per_text)
        adapter_stats = self._adapter.get_stats()
        chunk_delta = int(adapter_stats.get("chunks", 0)) - int(self._adapter_stats_prev.get("chunks", 0))
        infer_ms_delta = float(adapter_stats.get("infer_ms", 0.0)) - float(self._adapter_stats_prev.get("infer_ms", 0.0))
        errors_delta = int(adapter_stats.get("errors", 0)) - int(self._adapter_stats_prev.get("errors", 0))
        self._adapter_stats_prev = {
            "chunks": int(adapter_stats.get("chunks", 0)),
            "infer_ms": float(adapter_stats.get("infer_ms", 0.0)),
            "errors": int(adapter_stats.get("errors", 0)),
        }
        SLMStage._infer_stats["total_calls"] += max(0, chunk_delta)
        SLMStage._infer_stats["chunk_count"] += max(0, chunk_delta)
        SLMStage._infer_stats["elapsed_ms_sum"] += max(0.0, infer_ms_delta)
        SLMStage._infer_stats["errors"] += max(0, errors_delta)

        findings: list[Finding] = []
        for target, detections in zip(targets, results_per_target):
            text = getattr(target, "text", "") or ""
            base_offset = int(getattr(target, "base_offset", 0))
            for item in detections:
                rule = str(item.get("rule", "slm_pii"))
                start = int(item.get("start", -1))
                end = int(item.get("end", -1))
                if not (0 <= start < end <= len(text)):
                    continue
                match_text = str(item.get("text", "")).strip() or text[start:end]
                confidence = float(item.get("confidence", 0.85))
                ctx_before = text[max(0, start - 60) : start]
                ctx_after = text[end : end + 60]
                findings.append(Finding(
                    stage="slm",
                    rule=rule,
                    severity=Severity.HIGH,
                    field_path=getattr(target, "field_path", ""),
                    role=getattr(target, "role", ""),
                    match_text=match_text,
                    match_start=base_offset + start,
                    match_end=base_offset + end,
                    context_before=ctx_before,
                    context_after=ctx_after,
                    confidence=confidence,
                    history=getattr(target, "history", False),
                    metadata={"slm_rule": rule, "slm_backend": "adapter"},
                ))
        SLMStage._infer_stats["total_findings"] += len(findings)
        return findings

    # ── Stage 인터페이스 ──────────────────────────────────────────────────────

    def scan(self, targets: list, prior_findings: list[Finding]) -> list[Finding]:
        """
        모든 타깃의 순수 텍스트를 하나로 합친 뒤 SLM에 한 번만 전달.
        JSON 구조 없이 추출된 문자열만 보내므로 SLM이 더 정확히 분석.

        타깃별 구분자로 오프셋을 추적해 findings를 올바른 target에 매핑.
        """
        with self._lock:
            if self._should_use_api():
                return self._scan_with_api(targets, prior_findings)

            if not self._ensure_loaded():
                return []

            if self._adapter is not None:
                return self._scan_with_adapter(targets, prior_findings)

            # 텍스트가 있는 타깃만 선별, 각 시작 오프셋 기록
            SEP = "\n\n"
            segments: list[tuple[Any, int, int]] = []  # (target, start, end)
            parts: list[str] = []
            pos = 0
            for target in targets:
                text: str = getattr(target, "text", "") or ""
                if not text.strip():
                    continue
                start = pos
                end   = pos + len(text)
                segments.append((target, start, end))
                parts.append(text)
                pos = end + len(SEP)

            if not segments:
                return []

            combined = SEP.join(parts)

            # Regex findings → 전체 combined 기준 절대 범위로 변환
            prior_ranges: list[tuple[int, int]] = []
            for target, seg_start, _ in segments:
                for start, end in self._prior_ranges_for_target(target, prior_findings):
                    prior_ranges.append((seg_start + start, seg_start + end))

            # SLM 추론 (청크 분할 포함)
            raw_findings = self._scan_text(combined, prior_ranges)

            # combined 기준 finding → 해당 target 매핑
            results: list[Finding] = []
            for rf in raw_findings:
                target, role, field_path = None, "", ""
                for t, seg_start, seg_end in segments:
                    if seg_start <= rf.match_start < seg_end:
                        target     = t
                        role       = getattr(t, "role", "")
                        field_path = getattr(t, "field_path", "")
                        base_offset = int(getattr(t, "base_offset", 0))
                        # 오프셋을 타깃 내부 로컬 좌표로 변환
                        local_start = rf.match_start - seg_start + base_offset
                        local_end   = rf.match_end   - seg_start + base_offset
                        break
                else:
                    # 어느 세그먼트에도 속하지 않으면 첫 번째 타깃
                    if segments:
                        target     = segments[0][0]
                        role       = getattr(target, "role", "")
                        field_path = getattr(target, "field_path", "")
                        base_offset = int(getattr(target, "base_offset", 0))
                        local_start = rf.match_start + base_offset
                        local_end   = rf.match_end + base_offset

                results.append(Finding(
                    stage="slm",
                    rule=rf.rule,
                    severity=rf.severity,
                    field_path=field_path,
                    role=role,
                    match_text=rf.match_text,
                    match_start=local_start,
                    match_end=local_end,
                    context_before=rf.context_before,
                    context_after=rf.context_after,
                    confidence=rf.confidence,
                    history=getattr(target, "history", False),
                    metadata=rf.metadata,
                ))

            SLMStage._infer_stats["total_findings"] += len(results)
            return results

    @classmethod
    def get_stats(cls) -> dict:
        """추론 통계 반환 (TUI/모니터링용)."""
        s = cls._infer_stats
        total = s["total_calls"]
        avg_ms = round(s["elapsed_ms_sum"] / total) if total else 0
        buf = sorted(s["elapsed_ms_p95_buf"])
        p95_ms = buf[int(len(buf) * 0.95)] if buf else 0
        return {
            "total_calls": total,
            "chunk_count": s["chunk_count"],
            "total_findings": s["total_findings"],
            "errors": s["errors"],
            "avg_ms": avg_ms,
            "p95_ms": p95_ms,
            "backend": s["backend"],
        }

    def _scan_text(
        self,
        text: str,
        prior_ranges: list[tuple[int, int]],
    ) -> list[Finding]:
        """텍스트를 청크로 분할해 SLM 추론, Finding 목록 반환 (combined 기준 오프셋)."""
        findings: list[Finding] = []
        chunks = _split_chunks(text, CHUNK_CHARS, OVERLAP_CHARS)
        SLMStage._infer_stats["chunk_count"] += len(chunks)

        for chunk_text, chunk_offset in chunks:
            raw = self._infer(chunk_text)
            if raw is None:
                continue

            try:
                items = json.loads(raw)
                if not isinstance(items, list):
                    continue
            except json.JSONDecodeError:
                log.debug("[SLM] JSON 파싱 실패: %r", raw[:200])
                continue

            for item in items:
                try:
                    f = self._item_to_finding(item, chunk_text, chunk_offset, prior_ranges)
                    if f:
                        findings.append(f)
                except Exception as e:
                    log.debug("[SLM] finding 변환 오류: %s — %r", e, item)

        return findings

    def _infer(self, text: str) -> str | None:
        """SLM 추론 실행, 응답 문자열 반환."""
        try:
            from llama_cpp import LlamaGrammar
            grammar = LlamaGrammar.from_string(_GRAMMAR)

            t0 = time.monotonic()
            response = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": text},
                ],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                grammar=grammar,
            )
            elapsed_ms = round((time.monotonic() - t0) * 1000)
            SLMStage._infer_stats["total_calls"] += 1
            SLMStage._infer_stats["elapsed_ms_sum"] += elapsed_ms
            buf = SLMStage._infer_stats["elapsed_ms_p95_buf"]
            buf.append(elapsed_ms)
            if len(buf) > 100:
                buf.pop(0)
            return response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            log.warning("[SLM] 추론 오류: %s", e)
            SLMStage._infer_stats["errors"] += 1
            return None

    def _item_to_finding(
        self,
        item: dict,
        chunk_text: str,
        chunk_offset: int,
        prior_ranges: list[tuple[int, int]],
    ) -> Finding | None:
        """SLM JSON 항목 → Finding 객체 변환 (field_path/role은 scan()에서 덮어씀)."""
        rule       = str(item.get("rule", "slm_pii"))
        start      = int(item.get("start", -1))
        end        = int(item.get("end", -1))
        match_text = str(item.get("text", "")).strip()
        confidence = float(item.get("confidence", 0.0))

        if not match_text:
            return None
        if confidence < CONFIDENCE_THRESHOLD:
            return None

        # offset 검증/보정: SLM offset이 정확하면 사용, 아니면 문자열 직접 탐색
        if 0 <= start < end <= len(chunk_text) and chunk_text[start:end] == match_text:
            abs_start = chunk_offset + start
            abs_end   = chunk_offset + end
        else:
            idx = chunk_text.find(match_text)
            if idx == -1:
                return None
            abs_start = chunk_offset + idx
            abs_end   = abs_start + len(match_text)

        # Regex findings와 중복 제거 (combined 기준, 50% 이상 겹침 시 건너뜀)
        span = abs_end - abs_start
        for ps, pe in prior_ranges:
            overlap = max(0, min(abs_end, pe) - max(abs_start, ps))
            if span > 0 and overlap / span >= 0.5:
                return None

        local = abs_start - chunk_offset
        ctx_before = chunk_text[max(0, local - 60) : local]
        ctx_after  = chunk_text[local + len(match_text) : local + len(match_text) + 60]

        # field_path/role은 scan()에서 세그먼트 매핑 후 교체
        return Finding(
            stage="slm",
            rule=rule,
            severity=Severity.HIGH,
            field_path="",
            role="",
            match_text=match_text,
            match_start=abs_start,
            match_end=abs_end,
            context_before=ctx_before,
            context_after=ctx_after,
            confidence=confidence,
            metadata={"slm_rule": rule},
        )


# ── 유틸 ─────────────────────────────────────────────────────────────────────

def _split_chunks(
    text: str,
    chunk_size: int,
    overlap: int,
) -> list[tuple[str, int]]:
    """
    텍스트를 chunk_size 문자 단위로 분할.
    Returns list of (chunk_text, start_offset).
    """
    if len(text) <= chunk_size:
        return [(text, 0)]

    chunks: list[tuple[str, int]] = []
    step = chunk_size - overlap
    pos = 0
    while pos < len(text):
        end = min(pos + chunk_size, len(text))
        chunks.append((text[pos:end], pos))
        if end == len(text):
            break
        pos += step
    return chunks
