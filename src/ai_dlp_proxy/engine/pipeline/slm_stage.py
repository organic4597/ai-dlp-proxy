"""
SLM Stage — llama-cpp-python 기반 소형 언어 모델 PII 보완 탐지.

Regex Stage가 놓친 문맥 의존적 PII(예: 이름+소속 조합, 자유형식 주소 등)를
SLM(Qwen2.5-1.5B-Instruct)으로 검증·보완합니다.

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
import threading
import time
from pathlib import Path
from typing import Any

from .base import Finding, Severity, Stage

log = logging.getLogger(__name__)

# ── 상수 ─────────────────────────────────────────────────────────────────────

DEFAULT_MODEL_PATH = str(
    Path(__file__).parents[4] / "models" / "qwen2.5-1.5b-instruct-q4_k_m.gguf"
)

CHUNK_CHARS   = 1500   # 청크 최대 길이 (문자)
OVERLAP_CHARS = 100    # 청크 간 겹침 (offset 보정용)
MAX_TOKENS    = 512    # SLM 출력 최대 토큰
TEMPERATURE   = 0.0    # 결정적 출력
CONFIDENCE_THRESHOLD = 0.5  # 이 값 미만 finding 무시

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
    n_threads  : CPU 스레드 수 (None이면 자동)
    verbose    : llama.cpp 내부 로그 출력 여부
    """

    _lock = threading.Lock()  # 모델은 싱글톤, 멀티스레드 직렬화

    def __init__(
        self,
        model_path: str | None = None,
        n_ctx: int = 2048,
        n_threads: int | None = None,
        verbose: bool = False,
    ):
        self._model_path = model_path or DEFAULT_MODEL_PATH
        self._n_ctx = n_ctx
        self._n_threads = n_threads or max(1, (os.cpu_count() or 4) // 2)
        self._verbose = verbose
        self._llm: Any = None  # Llama 인스턴스 (지연 로드)
        self._load_error: str | None = None

    @property
    def name(self) -> str:
        return "slm"

    # ── 모델 로드 (최초 scan 호출 시 1회) ────────────────────────────────────

    def _ensure_loaded(self) -> bool:
        if self._llm is not None:
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
                verbose=self._verbose,
            )
            elapsed = round((time.monotonic() - t0) * 1000)
            log.info("[SLM] 모델 로드 완료 (%dms)", elapsed)
            return True
        except Exception as e:
            self._load_error = str(e)
            log.error("[SLM] 모델 로드 실패: %s", e)
            return False

    # ── Stage 인터페이스 ──────────────────────────────────────────────────────

    def scan(self, targets: list, prior_findings: list[Finding]) -> list[Finding]:
        """
        모든 타깃의 순수 텍스트를 하나로 합친 뒤 SLM에 한 번만 전달.
        JSON 구조 없이 추출된 문자열만 보내므로 SLM이 더 정확히 분석.

        타깃별 구분자로 오프셋을 추적해 findings를 올바른 target에 매핑.
        """
        with self._lock:
            if not self._ensure_loaded():
                return []

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
                fp = getattr(target, "field_path", "")
                for f in prior_findings:
                    if f.field_path == fp:
                        prior_ranges.append((seg_start + f.match_start, seg_start + f.match_end))

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
                        # 오프셋을 타깃 내부 로컬 좌표로 변환
                        local_start = rf.match_start - seg_start
                        local_end   = rf.match_end   - seg_start
                        break
                else:
                    # 어느 세그먼트에도 속하지 않으면 첫 번째 타깃
                    if segments:
                        target     = segments[0][0]
                        role       = getattr(target, "role", "")
                        field_path = getattr(target, "field_path", "")
                        local_start = rf.match_start
                        local_end   = rf.match_end

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
                    metadata=rf.metadata,
                ))

            return results

    # ── 내부 메서드 ───────────────────────────────────────────────────────────

    def _scan_text(
        self,
        text: str,
        prior_ranges: list[tuple[int, int]],
    ) -> list[Finding]:
        """텍스트를 청크로 분할해 SLM 추론, Finding 목록 반환 (combined 기준 오프셋)."""
        findings: list[Finding] = []
        chunks = _split_chunks(text, CHUNK_CHARS, OVERLAP_CHARS)

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

            response = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": text},
                ],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                grammar=grammar,
            )
            return response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            log.warning("[SLM] 추론 오류: %s", e)
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
