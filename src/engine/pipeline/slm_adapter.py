"""Qwen3.5 기반 SLM 어댑터.

무거운 의존성(torch / transformers)은 실제 모델 로드 시점에만 import하여,
런타임 fallback 및 테스트에서 모듈 import 자체가 실패하지 않도록 한다.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SYSTEM_PROMPT = (
    "당신은 개인정보(PII) 탐지 전문 AI입니다. "
    "주어진 텍스트에서 개인정보를 찾아 JSON 배열로만 반환하세요. "
    '출력 형식: [["rule_id", "탐지된값"], ...] — 규칙ID와 실제 탐지된 텍스트만 포함합니다. '
    "<<<...>>> 로 이미 마스킹된 항목은 무시합니다. "
    "테스트/예시 데이터, 공개 정보, 가상 인물은 PII로 분류하지 않습니다. "
    "마크다운 없이 순수 JSON만 출력합니다. PII가 없으면 [] 를 반환합니다."
)
USER_PREFIX = "다음 텍스트에서 개인정보를 탐지하세요:\n\n"

CHUNK_CHARS = 2400
OVERLAP_CHARS = 400  # 200 → 400: 청크 경계 근처 person_name/address FN 회수 (blog v5 분석)
MAX_NEW_TOKENS = 384
DEFAULT_CONF = 0.85

RULE_NORMALIZE: dict[str, str] = {
    "api_key": "api_key_assignment",
    "private_key": "pem_private_key",
    "card_number": "credit_card",
    "amex": "credit_card",
    "aws_key": "aws_access_key",
    "access_key": "aws_access_key",
}

_MASK_TOKEN_RE = re.compile(r"^<<<.+?>>>$")


@dataclass
class Detection:
    rule: str
    start: int
    end: int
    text: str
    confidence: float

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "confidence": self.confidence,
        }


def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = OVERLAP_CHARS) -> list[tuple[int, str]]:
    if len(text) <= size:
        return [(0, text)]
    if overlap >= size:
        raise ValueError("overlap must be smaller than size")
    chunks: list[tuple[int, str]] = []
    step = size - overlap
    pos = 0
    while pos < len(text):
        end = min(pos + size, len(text))
        chunks.append((pos, text[pos:end]))
        if end >= len(text):
            break
        pos += step
    return chunks


def parse_model_output(raw: str) -> list[tuple[str, str]]:
    if not raw:
        return []
    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        arr = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return []
    if not isinstance(arr, list):
        return []

    pairs: list[tuple[str, str]] = []
    for item in arr:
        if not isinstance(item, list) or len(item) != 2:
            continue
        rule, value = item
        if not isinstance(rule, str) or not isinstance(value, str):
            continue
        rule = RULE_NORMALIZE.get(rule.strip(), rule.strip())
        value = value.strip()
        if not rule or not value:
            continue
        if _MASK_TOKEN_RE.match(value):
            continue
        pairs.append((rule, value))
    return pairs


def find_all_spans(text: str, value: str) -> list[tuple[int, int]]:
    if not value:
        return []
    spans: list[tuple[int, int]] = []
    pos = 0
    while True:
        idx = text.find(value, pos)
        if idx < 0:
            break
        spans.append((idx, idx + len(value)))
        pos = idx + 1
    return spans


def recover_spans(
    pairs: list[tuple[str, str]],
    chunk: str,
    chunk_offset: int,
    full_text: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for rule, value in pairs:
        spans = find_all_spans(chunk, value)
        if spans:
            for start, end in spans:
                detections.append(Detection(rule, chunk_offset + start, chunk_offset + end, value, DEFAULT_CONF))
            continue

        for start, end in find_all_spans(full_text, value):
            detections.append(Detection(rule, start, end, value, round(DEFAULT_CONF * 0.9, 4)))
    return detections


# ── 후처리: span 경계 정규화 + 더미/예시 화이트리스트 ─────────────────────────

_RRN_PREFIX_RE = re.compile(
    r"^(RRN|주민번호|주민등록번호|resident\s*(?:registration\s*)?(?:number)?)\s*[:：\s]\s*",
    re.IGNORECASE,
)
_DUMMY_RRN_RE = re.compile(r"^0{6}[-\s]?0{7}$")

_DUMMY_WHITELIST: frozenset[str] = frozenset({
    # 이메일 예시 도메인
    "user@example.com", "test@example.com", "admin@example.com",
    "foo@example.com", "bar@example.com", "no-reply@example.com",
    "user@test.com", "admin@test.com",
    # 개인정보 없는 로컬 IP
    "127.0.0.1", "0.0.0.0", "localhost",
    # 명백한 더미/fake 키
    "sk-test-fake-key", "dummy_api_key", "your-api-key-here",
    "AKIAIOSFODNN7EXAMPLE",  # AWS 문서 예시
})

_DUMMY_PATTERN = re.compile(
    r"(?i)^(dummy|fake|test|example|placeholder|your[-_]?\w*[-_]?here"
    r"|sample|mock|demo|xxx+)$"
)

_PRIVATE_IP_RE = re.compile(
    r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|::1|fc[0-9a-f]{2}:.+)$"
)

# URL-encoded '@' → 디코드 후 span 재계산
_URL_ENC_AT = re.compile(r"%40", re.IGNORECASE)


def _trim_rrn_prefix(d: Detection, full_text: str) -> Detection:
    """kr_rrn span 앞에 'RRN:', '주민번호:' 등 접두가 붙어있으면 잘라낸다."""
    m = _RRN_PREFIX_RE.match(d.text)
    if m:
        trim = len(m.group(0))
        return Detection(d.rule, d.start + trim, d.end, d.text[trim:], d.confidence)
    return d


def _fix_email_url_encoding(d: Detection, full_text: str) -> Detection:
    """email span 안에 '%40' 이 있으면 '@' 로 교체하고 올바른 텍스트로 반환.

    span 위치는 full_text 기준이므로, 디코딩된 값이 실제로 full_text 안에
    있으면 그 위치를 재조회한다. 없으면 원본 Detection을 그대로 반환.
    """
    if "%40" not in d.text:
        return d
    decoded = _URL_ENC_AT.sub("@", d.text)
    # 디코딩 결과가 full_text 에 있으면 해당 위치로 교체
    idx = full_text.find(decoded)
    if idx >= 0:
        return Detection(d.rule, idx, idx + len(decoded), decoded, d.confidence)
    return d


def postprocess_detections(detections: list[Detection], full_text: str) -> list[Detection]:
    """모델 출력 Detection 에 대해 span 정규화 + 더미/예시 필터를 적용한다.

    적용 순서:
    1. rule별 span 트림 (kr_rrn prefix, email url-encoding)
    2. 텍스트가 비거나 너무 짧으면 제거
    3. 더미/예시/화이트리스트 값 제거
    4. ip_address 규칙에서 사설 IP 제거
    """
    result: list[Detection] = []
    for d in detections:
        # 1. rule별 정규화
        if d.rule == "kr_rrn":
            d = _trim_rrn_prefix(d, full_text)
            if _DUMMY_RRN_RE.match(d.text):
                continue
        elif d.rule == "email":
            d = _fix_email_url_encoding(d, full_text)

        # 2. span 유효성
        if not d.text or len(d.text) < 2:
            continue

        # 3. 더미/예시 화이트리스트
        if d.text in _DUMMY_WHITELIST:
            continue
        if _DUMMY_PATTERN.match(d.text):
            continue

        # 4. ip_address — 사설 IP는 외부 유출 위험 낮음
        if d.rule == "ip_address" and _PRIVATE_IP_RE.match(d.text):
            continue

        result.append(d)
    return result


def dedupe(detections: list[Detection]) -> list[Detection]:
    best: dict[tuple[str, int, int], Detection] = {}
    for detection in detections:
        key = (detection.rule, detection.start, detection.end)
        prev = best.get(key)
        if prev is None or detection.confidence > prev.confidence:
            best[key] = detection
    return sorted(best.values(), key=lambda item: (item.start, item.end, item.rule))


def filter_by_prior(
    detections: list[Detection],
    prior_ranges: list[tuple[int, int]],
    ratio: float = 0.5,
) -> list[Detection]:
    if not prior_ranges:
        return detections
    kept: list[Detection] = []
    for detection in detections:
        span = detection.end - detection.start
        if span <= 0:
            continue
        skip = False
        for prior_start, prior_end in prior_ranges:
            overlap = max(0, min(detection.end, prior_end) - max(detection.start, prior_start))
            if overlap / span >= ratio:
                skip = True
                break
        if not skip:
            kept.append(detection)
    return kept


class SLMRunner:
    def __init__(self, model_path: str, device: str = "cuda", dtype: str = "fp16"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        kwargs: dict[str, Any] = {
            "trust_remote_code": True,
            "attn_implementation": "sdpa",
        }
        if dtype == "int4":
            from transformers import BitsAndBytesConfig

            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )
            kwargs["device_map"] = "auto" if device != "cpu" else {"": "cpu"}
        else:
            torch_dtype = torch.bfloat16 if dtype == "bf16" else torch.float16
            kwargs["torch_dtype"] = torch_dtype
            kwargs["device_map"] = {"": device} if device != "cpu" else "cpu"

        self.model = AutoModelForCausalLM.from_pretrained(model_path, **kwargs)
        self.model.eval()

    def infer(self, chunk: str) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PREFIX + chunk},
        ]
        try:
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        with self._torch.inference_mode():
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            output = self.model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,
                temperature=1.0,
                top_p=1.0,
                pad_token_id=self.tokenizer.pad_token_id,
            )
        generated = output[0][inputs["input_ids"].shape[1] :]
        return self.tokenizer.decode(generated, skip_special_tokens=True).strip()


class SLMAdapter:
    SEP = "\n\n"

    def __init__(self, model_path: str | Path, device: str = "cuda", dtype: str = "fp16"):
        self.model_path = str(model_path)
        self.runner = SLMRunner(self.model_path, device=device, dtype=dtype)
        self.stats = {"calls": 0, "chunks": 0, "infer_ms": 0.0, "errors": 0}

    def detect(self, text: str, prior_ranges: list[tuple[int, int]] | None = None) -> list[dict]:
        if not text or not text.strip():
            return []
        self.stats["calls"] += 1
        detections: list[Detection] = []
        for offset, chunk in chunk_text(text):
            self.stats["chunks"] += 1
            t0 = time.monotonic()
            try:
                raw = self.runner.infer(chunk)
            except Exception:
                self.stats["errors"] += 1
                continue
            finally:
                self.stats["infer_ms"] += (time.monotonic() - t0) * 1000
            pairs = parse_model_output(raw)
            detections.extend(recover_spans(pairs, chunk, offset, text))

        deduped = dedupe(postprocess_detections(detections, text))
        if prior_ranges:
            deduped = filter_by_prior(deduped, prior_ranges)
        return [detection.to_dict() for detection in deduped]

    def detect_combined(
        self,
        texts: list[str],
        prior_ranges_per_text: list[list[tuple[int, int]]] | None = None,
    ) -> list[list[dict]]:
        segments: list[tuple[int, int, int]] = []
        parts: list[str] = []
        pos = 0
        for idx, text in enumerate(texts):
            if not text or not text.strip():
                continue
            segments.append((idx, pos, pos + len(text)))
            parts.append(text)
            pos += len(text) + len(self.SEP)

        results: list[list[dict]] = [[] for _ in texts]
        if not segments:
            return results

        combined = self.SEP.join(parts)
        combined_priors: list[tuple[int, int]] = []
        if prior_ranges_per_text:
            for original_idx, seg_start, _ in segments:
                if original_idx >= len(prior_ranges_per_text):
                    continue
                for start, end in prior_ranges_per_text[original_idx]:
                    combined_priors.append((seg_start + start, seg_start + end))

        combined_findings = self.detect(combined, prior_ranges=combined_priors)
        for finding in combined_findings:
            for original_idx, seg_start, seg_end in segments:
                if seg_start <= finding["start"] < seg_end:
                    local = dict(finding)
                    local["start"] = finding["start"] - seg_start
                    local["end"] = finding["end"] - seg_start
                    results[original_idx].append(local)
                    break
        return results

    def get_stats(self) -> dict:
        stats = dict(self.stats)
        stats["avg_infer_ms"] = stats["infer_ms"] / stats["chunks"] if stats["chunks"] else 0.0
        return stats