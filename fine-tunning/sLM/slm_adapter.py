#!/usr/bin/env python3
"""
DLP SLM 추론 어댑터 (Qwen3.5-4B 파인튜닝 모델 → DLP 파이프라인)
================================================================

원격 파이프라인(`/home1/ai-dlp-proxy/src/engine/pipeline/slm_stage.py`)을
교체하기 위한 어댑터. 핵심 책임:

  1. 입력 텍스트를 chunk 단위로 분할 (overlap 포함)
  2. 각 chunk에 대해 Qwen3.5-4B 추론 → `[[rule_id, value], ...]` JSON
  3. value를 원본 텍스트에서 찾아 (start, end) span 역산
  4. chunk overlap 영역의 중복 제거 + NMS
  5. 최종 출력: `[{rule, start, end, text, confidence}, ...]`
     (기존 slm_stage.py 인터페이스와 호환)

I/O 명세
─────────
  입력:
    text: str                    # Regex/Asset이 이미 마스킹한 텍스트
    role: str = "user"           # 메시지 role (필요 시 prompt에 활용)

  출력:
    list[dict]:
      {
        "rule":       str,       # 학습 라벨 (email, phone_kr, ...)
        "start":      int,       # 원본 text 내 시작 오프셋
        "end":        int,       # 원본 text 내 끝 오프셋
        "text":       str,       # 원본에서 잘라낸 매칭 문자열
        "confidence": float,     # 0.0 ~ 1.0 (기본 0.85, logprobs 사용 시 보정)
      }

  마스킹 처리:
    - <<<rule_id>>> 형태의 마스킹 토큰은 system prompt에서 무시 지시
    - 모델이 마스킹 토큰을 실수로 반환해도 span 역산 단계에서 자동 제외
      (검증: value 길이 >= 1, value가 <<<...>>> 패턴이 아님)

벤치마크 가정
─────────────
  - max_seq_train = 4096 토큰 (≈ 한국어 ~2,500자, 영문 코드 ~3,500자)
  - 안전 마진 두고 CHUNK_CHARS = 2400 (한국어 기준 ~1,500 토큰)
  - OVERLAP_CHARS = 200 (chunk 경계의 PII 잘림 방지)
  - 보통 user 입력은 단일 chunk (학습 데이터 99%ile = 299 토큰)
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Iterable

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


# ── 설정 ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "당신은 개인정보(PII) 탐지 전문 AI입니다. "
    "주어진 텍스트에서 개인정보를 찾아 JSON 배열로만 반환하세요. "
    '출력 형식: [["rule_id", "탐지된값"], ...] — 규칙ID와 실제 탐지된 텍스트만 포함합니다. '
    "<<<...>>> 로 이미 마스킹된 항목은 무시합니다. "
    "테스트/예시 데이터, 공개 정보, 가상 인물은 PII로 분류하지 않습니다. "
    "마크다운 없이 순수 JSON만 출력합니다. PII가 없으면 [] 를 반환합니다."
)

USER_PREFIX = "다음 텍스트에서 개인정보를 탐지하세요:\n\n"

CHUNK_CHARS    = 2400
OVERLAP_CHARS  = 200
MAX_NEW_TOKENS = 384
DEFAULT_CONF   = 0.85

# 마스킹 토큰 패턴 — 모델이 실수로 반환하면 제외
_MASK_TOKEN_RE = re.compile(r"^<<<.+?>>>$")

# 학습 라벨 → 원격 regex_stage 라벨 정규화
# 학습 데이터: api_key / private_key
# 원격 regex:  api_key_assignment / pem_private_key
# 라벨 일치는 prior_findings dedup 정확도에는 영향 없으나(위치 50% 기준)
# control.py severity_map 매칭에는 필수
RULE_NORMALIZE: dict[str, str] = {
    "api_key":     "api_key_assignment",
    "private_key": "pem_private_key",
}

# Regex stage가 이미 처리하는 rule들 — SLM이 이걸 다시 잡으면 prior_findings로 막히지만
# 추론 비용/false positive를 줄이려면 system prompt에서 SLM 보강 영역만 강조하는 것도 가능.
# 현재는 학습 모델이 이미 "regex 처리 rule도 학습"했으므로 차단하지 않음 (recall 우위).


# ── 자료구조 ─────────────────────────────────────────────────────────────────

@dataclass
class Detection:
    rule:       str
    start:      int
    end:        int
    text:       str
    confidence: float

    def to_dict(self) -> dict:
        return {
            "rule":       self.rule,
            "start":      self.start,
            "end":        self.end,
            "text":       self.text,
            "confidence": self.confidence,
        }


# ── 1. Chunking ──────────────────────────────────────────────────────────────

def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = OVERLAP_CHARS) -> list[tuple[int, str]]:
    """텍스트를 overlap이 있는 chunk로 분할.
    Returns: [(chunk_start_offset, chunk_text), ...]
    """
    if len(text) <= size:
        return [(0, text)]
    chunks: list[tuple[int, str]] = []
    step = size - overlap
    if step <= 0:
        raise ValueError("overlap must be < size")
    pos = 0
    while pos < len(text):
        end = min(pos + size, len(text))
        chunks.append((pos, text[pos:end]))
        if end >= len(text):
            break
        pos += step
    return chunks


# ── 2. 모델 추론 ─────────────────────────────────────────────────────────────

class SLMRunner:
    """Qwen3.5-4B 파인튜닝 모델 추론 래퍼."""

    def __init__(self, model_path: str, device: str = "cuda", dtype=torch.bfloat16):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            dtype=dtype,
            device_map={"": device} if device != "cpu" else "cpu",
            trust_remote_code=True,
            attn_implementation="sdpa",
        )
        self.model.eval()
        self.device = device

    @torch.inference_mode()
    def infer(self, chunk: str) -> str:
        """chunk → raw model output (JSON 문자열 기대)."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": USER_PREFIX + chunk},
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
                messages, tokenize=False, add_generation_prompt=True,
            )
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        out = self.model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=1.0,
            top_p=1.0,
            pad_token_id=self.tokenizer.pad_token_id,
        )
        gen = out[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(gen, skip_special_tokens=True).strip()


# ── 3. JSON 파싱 (robust) ────────────────────────────────────────────────────

def parse_model_output(raw: str) -> list[tuple[str, str]]:
    """모델 출력에서 [[rule, value], ...] 추출.
    형식 어긋난 항목은 조용히 스킵한다.
    """
    if not raw:
        return []
    # JSON 배열 부분만 추출 (모델이 앞뒤로 텍스트 붙이는 경우 대응)
    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    snippet = raw[start:end + 1]
    try:
        arr = json.loads(snippet)
    except json.JSONDecodeError:
        return []
    pairs: list[tuple[str, str]] = []
    if not isinstance(arr, list):
        return []
    for item in arr:
        if not isinstance(item, list) or len(item) != 2:
            continue
        rule, value = item
        if not isinstance(rule, str) or not isinstance(value, str):
            continue
        rule = rule.strip()
        value = value.strip()
        if not rule or not value:
            continue
        if _MASK_TOKEN_RE.match(value):
            continue
        # 라벨 정규화 (학습 라벨 → 원격 regex 표준 라벨)
        rule = RULE_NORMALIZE.get(rule, rule)
        pairs.append((rule, value))
    return pairs


# ── 4. Span 역산 ─────────────────────────────────────────────────────────────

def find_all_spans(text: str, value: str) -> list[tuple[int, int]]:
    """text 내 value의 모든 occurrence span 반환."""
    spans: list[tuple[int, int]] = []
    if not value:
        return spans
    pos = 0
    while True:
        idx = text.find(value, pos)
        if idx < 0:
            break
        spans.append((idx, idx + len(value)))
        pos = idx + 1   # overlap도 잡기 위해 +1
    return spans


def recover_spans(
    pairs: list[tuple[str, str]],
    chunk: str,
    chunk_offset: int,
    full_text: str,
) -> list[Detection]:
    """모델이 반환한 (rule, value) 쌍을 chunk 내에서 검색하여 spans 생성.
    - chunk 내 발견되면 chunk_offset 적용해 full_text 좌표로 변환
    - chunk에서 못 찾으면 full_text 전체에서 fallback 검색
      (모델이 chunk 경계를 무시하고 답한 경우 대응)
    """
    detections: list[Detection] = []
    for rule, value in pairs:
        spans = find_all_spans(chunk, value)
        if spans:
            for s, e in spans:
                detections.append(Detection(
                    rule=rule,
                    start=chunk_offset + s,
                    end=chunk_offset + e,
                    text=value,
                    confidence=DEFAULT_CONF,
                ))
        else:
            # Fallback: chunk에 없지만 full_text에 있을 수 있음 (overlap 영역)
            spans = find_all_spans(full_text, value)
            for s, e in spans:
                detections.append(Detection(
                    rule=rule,
                    start=s,
                    end=e,
                    text=value,
                    confidence=DEFAULT_CONF * 0.9,  # fallback은 조금 낮춤
                ))
    return detections


# ── 5. 중복 제거 (chunk overlap NMS) ─────────────────────────────────────────

def dedupe(detections: list[Detection]) -> list[Detection]:
    """동일 (rule, start, end) 중복 제거.
    여러 chunk가 overlap 영역에서 같은 finding을 만들면 confidence가 높은 것 유지.
    """
    best: dict[tuple[str, int, int], Detection] = {}
    for d in detections:
        key = (d.rule, d.start, d.end)
        prev = best.get(key)
        if prev is None or d.confidence > prev.confidence:
            best[key] = d
    return sorted(best.values(), key=lambda x: (x.start, x.end))


def filter_by_prior(
    detections: list[Detection],
    prior_ranges: list[tuple[int, int]],
    overlap_ratio: float = 0.5,
) -> list[Detection]:
    """Regex stage가 이미 잡은 finding과 overlap_ratio 이상 겹치는 SLM finding 제외.
    원격 SLMStage._item_to_finding의 50% overlap 룰과 동일.
    """
    if not prior_ranges:
        return detections
    kept: list[Detection] = []
    for d in detections:
        span = d.end - d.start
        if span <= 0:
            continue
        skip = False
        for ps, pe in prior_ranges:
            ov = max(0, min(d.end, pe) - max(d.start, ps))
            if ov / span >= overlap_ratio:
                skip = True
                break
        if not skip:
            kept.append(d)
    return kept


# ── 6. 메인 진입점 ───────────────────────────────────────────────────────────

class SLMAdapter:
    """파이프라인이 사용하는 외부 인터페이스.

    제공 API:
      - detect(text, prior_ranges=None) -> list[dict]
          단일 텍스트 처리. 원격 SLMStage._scan_text 대응.
      - detect_combined(texts, prior_ranges_per_text=None) -> list[list[dict]]
          여러 target을 SEP로 합쳐 1회 추론하고 target별로 분리.
          원격 SLMStage.scan 대응 (combined 처리로 SLM 호출 횟수 절감).
    """

    SEP = "\n\n"

    def __init__(self, model_path: str, device: str = "cuda"):
        self.runner = SLMRunner(model_path, device=device)
        self.stats  = {"calls": 0, "chunks": 0, "infer_ms": 0.0, "errors": 0}

    # ── 단일 텍스트 ─────────────────────────────────────────────────────────
    def detect(
        self,
        text: str,
        prior_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict]:
        """파이프라인 호환 출력 반환."""
        if not text or not text.strip():
            return []
        self.stats["calls"] += 1
        chunks = chunk_text(text)
        all_dets: list[Detection] = []
        for offset, chunk in chunks:
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
            all_dets.extend(recover_spans(pairs, chunk, offset, text))
        deduped = dedupe(all_dets)
        if prior_ranges:
            deduped = filter_by_prior(deduped, prior_ranges)
        return [d.to_dict() for d in deduped]

    # ── 다중 타깃 combined 추론 ─────────────────────────────────────────────
    def detect_combined(
        self,
        texts: list[str],
        prior_ranges_per_text: list[list[tuple[int, int]]] | None = None,
    ) -> list[list[dict]]:
        """원격 SLMStage.scan과 동일 패턴.
        여러 target 텍스트를 SEP로 합쳐 SLM 호출 횟수 절감, 결과는 target별 분리.

        Args:
            texts: 각 target의 text
            prior_ranges_per_text: 각 target별 regex prior_ranges (target 로컬 좌표)

        Returns:
            len(texts) 길이의 list, 각 원소는 해당 target의 finding dict 목록
        """
        # 빈 텍스트 제외하면서 segment 인덱스 매핑
        segments: list[tuple[int, int, int]] = []  # (orig_idx, seg_start, seg_end)
        parts: list[str] = []
        pos = 0
        for i, t in enumerate(texts):
            if not t or not t.strip():
                continue
            segments.append((i, pos, pos + len(t)))
            parts.append(t)
            pos += len(t) + len(self.SEP)

        results: list[list[dict]] = [[] for _ in texts]
        if not segments:
            return results

        combined = self.SEP.join(parts)

        # prior_ranges를 combined 좌표로 변환
        combined_priors: list[tuple[int, int]] = []
        if prior_ranges_per_text:
            for orig_idx, seg_start, _ in segments:
                if orig_idx < len(prior_ranges_per_text):
                    for ls, le in prior_ranges_per_text[orig_idx]:
                        combined_priors.append((seg_start + ls, seg_start + le))

        # combined 텍스트로 단일 detect (chunking 포함)
        combined_findings = self.detect(combined, prior_ranges=combined_priors)

        # combined 좌표 → 각 target 로컬 좌표
        for f in combined_findings:
            s = f["start"]
            for orig_idx, seg_start, seg_end in segments:
                if seg_start <= s < seg_end:
                    local = dict(f)
                    local["start"] = f["start"] - seg_start
                    local["end"]   = f["end"] - seg_start
                    results[orig_idx].append(local)
                    break
        return results

    def get_stats(self) -> dict:
        s = dict(self.stats)
        s["avg_infer_ms"] = s["infer_ms"] / s["chunks"] if s["chunks"] else 0.0
        return s


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="SLM 추론 어댑터 단독 실행")
    ap.add_argument("--model", required=True, help="merged 모델 경로 (예: output/merged_v5)")
    ap.add_argument("--text",  default=None, help="단일 입력 (생략 시 stdin)")
    ap.add_argument("--device", default="cuda")
    args = ap.parse_args()

    if args.text is None:
        import sys
        args.text = sys.stdin.read()

    adapter = SLMAdapter(args.model, device=args.device)
    t0 = time.monotonic()
    result = adapter.detect(args.text)
    dt = (time.monotonic() - t0) * 1000
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n--- {len(result)} findings, {dt:.1f} ms total ---", flush=True)
    print(f"stats: {adapter.get_stats()}", flush=True)
