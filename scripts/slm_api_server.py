#!/usr/bin/env python3
"""
SLM API Server — 학습 서버(WSL2/GPU)에서 실행하는 FastAPI 추론 서버.

라즈베리파이(DLP Proxy)가 SSH 역방향 터널을 통해 localhost:8765로 호출하면
이 서버가 SLMAdapter(Qwen3.5-4B 파인튜닝 모델)로 추론하여 결과를 반환한다.

실행:
    CUDA_VISIBLE_DEVICES=0 python3 scripts/slm_api_server.py \\
        --model output/merged_v5 --port 8765 --device cuda --dtype fp16

엔드포인트:
    GET  /health           → 서버·모델 상태 확인
    POST /detect           → 단일 텍스트 PII 탐지
    POST /detect_batch     → 여러 텍스트 일괄 PII 탐지
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

# argparse를 모듈 임포트 시점(uvicorn worker reload)에도 안전하게 호출
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--model",   default="output/merged_v5")
_parser.add_argument("--host",    default="0.0.0.0")
_parser.add_argument("--port",    type=int, default=8766)
_parser.add_argument("--device",  default="cuda")
_parser.add_argument("--dtype",   default="fp16",
                     choices=["fp16", "bf16", "int4"])
_parser.add_argument("--workers", type=int, default=1)
_args, _ = _parser.parse_known_args()

# ── 로깅 설정 ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("slm_api")

# ── FastAPI / Pydantic ──────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    log.error("fastapi/uvicorn 미설치: pip install fastapi uvicorn")
    sys.exit(1)

# ── SLMAdapter 임포트 경로 설정 ───────────────────────────────────────────────
# 학습 서버에서는 /qwen_tunning/fine-tunning/sLM/slm_adapter.py 위치 가정.
# 실제 경로가 다르면 PYTHONPATH 에 포함시키거나 --model 인수 조정.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent  # ai-dlp-proxy/

# 1순위: 같은 리포 내 fine-tunning/sLM
_ADAPTER_SEARCH = [
    _REPO_ROOT / "fine-tunning" / "sLM",
    Path("/qwen_tunning/fine-tunning/sLM"),
    Path.home() / "qwen_tunning" / "fine-tunning" / "sLM",
]
for _p in _ADAPTER_SEARCH:
    if (_p / "slm_adapter.py").exists():
        if str(_p) not in sys.path:
            sys.path.insert(0, str(_p))
        log.info("slm_adapter 경로: %s", _p)
        break

try:
    from slm_adapter import SLMAdapter  # type: ignore
except ImportError:
    log.error(
        "slm_adapter.py 를 찾을 수 없습니다. "
        "PYTHONPATH 에 slm_adapter.py 가 있는 디렉터리를 추가하세요."
    )
    sys.exit(1)

# ── 모델 dtype 매핑 ──────────────────────────────────────────────────────────
import torch  # type: ignore

_DTYPE_MAP = {
    "fp16": torch.float16,
    "bf16": torch.bfloat16,
    "int4": None,  # BitsAndBytes 4-bit — SLMAdapter가 내부 처리
}

# ── 전역 어댑터 (서버 시작 시 1회 로드) ──────────────────────────────────────
_adapter: SLMAdapter | None = None
_model_path: str = _args.model
_device: str = _args.device
_dtype_str: str = _args.dtype
_load_error: str | None = None

app = FastAPI(title="SLM DLP API", version="1.0.0")


@app.on_event("startup")
async def _load_model() -> None:
    global _adapter, _load_error
    log.info("모델 로딩 중: %s  device=%s  dtype=%s", _model_path, _device, _dtype_str)
    try:
        dtype = _DTYPE_MAP[_dtype_str]
        if dtype is not None:
            _adapter = SLMAdapter(_model_path, device=_device, dtype=dtype)
        else:
            # int4: dtype 인자 없이 호출 (SLMAdapter가 load_in_4bit 처리)
            _adapter = SLMAdapter(_model_path, device=_device)
        log.info("모델 로드 완료")
    except Exception as exc:
        _load_error = str(exc)
        log.error("모델 로드 실패: %s", exc)


# ── 요청/응답 스키마 ─────────────────────────────────────────────────────────

class DetectRequest(BaseModel):
    text: str
    prior_ranges: Optional[list[list[int]]] = None   # [[start,end], ...]


class DetectBatchRequest(BaseModel):
    texts: list[str]
    prior_ranges_per_text: Optional[list[Optional[list[list[int]]]]] = None


class FindingSchema(BaseModel):
    rule: str
    start: int
    end: int
    text: str
    confidence: float


class DetectResponse(BaseModel):
    findings: list[FindingSchema]
    elapsed_ms: float


class DetectBatchResponse(BaseModel):
    results: list[list[FindingSchema]]
    elapsed_ms: float


# ── 헬퍼 ────────────────────────────────────────────────────────────────────

def _to_prior_tuples(
    raw: list[list[int]] | None,
) -> list[tuple[int, int]]:
    if not raw:
        return []
    result: list[tuple[int, int]] = []
    for item in raw:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            s, e = int(item[0]), int(item[1])
            if s < e:
                result.append((s, e))
    return result


def _ensure_adapter() -> SLMAdapter:
    if _adapter is None:
        raise HTTPException(
            status_code=503,
            detail=f"모델 미로드{': ' + _load_error if _load_error else ''}",
        )
    return _adapter


# ── 엔드포인트 ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> JSONResponse:
    """서버 및 모델 상태 확인."""
    return JSONResponse({
        "status": "ok" if _adapter is not None else "loading",
        "model": _model_path,
        "device": _device,
        "dtype": _dtype_str,
        "error": _load_error,
    })


@app.post("/detect", response_model=DetectResponse)
async def detect(req: DetectRequest) -> DetectResponse:
    """단일 텍스트 PII 탐지."""
    adapter = _ensure_adapter()
    prior = _to_prior_tuples(req.prior_ranges)
    t0 = time.monotonic()
    try:
        raw_findings = adapter.detect(req.text, prior_ranges=prior or None)
    except Exception as exc:
        log.error("/detect 오류: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    elapsed_ms = (time.monotonic() - t0) * 1000
    findings = [FindingSchema(**f) for f in raw_findings]
    return DetectResponse(findings=findings, elapsed_ms=round(elapsed_ms, 2))


@app.post("/detect_batch", response_model=DetectBatchResponse)
async def detect_batch(req: DetectBatchRequest) -> DetectBatchResponse:
    """여러 텍스트 일괄 PII 탐지."""
    adapter = _ensure_adapter()

    prior_list: list[list[tuple[int, int]] | None] = []
    if req.prior_ranges_per_text:
        for raw in req.prior_ranges_per_text:
            prior_list.append(_to_prior_tuples(raw) if raw else None)
    else:
        prior_list = [None] * len(req.texts)

    # None → [] 정규화
    norm_prior = [p or [] for p in prior_list]

    t0 = time.monotonic()
    try:
        batch_results = adapter.detect_combined(
            req.texts,
            prior_ranges_per_text=norm_prior or None,
        )
    except Exception as exc:
        log.error("/detect_batch 오류: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    elapsed_ms = (time.monotonic() - t0) * 1000

    results = [
        [FindingSchema(**f) for f in findings]
        for findings in batch_results
    ]
    return DetectBatchResponse(results=results, elapsed_ms=round(elapsed_ms, 2))


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(
        "SLM API 서버 시작  host=%s  port=%d  model=%s  device=%s  dtype=%s",
        _args.host, _args.port, _args.model, _args.device, _args.dtype,
    )
    uvicorn.run(
        "slm_api_server:app",
        host=_args.host,
        port=_args.port,
        workers=_args.workers,
        log_level="info",
    )
