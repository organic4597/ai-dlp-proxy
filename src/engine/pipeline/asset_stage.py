"""
AssetStage — 보호 자산 키워드 + 임베딩 유사도 탐지 (Step 8).

동작 방식:
1. 키워드 전문 검색 (청킹 없이 전체 텍스트에서 직접 검색)
2. 의미 기반 청킹 → ONNX/PyTorch 임베딩 → cosine 유사도 비교
3. sentence-transformers 미설치 시 키워드 전용 모드 graceful fallback
4. assets.json mtime 기반 캐시 + double-checked locking으로 스레드 안전

자산 파일 경로: ~/.config/ai-dlp-proxy/assets.json
형식:
    {
        "assets": [
            {
                "id": "a1",
                "name": "SSH 키",
                "severity": "critical",
                "keywords": ["id_rsa", ".ssh", "authorized_keys"],
                "examples": ["id_rsa 파일을 첨부합니다", "SSH 키를 보내드립니다"],
                "embedding_threshold": 0.85
            }
        ]
    }
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .base import Finding, Severity, Stage
from .default_assets import ensure_default_assets_file

log = logging.getLogger(__name__)

ASSETS_PATH = Path.home() / ".config" / "ai-dlp-proxy" / "assets.json"
_DEFAULT_EMBEDDING_THRESHOLD = 0.80
_ASSET_EMBEDDING_TIMEOUT_MS = 500
_EMBED_CACHE_MAX = 256

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class _Asset:
    id: str
    name: str
    severity: Severity
    keywords: list[str]
    examples: list[str]
    embedding_threshold: float
    example_vecs: list | None = None  # numpy array list, loaded lazily


def _cosine_sim(a, b) -> float:
    """두 numpy 벡터의 cosine 유사도."""
    try:
        import numpy as np
        dot = float(np.dot(a, b))
        norm = float(np.linalg.norm(a) * np.linalg.norm(b))
        return dot / norm if norm > 0 else 0.0
    except Exception:
        return 0.0


def _semantic_chunks(text: str, max_len: int = 200, stride: int = 100) -> list[str]:
    """의미 기반 청킹.

    1차: '\n' 또는 마침표 기준 문장 분할
    문장이 max_len 초과하면 슬라이딩 윈도우 적용.
    전체 길이 < max_len이면 단일 청크.
    """
    if len(text) <= max_len:
        return [text]

    # 문장 분할 (빈 문자열 제거)
    sentences = [s.strip() for s in re.split(r"[\n.]+", text) if s.strip()]
    chunks: list[str] = []
    for sentence in sentences:
        if len(sentence) <= max_len:
            chunks.append(sentence)
        else:
            # 슬라이딩 윈도우
            for start in range(0, len(sentence), stride):
                chunk = sentence[start : start + max_len]
                if chunk:
                    chunks.append(chunk)
    return chunks if chunks else [text[:max_len]]


class AssetStage(Stage):
    """보호 자산 탐지 스테이지."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._assets: list[_Asset] = []
        self._cached_mtime: float | None = None
        self._model: object | None = None  # sentence-transformers 모델
        self._model_loaded = False
        self._embed_cache: dict[str, object] = {}  # sha256 → numpy array
        self._runtime_warnings: list[str] = []

        self._load_assets()
        self._try_load_model()

    @property
    def name(self) -> str:
        return "asset"

    def runtime_warning_lines(self) -> list[str]:
        return list(self._runtime_warnings)

    def _warn_runtime(self, message: str) -> None:
        if message not in self._runtime_warnings:
            self._runtime_warnings.append(message)
        log.warning(message)

    # ── 모델 로드 ─────────────────────────────────────────────────────────────

    def _try_load_model(self) -> None:
        """sentence-transformers 로드 시도. 실패하면 키워드 전용 모드."""
        if self._model_loaded:
            return
        self._model_loaded = True
        try:
            # ONNX optimum 우선
            try:
                from optimum.onnxruntime import ORTModelForFeatureExtraction  # type: ignore
                from transformers import AutoTokenizer  # type: ignore
                # ONNX 모델 시도 → 실패하면 PyTorch fallback
            except ImportError:
                pass

            from sentence_transformers import SentenceTransformer  # type: ignore
            model_candidates = [
                "jhgan/ko-sroberta-multitask",
                "BM-K/KoSimCSE-roberta",
                "all-MiniLM-L6-v2",
            ]
            for model_name in model_candidates:
                try:
                    self._model = SentenceTransformer(model_name)
                    # 워밍업 (콜드 스타트 방지)
                    self._model.encode("warmup", show_progress_bar=False)  # type: ignore
                    log.info("[asset] 임베딩 모델 로드 완료: %s", model_name)
                    break
                except Exception:
                    continue
            if self._model is None:
                self._warn_runtime("[asset] 임베딩 모델 로드 실패 — 키워드 전용 모드")
        except ImportError:
            self._warn_runtime("[asset] sentence-transformers 미설치 — 키워드 전용 모드")
        except OSError:
            self._warn_runtime("[asset] 오프라인/에어갭 환경 — 키워드 전용 모드")

    # ── 자산 로드 ─────────────────────────────────────────────────────────────

    def _load_assets(self, seed_if_missing: bool = False) -> None:
        """assets.json 로드. 필요 시 기본 자산을 초기 시드한다."""
        path = ASSETS_PATH
        if seed_if_missing:
            ensure_default_assets_file(path)
        if not path.exists():
            self._assets = []
            self._cached_mtime = None
            return

        try:
            mtime = path.stat().st_mtime
        except OSError:
            self._assets = []
            self._cached_mtime = None
            return

        # Lock 밖 빠른 체크
        if self._cached_mtime is not None and mtime == self._cached_mtime:
            return

        with self._lock:
            # Lock 안 재확인
            if self._cached_mtime is not None and mtime == self._cached_mtime:
                return
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                assets = []
                for a in raw.get("assets", []):
                    sev = _SEVERITY_MAP.get(str(a.get("severity", "high")).lower(), Severity.HIGH)
                    asset = _Asset(
                        id=str(a.get("id", "")),
                        name=str(a.get("name", "")),
                        severity=sev,
                        keywords=[str(k) for k in a.get("keywords", [])],
                        examples=[str(e) for e in a.get("examples", [])],
                        embedding_threshold=float(a.get("embedding_threshold", _DEFAULT_EMBEDDING_THRESHOLD)),
                    )
                    assets.append(asset)
                self._assets = assets
                self._cached_mtime = mtime
                # 임베딩 재계산
                if self._model:
                    self._recompute_embeddings()
            except Exception as e:
                log.error("[asset] assets.json 로드 실패: %s", e)

    def _recompute_embeddings(self) -> None:
        """각 자산의 examples 임베딩 벡터 계산."""
        for asset in self._assets:
            if not asset.examples:
                asset.example_vecs = []
                continue
            try:
                vecs = [self._cached_embed(ex) for ex in asset.examples]
                asset.example_vecs = vecs
            except Exception as e:
                log.warning("[asset] '%s' 임베딩 계산 실패: %s", asset.name, e)
                asset.example_vecs = []

    # ── 임베딩 캐시 ───────────────────────────────────────────────────────────

    def _cached_embed(self, text: str):
        """SHA-256 기반 임베딩 캐시 (FIFO, maxsize=256)."""
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if key not in self._embed_cache:
            if len(self._embed_cache) >= _EMBED_CACHE_MAX:
                # FIFO: 가장 오래된 항목 제거
                self._embed_cache.pop(next(iter(self._embed_cache)))
            self._embed_cache[key] = self._model.encode(text, show_progress_bar=False)  # type: ignore
        return self._embed_cache[key]

    # ── 스캔 ─────────────────────────────────────────────────────────────────

    def scan(self, targets: list, findings: list[Finding]) -> list[Finding]:
        # 자산 파일 변경 감지 후 리로드
        self._load_assets(seed_if_missing=True)

        if not self._assets:
            return []

        result: list[Finding] = []
        for target in targets:
            text = getattr(target, "text", "")
            if not text:
                continue
            kw_findings = self._scan_keywords(target, text)
            result.extend(kw_findings)
            if self._model:
                result.extend(self._scan_embeddings(target, text, kw_findings))

        return result

    def _scan_keywords(self, target, text: str) -> list[Finding]:
        """키워드 전문 검색. 청킹 없이 전체 텍스트에서 직접 검색."""
        found: list[Finding] = []
        for asset in self._assets:
            for keyword in asset.keywords:
                idx = text.lower().find(keyword.lower())
                if idx == -1:
                    continue
                end = idx + len(keyword)
                found.append(Finding(
                    stage=self.name,
                    rule=asset.name,
                    severity=asset.severity,
                    field_path=target.field_path,
                    role=target.role,
                    match_text=text[idx:end],
                    match_start=idx,
                    match_end=end,
                    context_before=text[max(0, idx - 100):idx],
                    context_after=text[end:min(len(text), end + 100)],
                    confidence=1.0,
                    metadata={"asset_id": asset.id, "match_type": "keyword", "keyword": keyword},
                ))
                break  # 자산당 첫 번째 키워드 매치만 (중복 방지)
        return found

    def _scan_embeddings(self, target, text: str, kw_findings: list[Finding] | None = None) -> list[Finding]:
        """의미 청킹 + cosine 유사도로 자산 탐지."""
        import asyncio
        import concurrent.futures

        found: list[Finding] = []
        chunks = _semantic_chunks(text)

        for asset in self._assets:
            if not asset.example_vecs:
                continue

            timeout_s = _ASSET_EMBEDDING_TIMEOUT_MS / 1000.0
            best_sim = 0.0
            best_chunk = ""
            best_start = 0

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self._embed_chunks_and_compare, chunks, asset)
                    best_sim, best_chunk, best_start = future.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError:
                log.warning("[asset] '%s' 임베딩 타임아웃 — 스킵", asset.name)
                continue
            except Exception as e:
                log.debug("[asset] 임베딩 오류: %s", e)
                continue

            if best_sim >= asset.embedding_threshold:
                # 매칭된 청크의 텍스트 위치 계산
                chunk_start = text.find(best_chunk)
                if chunk_start == -1:
                    chunk_start = best_start
                chunk_end = chunk_start + len(best_chunk)

                # 키워드 매치에서 이미 탐지된 자산은 중복 추가 안 함
                already_found = any(
                    f.rule == asset.name and f.metadata.get("match_type") == "keyword"
                    for f in (kw_findings or [])
                )
                if already_found:
                    continue

                found.append(Finding(
                    stage=self.name,
                    rule=asset.name,
                    severity=asset.severity,
                    field_path=target.field_path,
                    role=target.role,
                    match_text=best_chunk,
                    match_start=chunk_start,
                    match_end=chunk_end,
                    context_before=text[max(0, chunk_start - 100):chunk_start],
                    context_after=text[chunk_end:min(len(text), chunk_end + 100)],
                    confidence=round(best_sim, 4),
                    metadata={"asset_id": asset.id, "match_type": "embedding", "similarity": best_sim},
                ))

        return found

    def _embed_chunks_and_compare(
        self, chunks: list[str], asset: _Asset
    ) -> tuple[float, str, int]:
        """청크별 임베딩 계산 + 예문 벡터와 max cosine 유사도 반환.
        (best_sim, best_chunk, chunk_offset)
        """
        best_sim = 0.0
        best_chunk = ""
        best_idx = 0

        for i, chunk in enumerate(chunks):
            chunk_vec = self._cached_embed(chunk)
            for ex_vec in asset.example_vecs:
                sim = _cosine_sim(chunk_vec, ex_vec)
                if sim > best_sim:
                    best_sim = sim
                    best_chunk = chunk
                    best_idx = i

        return best_sim, best_chunk, best_idx
