"""
ML False Positive 필터.

RegexStage 출력 Finding을 입력받아 "진짜 PII인가?" 이진 분류.
모델 파일 또는 의존 라이브러리 부재 시 자동 비활성화 (no-op fallback).

의존성 (optional):
  - scikit-learn >= 1.2
  - xgboost (또는 다른 sklearn 호환 분류기)
  - joblib (sklearn 번들)

모델 파일:
  models/fp_filter_xgb.pkl       — joblib dump (sklearn Pipeline 권장)
  models/fp_filter_metadata.json — feature 순서, threshold, 학습 날짜, 메트릭

Ordinal 인코딩 (rule_name → int):
  학습 시 동일 RULE_ORDINAL 사전을 사용해야 학습-추론 일치 보장.
  미등록 규칙(커스텀 룰 등)은 UNKNOWN_RULE_ORD로 처리.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.pipeline.base import Finding

from .features import NUMERIC_FEATURE_ORDER, extract_features

log = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).parent / "models"
_MODEL_PATH  = _MODELS_DIR / "fp_filter_xgb.pkl"
_META_PATH   = _MODELS_DIR / "fp_filter_metadata.json"

# ── Ordinal 인코딩 ────────────────────────────────────────────────────────────
# 학습/추론 일치를 위해 tests/build_ml_dataset.py 에도 이 사전을 import하여 사용

RULE_ORDINAL: dict[str, int] = {
    "kr_rrn":             0,
    "credit_card":        1,
    "us_ssn":             2,
    "aws_access_key":     3,
    "pem_private_key":    4,
    "github_pat":         5,
    "kr_passport":        6,
    "kr_driver_license":  7,
    "jwt_token":          8,
    "api_key_assignment": 9,
    "kr_phone":           10,
    "email":              11,
}
UNKNOWN_RULE_ORD = len(RULE_ORDINAL)  # 12 — 커스텀 룰 폴백


# ── FalsePositiveFilter ───────────────────────────────────────────────────────

class FalsePositiveFilter:
    """ML 기반 False Positive 억제 필터.

    Usage
    -----
    flt = load_filter()          # 실패 시 None 반환
    if flt:
        keep, prob = flt.predict(finding, target.text)
    """

    def __init__(
        self,
        model,
        threshold: float = 0.4,
        metadata: dict | None = None,
    ) -> None:
        self._model   = model
        self.threshold = threshold
        self.metadata  = metadata or {}
        # 통계 (런타임 모니터링용)
        self.stats: dict[str, int | float] = {
            "total_calls":      0,
            "suppressed":       0,
            "errors":           0,
        }

    # ── 공개 메서드 ──────────────────────────────────────────────────────────

    def predict(self, finding: "Finding", full_text: str) -> tuple[bool, float]:
        """Finding → (keep, prob_true_pii).

        Parameters
        ----------
        finding   : RegexStage 또는 AssetStage에서 생성된 Finding
        full_text : finding이 속한 DLPTarget.text

        Returns
        -------
        keep : bool
            True  → finding 유지 (TP로 판정 또는 불확실)
            False → finding.suppressed=True 권장 (FP로 판정)
        prob_true_pii : float
            True PII 확률 (0.0 ~ 1.0)
        """
        self.stats["total_calls"] += 1
        try:
            feats = extract_features(finding, full_text)
            x     = self._feats_to_vector(feats)
            proba = self._model.predict_proba([x])[0]
            # sklearn binary: classes_[1]==1 → proba[1] = P(True PII)
            prob_tp = float(proba[1]) if len(proba) >= 2 else float(proba[0])
            keep    = prob_tp >= self.threshold
            if not keep:
                self.stats["suppressed"] += 1
            return keep, prob_tp
        except Exception as exc:
            self.stats["errors"] += 1
            log.warning("[ML Filter] 추론 실패 (%s / %s): %s — 유지(keep)", finding.rule, finding.match_text[:30], exc)
            return True, 1.0  # 보수적 fallback: 유지

    def get_stats(self) -> dict:
        """런타임 통계 반환."""
        total = self.stats["total_calls"]
        suppressed = self.stats["suppressed"]
        return {
            **self.stats,
            "suppress_rate": round(suppressed / total, 4) if total else 0.0,
            "threshold": self.threshold,
            "model_type": type(self._model).__name__,
            "trained_at": self.metadata.get("trained_at", "unknown"),
        }

    # ── 내부 헬퍼 ────────────────────────────────────────────────────────────

    def _feats_to_vector(self, feats: dict) -> list:
        """feature dict → 모델 입력 벡터 (NUMERIC_FEATURE_ORDER 순서)."""
        rule_ord = RULE_ORDINAL.get(feats["rule_name"], UNKNOWN_RULE_ORD)
        # NUMERIC_FEATURE_ORDER 순서대로 값 추출
        values = []
        for col in NUMERIC_FEATURE_ORDER:
            if col == "rule_name_ord":
                values.append(rule_ord)
            else:
                values.append(feats[col])
        return values


# ── 팩토리 함수 ───────────────────────────────────────────────────────────────

def load_filter(
    model_path: str | Path | None = None,
    threshold: float | None = None,
) -> "FalsePositiveFilter | None":
    """FalsePositiveFilter 로드. 실패 시 None 반환 (비활성화 fallback).

    Parameters
    ----------
    model_path : pkl 경로. None이면 models/fp_filter_xgb.pkl 사용.
    threshold  : 분류 임계값. None이면 metadata.json 또는 기본값(0.4) 사용.

    Returns
    -------
    FalsePositiveFilter or None
    """
    path = Path(model_path) if model_path else _MODEL_PATH

    if not path.exists():
        log.info("[ML Filter] 모델 파일 없음 (%s) — ML 필터 비활성화", path.name)
        return None

    try:
        import joblib  # sklearn 번들, sklearn 설치 시 항상 존재
    except ImportError:
        log.warning("[ML Filter] joblib 미설치 — ML 필터 비활성화")
        return None

    try:
        model = joblib.load(path)
    except Exception as exc:
        log.warning("[ML Filter] 모델 로드 실패: %s — ML 필터 비활성화", exc)
        return None

    if not hasattr(model, "predict_proba"):
        log.warning(
            "[ML Filter] 모델(%s)에 predict_proba 없음 — ML 필터 비활성화",
            type(model).__name__,
        )
        return None

    # 메타데이터 로드
    metadata: dict = {}
    if _META_PATH.exists():
        try:
            metadata = json.loads(_META_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 임계값 우선순위: 파라미터 > metadata > 기본값
    if threshold is None:
        threshold = float(metadata.get("threshold", 0.4))

    log.info(
        "[ML Filter] 로드 완료: model=%s, threshold=%.2f, trained_at=%s",
        type(model).__name__,
        threshold,
        metadata.get("trained_at", "unknown"),
    )
    return FalsePositiveFilter(model, threshold=threshold, metadata=metadata)


def get_filter_status() -> dict:
    """외부(TUI/모니터링)에서 ML 필터 상태 조회용."""
    return {
        "model_path":  str(_MODEL_PATH),
        "model_exists": _MODEL_PATH.exists(),
        "meta_path":   str(_META_PATH),
    }
