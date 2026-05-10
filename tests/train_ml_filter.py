#!/usr/bin/env python3
"""
ML FP 필터 모델 학습 스크립트.

pii_findings_ml_dataset.csv를 읽어 XGBoost / Random Forest / Logistic Regression 3개를
학습·비교하고, 최고 성능 모델(XGBoost)을 joblib으로 저장한다.

Usage:
    cd /home1/ai-dlp-proxy
    python3 tests/train_ml_filter.py [--threshold 0.4] [--model xgb|rf|lr]

출력:
    src/engine/pipeline/ml_filter/models/fp_filter_xgb.pkl
    src/engine/pipeline/ml_filter/models/fp_filter_metadata.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[경고] xgboost 미설치 — Random Forest로 대체")

import joblib

from engine.pipeline.ml_filter import RULE_ORDINAL, UNKNOWN_RULE_ORD
from engine.pipeline.ml_filter.features import NUMERIC_FEATURE_ORDER

HERE      = Path(__file__).resolve().parent
DATA_PATH = HERE / "pii_findings_ml_dataset.csv"
OUT_DIR   = ROOT / "src" / "engine" / "pipeline" / "ml_filter" / "models"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ── feature 준비 ─────────────────────────────────────────────────────────────

def load_data(path: Path) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    print(f"\n데이터셋: {len(df)}행  (TP={df['label'].sum()}, FP={(df['label']==0).sum()})")

    # rule_name → ordinal (이미 rule_name_ord 컬럼 있으면 그대로 사용)
    if "rule_name_ord" not in df.columns:
        df["rule_name_ord"] = df["rule_name"].map(RULE_ORDINAL).fillna(UNKNOWN_RULE_ORD).astype(int)

    # NUMERIC_FEATURE_ORDER에서 실제 컬럼명에 맞춰 X 구성
    feature_cols = [c for c in NUMERIC_FEATURE_ORDER if c in df.columns]
    X = df[feature_cols].values.astype(float)
    y = df["label"].values.astype(int)
    print(f"Features: {feature_cols}")
    return X, y


# ── 모델 정의 ──────────────────────────────────────────────────────────────────

def get_models(threshold: float) -> dict[str, object]:
    models: dict[str, object] = {}

    if HAS_XGB:
        models["XGBoost"] = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )

    models["RandomForest"] = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    models["LogisticRegression"] = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=500,
            random_state=42,
        )),
    ])

    return models


# ── 학습 및 비교 ──────────────────────────────────────────────────────────────

def train_and_compare(X: np.ndarray, y: np.ndarray, threshold: float = 0.4) -> tuple[str, object, dict]:
    models = get_models(threshold)
    skf    = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    print(f"\n{'='*65}")
    print(f"{'모델':<22} {'F1':>6} {'Recall':>8} {'Precision':>10} {'ROC-AUC':>9}")
    print(f"{'─'*65}")

    best_name:  str | None = None
    best_score: float = -1.0
    best_model: object = None
    results: dict[str, dict] = {}

    for name, model in models.items():
        f1_scores  = cross_val_score(model, X, y, cv=skf, scoring="f1",       n_jobs=-1)
        rec_scores = cross_val_score(model, X, y, cv=skf, scoring="recall",   n_jobs=-1)
        pre_scores = cross_val_score(model, X, y, cv=skf, scoring="precision",n_jobs=-1)
        auc_scores = cross_val_score(model, X, y, cv=skf, scoring="roc_auc",  n_jobs=-1)

        f1  = f1_scores.mean()
        rec = rec_scores.mean()
        pre = pre_scores.mean()
        auc = auc_scores.mean()

        results[name] = {"f1": round(f1, 4), "recall": round(rec, 4),
                         "precision": round(pre, 4), "roc_auc": round(auc, 4)}
        print(f"  {name:<20} {f1:>6.4f}  {rec:>8.4f}  {pre:>10.4f}  {auc:>9.4f}")

        if f1 > best_score:
            best_score = f1
            best_name  = name
            best_model = model

    print(f"{'='*65}")
    print(f"\n최고 성능: {best_name}  (F1={best_score:.4f})")

    # 최고 모델 전체 데이터로 재학습
    assert best_model is not None
    best_model.fit(X, y)
    return best_name, best_model, results  # type: ignore[return-value]


# ── 저장 ──────────────────────────────────────────────────────────────────────

def save_model(
    name: str,
    model: object,
    results: dict,
    threshold: float,
    model_key: str = "xgb",
) -> None:
    pkl_path  = OUT_DIR / f"fp_filter_{model_key}.pkl"
    meta_path = OUT_DIR / "fp_filter_metadata.json"

    joblib.dump(model, pkl_path)
    print(f"\n모델 저장 → {pkl_path}")

    meta = {
        "model_name":   name,
        "model_file":   pkl_path.name,
        "threshold":    threshold,
        "trained_at":   datetime.now(timezone.utc).isoformat(),
        "feature_order": NUMERIC_FEATURE_ORDER,
        "rule_ordinal":  RULE_ORDINAL,
        "cv_results":   results,
        "dataset":      str(DATA_PATH),
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"메타데이터 저장 → {meta_path}")


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ML FP 필터 학습")
    parser.add_argument("--threshold", type=float, default=0.4,
                        help="TP 확률 임계값 (기본: 0.4, 낮을수록 Recall 우선)")
    parser.add_argument("--model", choices=["xgb", "rf", "lr"], default="xgb",
                        help="저장할 모델 (기본: xgb)")
    args = parser.parse_args()

    if not DATA_PATH.exists():
        print(f"[오류] 데이터셋 없음: {DATA_PATH}")
        print("  → python3 tests/build_ml_dataset.py 먼저 실행하세요")
        sys.exit(1)

    X, y = load_data(DATA_PATH)
    best_name, best_model, results = train_and_compare(X, y, args.threshold)
    save_model(best_name, best_model, results, args.threshold, model_key=args.model)

    print("\n통합 확인:")
    print("  python3 -c \"from engine.pipeline.ml_filter import load_filter; f=load_filter(); print('OK' if f else 'no model')\"")


if __name__ == "__main__":
    main()
