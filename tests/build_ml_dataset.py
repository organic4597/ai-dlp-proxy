#!/usr/bin/env python3
"""
DLP False Positive 필터용 ML 데이터셋 빌더.

기존 proto phase1 CSV 6개를 로드하여,
각 input_text에 RegexStage를 실행한 뒤 Finding에서 feature를 추출한다.
label:
  1 = True Positive  (진짜 PII — 잘 잡아야 할 것)
  0 = False Positive (오탐  — 억제해야 할 것)

출력: tests/pii_findings_ml_dataset.csv
"""
from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engine.pipeline.regex_stage import RegexStage
from engine.pipeline.base import Finding
from engine.pipeline.ml_filter.features import FEATURE_COLS, extract_features
from engine.pipeline.ml_filter import RULE_ORDINAL, UNKNOWN_RULE_ORD

HERE = Path(__file__).resolve().parent

# ── 소스 CSV 정의 ────────────────────────────────────────────────────────
SOURCES = [
    # 원래 proto phase1 데이터
    (HERE / "proto_phase1_true_positive.csv",            "positive"),
    (HERE / "proto_phase1_realistic_true_positive.csv",  "positive"),
    (HERE / "proto_phase1_false_positive.csv",           "negative"),
    (HERE / "proto_phase1_realistic_false_positive.csv", "negative"),
    (HERE / "proto_phase1_false_negative_risk.csv",      "positive"),
    (HERE / "proto_phase1_over_detection_risk.csv",      "negative"),
    # 합성 데이터 (generate_synthetic_dataset.py 생성)
    (HERE / "synthetic_true_positive.csv",               "positive"),
    (HERE / "synthetic_realistic_true_positive.csv",     "positive"),
    (HERE / "synthetic_false_positive.csv",              "negative"),
    # FN 위험 케이스는 실제 regex가 탐지 못 할 수 있으므로 제외
]

OUTPUT = HERE / "pii_findings_ml_dataset.csv"

# FEATURE_COLS: ml_filter.features에서 import (shared source of truth)
# label 콼럼 포함
FEATURE_COLS_WITH_LABEL = FEATURE_COLS + ["label"]

# rule_name ordinal 콼럼 이름 (모델 입력 순서에 맞춰 데이터셋에도 구욹)
FEATURE_COLS_NUMERIC = ["rule_name_ord"] + [c for c in FEATURE_COLS if c != "rule_name"] + ["label"]


@dataclass
class DLPTarget:
    field_path: str
    role: str
    text: str

# _entropy, _extract_features는 engine.pipeline.ml_filter.features의
# extract_features로 통합 (단일 소스 보장)


def build_dataset() -> None:
    stage = RegexStage()
    rows: list[dict] = []

    total_processed = 0
    total_found = 0
    skipped_no_finding = 0

    for csv_path, polarity in SOURCES:
        if not csv_path.exists():
            print(f"[SKIP] {csv_path.name} 없음")
            continue

        label = 1 if polarity == "positive" else 0
        print(f"[LOAD] {csv_path.name} → label={label}")

        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                case_id = row.get("case_id", "").strip()
                if case_id.startswith("#") or not case_id:
                    continue

                input_text = row.get("input_text", "").strip()
                expected_rule = row.get("expected_rule", "").strip()

                target = DLPTarget("messages[0].content", "user", input_text)
                findings = stage.scan([target], [])
                total_processed += 1

                # expected_rule과 일치하는 finding만 선택
                matched = [f for f in findings if f.rule == expected_rule]

                if not matched:
                    skipped_no_finding += 1
                    # FP 데이터에서 regex가 아예 안 터진 경우는
                    # 모델 입력이 없으므로 제외
                    continue

                for finding in matched:
                    features = extract_features(finding, input_text)
                    features["label"] = label
                    features["_case_id"] = case_id
                    # ordinal 콼럼 추가 (노트북 학습 편의)
                    features["rule_name_ord"] = RULE_ORDINAL.get(finding.rule, UNKNOWN_RULE_ORD)
                    rows.append(features)
                    total_found += 1

    print(f"\n처리: {total_processed}건  |  Finding 추출: {total_found}건  |  Finding 없어서 제외: {skipped_no_finding}건")
    print(f"label=1 (TP): {sum(1 for r in rows if r['label'] == 1)}건")
    print(f"label=0 (FP): {sum(1 for r in rows if r['label'] == 0)}건")

    # _case_id 제거 후 저장
    final_cols = ["_case_id"] + FEATURE_COLS + ["rule_name_ord", "label"]
    with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=final_cols)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n저장 완료 → {OUTPUT}")
    print(f"전 {len(rows)}행, {len(FEATURE_COLS)}개 feature + rule_name_ord + label")
    print("\n소스별 건수:")
    for src_path, pol in SOURCES:
        if src_path.exists():
            src_rows = [r for r in rows if r.get("_case_id", "").startswith(src_path.stem[:8])]
            print(f"  {src_path.name:<55} {len(src_rows):>5}행")


if __name__ == "__main__":
    build_dataset()
