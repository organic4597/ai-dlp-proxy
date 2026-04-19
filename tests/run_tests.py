#!/usr/bin/env python3
"""
DLP 파이프라인 테스트 러너.

test_cases.csv   — 개별 PII 값 단위 탐지 검증
test_requests.json — OpenAI 형식 요청 단위 파이프라인 검증
"""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from engine.api.base import DLPTarget
from engine.pipeline import run_pipeline, get_cache_stats
from engine.pipeline.regex_stage import RegexStage

HERE = Path(__file__).resolve().parent

# ── 색상 ─────────────────────────────────────────────────────────────────
G = "\033[32m"  # green
R = "\033[31m"  # red
Y = "\033[33m"  # yellow
W = "\033[0m"   # reset


def _setup_control_file() -> None:
    """테스트용 제어 파일 초기화.

    E01/E02: email이 disabled_rules에 포함되어야 탐지 안 됨.
    T01: 이메일 주소가 포함된 복합 메시지에서 email 룰 비활성.
    파일이 root 소유인 경우 sudo tee로 덮어씀.
    """
    ctrl = {
        "disabled_rules": ["email"],
        "confidence_threshold": 0.5,
        "context_penalty_enabled": True,
        "allowlist": [],
    }
    content = json.dumps(ctrl, ensure_ascii=False).encode("utf-8")
    path = "/tmp/dlp-control.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ctrl, f, ensure_ascii=False)
    except PermissionError:
        subprocess.run(["sudo", "tee", path], input=content, check=True, capture_output=True)


def run_csv_tests() -> tuple[int, int]:
    """test_cases.csv 실행. (passed, failed) 반환."""
    csv_path = HERE / "test_cases.csv"
    stage = RegexStage()
    passed = failed = 0

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["test_id"].strip()
            if tid.startswith("#") or not tid:
                continue

            text = row["input_text"].strip()
            should = row["should_detect"].strip().lower() == "true"
            expected_rule = row.get("expected_rule", "").strip()

            target = DLPTarget("test.content", "user", text)
            findings = stage.scan([target], [])

            detected = len(findings) > 0
            rule_match = True
            if should and expected_rule:
                rule_match = any(f.rule == expected_rule for f in findings)

            ok = (detected == should) and rule_match

            if ok:
                passed += 1
                status = f"{G}PASS{W}"
            else:
                failed += 1
                found_rules = [f.rule for f in findings] if findings else []
                status = f"{R}FAIL{W} (detected={found_rules}, expected={'['+expected_rule+']' if should else '[]'})"

            print(f"  [{status}] {tid:6s} {row['category']:20s} {text[:50]}")

    return passed, failed


def run_json_tests() -> tuple[int, int]:
    """test_requests.json 실행 — 파이프라인 통합 테스트. (passed, failed) 반환."""
    json_path = HERE / "test_requests.json"
    with open(json_path, encoding="utf-8") as f:
        cases = json.load(f)

    # 파이프라인 캐시 리셋
    from engine.pipeline import _msg_cache, _cache_stats
    _msg_cache.clear()
    _cache_stats["hits"] = 0
    _cache_stats["misses"] = 0

    passed = failed = 0

    for case in cases:
        tid = case["id"]
        desc = case["description"]
        messages = case["request"]["messages"]
        expected = case["expected"]
        exp_rules = set(expected["detected_rules"])
        exp_action = expected["action"]

        # user/tool 메시지만 타깃 생성 (openai 파서와 동일)
        targets = []
        for i, msg in enumerate(messages):
            if msg["role"] in ("user", "tool"):
                targets.append(DLPTarget(
                    f"messages[{i}].content", msg["role"], msg["content"],
                ))

        result = run_pipeline(targets)
        found_rules = set(f.rule for f in result.findings)
        actual_action = result.action.value

        rules_ok = exp_rules == found_rules
        action_ok = exp_action == actual_action
        ok = rules_ok and action_ok

        if ok:
            passed += 1
            status = f"{G}PASS{W}"
        else:
            failed += 1
            detail = []
            if not rules_ok:
                detail.append(f"rules: got={sorted(found_rules)}, exp={sorted(exp_rules)}")
            if not action_ok:
                detail.append(f"action: got={actual_action}, exp={exp_action}")
            status = f"{R}FAIL{W} ({', '.join(detail)})"

        print(f"  [{status}] {tid:4s} {desc}")

    cache = get_cache_stats()
    print(f"\n  캐시 통계: hits={cache['hits']}, misses={cache['misses']}, size={cache['size']}")
    return passed, failed


def main():
    print(f"\n{'='*70}")
    print(f"  DLP 파이프라인 테스트")
    print(f"{'='*70}")

    _setup_control_file()

    print(f"\n{Y}▶ CSV 단위 테스트 (test_cases.csv){W}")
    csv_pass, csv_fail = run_csv_tests()

    print(f"\n{Y}▶ JSON 통합 테스트 (test_requests.json){W}")
    json_pass, json_fail = run_json_tests()

    total_pass = csv_pass + json_pass
    total_fail = csv_fail + json_fail

    print(f"\n{'='*70}")
    color = G if total_fail == 0 else R
    print(f"  {color}결과: {total_pass} passed, {total_fail} failed{W}")
    print(f"{'='*70}\n")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
