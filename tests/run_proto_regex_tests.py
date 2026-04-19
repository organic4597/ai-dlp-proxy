#!/usr/bin/env python3
"""
Regex 프로덕션 테스트 러너.

Phase 1 기준으로 일곱 구역을 실행한다.
1. 기본 정탐(True Positive) 데이터셋
2. 기본 오탐(False Positive) 억제 데이터셋
3. 현실형 정탐 데이터셋
4. 현실형 과탐 억제 데이터셋
5. 미탐 위험(False Negative Risk) 데이터셋
6. 과탐 위험(Over-detection Risk) 데이터셋
7. 제어/롤백 회귀 테스트
"""
from __future__ import annotations

import csv
import json
import sys
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "engine"))

from pipeline.control import DEFAULT_CONTROL_PATH, load_control
from pipeline.regex_stage import RegexStage, _context_multiplier
from pipeline.base import Action, Finding, PipelineResult, Severity

# 프로토타입에만 있던 룰 (password_assignment)은 프로덕션에 없으므로 건너뾴
_SKIP_RULES = frozenset({"password_assignment"})


def run_regex_pipeline(targets: list, control_path: str = DEFAULT_CONTROL_PATH) -> PipelineResult:
    """Regex-only 파이프라인 (테스트용)."""
    t0 = time.monotonic()
    control = load_control(control_path)
    stage = RegexStage(control_path=control_path)
    findings = stage.scan(targets, [])
    effective = [
        f for f in findings
        if f.confidence >= control.confidence_threshold and not f.suppressed
    ]
    if not effective:
        action = Action.PASS
    else:
        max_sev = max(f.severity.value for f in effective)
        action = Action.MASK if max_sev >= Severity.CRITICAL.value else Action.ALERT
    elapsed = round((time.monotonic() - t0) * 1000, 2)
    return PipelineResult(action=action, findings=findings, elapsed_ms=elapsed)


G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
W = "\033[0m"
HERE = Path(__file__).resolve().parent


@dataclass
class DLPTarget:
    field_path: str
    role: str
    text: str


def _write_control(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _single_finding(text: str, control_path: str = DEFAULT_CONTROL_PATH):
    stage = RegexStage(control_path=control_path)
    findings = stage.scan([DLPTarget("test.content", "user", text)], [])
    return findings[0] if findings else None


def _run_case(case_id: str, condition: bool, detail: str = "") -> int:
    if condition:
        print(f"[{G}PASS{W}] {case_id} {detail}")
        return 0
    print(f"[{R}FAIL{W}] {case_id} {detail}")
    return 1


def _read_csv_cases(path: Path) -> list[dict[str, str]]:
    with open(path, encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _find_rule_finding(findings, expected_rule: str):
    for finding in findings:
        if finding.rule == expected_rule:
            return finding
    return None


def _run_positive_suite(control_path: str, csv_name: str, title: str) -> tuple[int, int]:
    cases = _read_csv_cases(HERE / csv_name)
    passed = failed = 0

    print(f"\n{Y}▶ {title}{W}")
    for row in cases:
        if row["expected_rule"] in _SKIP_RULES:
            continue
        result = run_regex_pipeline([
            DLPTarget("messages[0].content", "user", row["input_text"]),
        ], control_path=control_path)
        finding = _find_rule_finding(result.findings, row["expected_rule"])
        min_conf = float(row["min_confidence"])
        ok = (
            finding is not None
            and finding.confidence >= min_conf
            and finding.suppressed is False
            and result.action.value == row["expected_action"]
        )
        detail = (
            f"rule={getattr(finding, 'rule', None)} "
            f"conf={getattr(finding, 'confidence', None)} "
            f"action={result.action.value}"
        )
        if ok:
            passed += 1
        else:
            failed += 1
        _run_case(row["case_id"], ok, detail)

    return passed, failed


def _run_negative_suite(control_path: str, csv_name: str, title: str) -> tuple[int, int]:
    cases = _read_csv_cases(HERE / csv_name)
    passed = failed = 0

    print(f"\n{Y}▶ {title}{W}")
    for row in cases:
        if row["expected_rule"] in _SKIP_RULES:
            continue
        result = run_regex_pipeline([
            DLPTarget("messages[0].content", "user", row["input_text"]),
        ], control_path=control_path)
        finding = _find_rule_finding(result.findings, row["expected_rule"])
        max_conf = float(row["max_confidence"])
        ok = (
            finding is not None
            and finding.confidence <= max_conf + 1e-9
            and result.action.value == row["expected_action"]
        )
        detail = (
            f"rule={getattr(finding, 'rule', None)} "
            f"conf={getattr(finding, 'confidence', None)} "
            f"action={result.action.value}"
        )
        if ok:
            passed += 1
        else:
            failed += 1
        _run_case(row["case_id"], ok, detail)

    return passed, failed


def run_control_regression_suite(control_path: str) -> tuple[int, int]:
    passed = failed = 0

    print(f"\n{Y}▶ Phase 1 제어/롤백 회귀 테스트{W}")

    phone_result = run_regex_pipeline([
        DLPTarget("messages[0].content", "user", "제 전화번호는 010-1234-5678입니다."),
    ], control_path=control_path)
    phone_finding = phone_result.findings[0] if phone_result.findings else None
    ok = phone_finding is not None and phone_finding.rule == "kr_phone" and phone_finding.confidence >= 1.0
    failed += _run_case("C01", ok, f"kr_phone conf={getattr(phone_finding, 'confidence', None)}")
    passed += int(ok)

    passport_plain = _single_finding("M12345678", control_path)
    ok = passport_plain is not None and abs(passport_plain.confidence - 0.4) < 1e-9
    failed += _run_case("C02", ok, f"kr_passport plain conf={getattr(passport_plain, 'confidence', None)}")
    passed += int(ok)

    passport_code = _single_finding("const sample = M12345678; return sample;", control_path)
    ok = passport_code is not None and abs(passport_code.confidence - 0.12) < 1e-9 and passport_code.metadata.get("code_context") is True
    failed += _run_case("C03", ok, f"kr_passport code conf={getattr(passport_code, 'confidence', None)} code={getattr(passport_code, 'metadata', {}).get('code_context')}")
    passed += int(ok)

    rrn_code = _single_finding("def parse_rrn(): return '880515-1104333'", control_path)
    ok = rrn_code is not None and abs(rrn_code.confidence - 0.8) < 1e-9
    failed += _run_case("C04", ok, f"kr_rrn floor conf={getattr(rrn_code, 'confidence', None)}")
    passed += int(ok)

    _write_control(control_path, {
        "confidence_threshold": 0.5,
        "context_penalty_enabled": False,
        "allowlist": [],
        "disabled_rules": [],
    })
    passport_no_penalty = _single_finding("const sample = M12345678; return sample;", control_path)
    ok = passport_no_penalty is not None and abs(passport_no_penalty.confidence - 1.0) < 1e-9
    failed += _run_case("C05", ok, f"penalty-off conf={getattr(passport_no_penalty, 'confidence', None)}")
    passed += int(ok)

    _write_control(control_path, {
        "confidence_threshold": 0.5,
        "context_penalty_enabled": True,
        "allowlist": [{"rule": "kr_phone", "value": "010-1234-5678", "normalized": "01012345678"}],
        "disabled_rules": [],
    })
    allowlisted = _single_finding("제 전화번호는 010 1234 5678 입니다.", control_path)
    ok = allowlisted is not None and allowlisted.suppressed is True
    failed += _run_case("C06", ok, f"allowlisted suppressed={getattr(allowlisted, 'suppressed', None)}")
    passed += int(ok)

    # C07, C08 (password_assignment) — 프로덕션에 없는 프로토 전용 룰이므로 제거됨

    _write_control(control_path, {
        "confidence_threshold": 0.5,
        "context_penalty_enabled": True,
        "allowlist": [],
        "disabled_rules": [],
    })

    weak_signal_text = "Please return this document 010-1234-5678"
    weak_signal = _single_finding(weak_signal_text, control_path)
    ok = weak_signal is not None and weak_signal.metadata.get("code_context") is False
    failed += _run_case("C09", ok, f"weak-signal code={getattr(weak_signal, 'metadata', {}).get('code_context')}")
    passed += int(ok)

    unknown_multiplier = _context_multiplier("unknown_rule", "", "")
    ok = abs(unknown_multiplier - 0.7) < 1e-9
    failed += _run_case("C10", ok, f"unknown multiplier={unknown_multiplier}")
    passed += int(ok)

    # C11 (password_assignment) — 프로덕션에 없는 프로토 전용 룰이므로 제거됨

    return passed, failed


def main() -> int:
    """
    기본 실행: 제어/롤백 회귀 테스트 (C01-C10) 만 실행.
    --csv 플래그 지정 시 프로토 CSV 스위트 추가 실행
    (CSV 기대값은 프로토 키워드 세트 기준이므로 프로덕션과 차이가 있을 수 있음).
    """
    run_csv = "--csv" in sys.argv
    total_passed = 0
    total_failed = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        control_path = str(Path(tmpdir) / "dlp-control.json")
        _write_control(control_path, {
            "confidence_threshold": 0.5,
            "context_penalty_enabled": True,
            "allowlist": [],
            "disabled_rules": [],
        })

        if run_csv:
            passed, failed = _run_positive_suite(
                control_path,
                "proto_phase1_true_positive.csv",
                "Phase 1 정탐(True Positive) 테스트",
            )
            total_passed += passed
            total_failed += failed

            passed, failed = _run_negative_suite(
                control_path,
                "proto_phase1_false_positive.csv",
                "Phase 1 오탐(False Positive) 억제 테스트",
            )
            total_passed += passed
            total_failed += failed

            passed, failed = _run_positive_suite(
                control_path,
                "proto_phase1_realistic_true_positive.csv",
                "Phase 1 현실형 정탐 테스트",
            )
            total_passed += passed
            total_failed += failed

            passed, failed = _run_negative_suite(
                control_path,
                "proto_phase1_realistic_false_positive.csv",
                "Phase 1 현실형 과탐 억제 테스트",
            )
            total_passed += passed
            total_failed += failed

            passed, failed = _run_positive_suite(
                control_path,
                "proto_phase1_false_negative_risk.csv",
                "Phase 1 미탐 위험(False Negative Risk) 테스트",
            )
            total_passed += passed
            total_failed += failed

            passed, failed = _run_negative_suite(
                control_path,
                "proto_phase1_over_detection_risk.csv",
                "Phase 1 과탐 위험(Over-detection Risk) 테스트",
            )
            total_passed += passed
            total_failed += failed

        passed, failed = run_control_regression_suite(control_path)
        total_passed += passed
        total_failed += failed

    print(f"\n{'=' * 72}")
    print(f"Phase 1 결과: {total_passed} passed, {total_failed} failed")
    print(f"{'=' * 72}")

    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())