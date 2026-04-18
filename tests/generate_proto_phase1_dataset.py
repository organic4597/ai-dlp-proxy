#!/usr/bin/env python3
"""
Phase 1 regex 프로토타입용 데이터셋 생성기.

- 기본 정탐(True Positive) 150건
- 기본 오탐 억제(False Positive) 150건
- 현실형 정탐(True Positive) 150건
- 현실형 오탐 억제(False Positive) 150건
- 미탐 위험(False Negative Risk) 48건
- 과탐 위험(Over-detection Risk) 48건

출력 파일:
- tests/proto_phase1_true_positive.csv
- tests/proto_phase1_false_positive.csv
- tests/proto_phase1_realistic_true_positive.csv
- tests/proto_phase1_realistic_false_positive.csv
- tests/proto_phase1_false_negative_risk.csv
- tests/proto_phase1_over_detection_risk.csv
"""
from __future__ import annotations

import csv
from pathlib import Path


HERE = Path(__file__).resolve().parent
TP_PATH = HERE / "proto_phase1_true_positive.csv"
FP_PATH = HERE / "proto_phase1_false_positive.csv"
RTP_PATH = HERE / "proto_phase1_realistic_true_positive.csv"
RFP_PATH = HERE / "proto_phase1_realistic_false_positive.csv"
FNR_PATH = HERE / "proto_phase1_false_negative_risk.csv"
ODR_PATH = HERE / "proto_phase1_over_detection_risk.csv"

POSITIVE_FIELDS = ["case_id", "category", "input_text", "expected_rule", "min_confidence", "expected_action", "notes"]
NEGATIVE_FIELDS = ["case_id", "category", "input_text", "expected_rule", "max_confidence", "expected_action", "notes"]


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _next_case_index(rows: list[dict[str, str]], prefix: str) -> int:
    return sum(1 for row in rows if row["case_id"].startswith(f"{prefix}-")) + 1


def _append_positive_rows(
    rows: list[dict[str, str]],
    *,
    prefix: str,
    category: str,
    templates: list[str],
    values: list[str],
    expected_rule: str,
    min_confidence: str,
    expected_action: str,
    notes: str,
    keys: list[str] | None = None,
    total: int | None = None,
) -> None:
    count = total or (len(templates) * len(values))
    start = _next_case_index(rows, prefix)
    for offset in range(count):
        payload = {"value": values[offset % len(values)]}
        if keys:
            payload["key"] = keys[offset % len(keys)]
        rows.append({
            "case_id": f"{prefix}-{start + offset:03d}",
            "category": category,
            "input_text": templates[offset % len(templates)].format(**payload),
            "expected_rule": expected_rule,
            "min_confidence": min_confidence,
            "expected_action": expected_action,
            "notes": notes,
        })


def _append_negative_rows(
    rows: list[dict[str, str]],
    *,
    prefix: str,
    category: str,
    templates: list[str],
    values: list[str],
    expected_rule: str,
    max_confidence: str,
    expected_action: str,
    notes: str,
    keys: list[str] | None = None,
    total: int | None = None,
) -> None:
    count = total or (len(templates) * len(values))
    start = _next_case_index(rows, prefix)
    for offset in range(count):
        payload = {"value": values[offset % len(values)]}
        if keys:
            payload["key"] = keys[offset % len(keys)]
        rows.append({
            "case_id": f"{prefix}-{start + offset:03d}",
            "category": category,
            "input_text": templates[offset % len(templates)].format(**payload),
            "expected_rule": expected_rule,
            "max_confidence": max_confidence,
            "expected_action": expected_action,
            "notes": notes,
        })


def _append_positive_inputs(
    rows: list[dict[str, str]],
    *,
    prefix: str,
    category: str,
    inputs: list[str],
    expected_rule: str,
    min_confidence: str,
    expected_action: str,
    notes: str,
) -> None:
    start = _next_case_index(rows, prefix)
    for offset, input_text in enumerate(inputs):
        rows.append({
            "case_id": f"{prefix}-{start + offset:03d}",
            "category": category,
            "input_text": input_text,
            "expected_rule": expected_rule,
            "min_confidence": min_confidence,
            "expected_action": expected_action,
            "notes": notes,
        })


def _append_negative_inputs(
    rows: list[dict[str, str]],
    *,
    prefix: str,
    category: str,
    inputs: list[str],
    expected_rule: str,
    max_confidence: str,
    expected_action: str,
    notes: str,
) -> None:
    start = _next_case_index(rows, prefix)
    for offset, input_text in enumerate(inputs):
        rows.append({
            "case_id": f"{prefix}-{start + offset:03d}",
            "category": category,
            "input_text": input_text,
            "expected_rule": expected_rule,
            "max_confidence": max_confidence,
            "expected_action": expected_action,
            "notes": notes,
        })


def generate_true_positive_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_positive_rows(
        rows,
        prefix="TP-RRN",
        category="kr_rrn",
        values=["880515-1104333", "950720-2218199", "000301-3600132", "751103-1389080", "010614-4542353"],
        templates=[
            "주민 등록 본인확인 번호는 {value} 입니다.",
            "본인확인용 주민 등록 값: {value}",
            "resident identification birth data: {value}",
        ],
        expected_rule="kr_rrn",
        min_confidence="0.8",
        expected_action="mask",
        notes="체크섬 통과 + 주민등록 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-CARD",
        category="credit_card",
        values=["4539-1488-0343-6467", "5425-2334-3010-9903", "6011-0009-9013-9424", "4532015112830366", "4556737586899855"],
        templates=[
            "카드 결제 승인 번호는 {value} 입니다.",
            "payment credit billing card = {value}",
            "신용 카드 명세 값: {value}",
        ],
        expected_rule="credit_card",
        min_confidence="0.6",
        expected_action="mask",
        notes="Luhn 통과 + 카드 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-PHONE",
        category="kr_phone",
        values=["010-1234-5678", "010.9876.5432", "01055557777", "011-223-7788", "019-9999-1234"],
        templates=[
            "연락 전화번호는 {value} 입니다.",
            "phone contact call: {value}",
            "핸드폰 연락처 {value}",
        ],
        expected_rule="kr_phone",
        min_confidence="1.0",
        expected_action="alert",
        notes="전화 관련 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-EMAIL",
        category="email",
        values=["security@example.com", "ops-team@company.co.kr", "alice.bob@internal.org", "notify@service.io", "contact@support.dev"],
        templates=[
            "연락처 이메일은 {value} 입니다.",
            "mail inbox recipient: {value}",
        ],
        expected_rule="email",
        min_confidence="1.0",
        expected_action="alert",
        notes="이메일 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-PASS",
        category="kr_passport",
        values=["M12345678", "AB1234567", "MA9876543", "K76543210", "P12345678"],
        templates=[
            "여권 출국 비자 번호는 {value} 입니다.",
            "passport departure visa: {value}",
        ],
        expected_rule="kr_passport",
        min_confidence="1.0",
        expected_action="alert",
        notes="여권 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-LIC",
        category="kr_driver_license",
        values=["11-23-456789-01", "12-34-567890-12", "13-45-678901-23", "26-12-345678-90", "28-98-765432-10"],
        templates=[
            "운전 면허 발급 번호는 {value} 입니다.",
            "driving license police issue: {value}",
        ],
        expected_rule="kr_driver_license",
        min_confidence="1.0",
        expected_action="alert",
        notes="운전면허 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-AWS",
        category="aws_access_key",
        values=["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE", "ABIAIOSFODNN7EXAMPLE", "ACCAIOSFODNN7EXAMPLE", "AKIA1234567890ABCD12"],
        templates=[
            "클라우드 인프라 계정 키는 {value} 입니다.",
            "cloud deploy infra account key: {value}",
            "배포용 클라우드 계정 값 {value}",
        ],
        expected_rule="aws_access_key",
        min_confidence="1.0",
        expected_action="mask",
        notes="AWS 키 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-API",
        category="api_key_assignment",
        values=[
            "sk-proj-abcdef1234567890ABCDEFGHIJ",
            "ghijklmnopqrstuvwxyz0123456789ABCD",
            "tok_1234567890ABCDEFghijklmnop",
            "svcKEY_000011112222333344445555",
            "private_token_abcdefghijklmnop1234",
        ],
        keys=["api_key", "secret_key", "access_token", "auth_token", "private_key"],
        templates=[
            "외부 서비스키로 발급받은 값: {key} = {value}",
            "issued external integration {key}={value}",
            "연동용 서비스키 {key}: {value}",
        ],
        expected_rule="api_key_assignment",
        min_confidence="1.0",
        expected_action="alert",
        notes="API 키 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-PWD",
        category="password_assignment",
        values=["S3curePassw0rd!", "ProdLogin123!", "VaultSecret777$", "UserPass_2026!", "AdminPwd#4455"],
        keys=["password", "passwd", "pwd", "db_password", "login_password"],
        templates=[
            "로그인 credential {key} = {value}",
            "비밀번호 인증용 {key}: {value}",
            "password signin credential {key}={value}",
        ],
        expected_rule="password_assignment",
        min_confidence="0.49",
        expected_action="pass",
        notes="패스워드 candidate 추출",
    )
    _append_positive_rows(
        rows,
        prefix="TP-PEM",
        category="pem_private_key",
        values=[
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd",
            "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345",
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE",
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011",
            "MIICXAIBAAKBgQCexamplepayloadforpemprivatekey0123456789ABCDEFGHIJKLMNOP",
        ],
        templates=[
            "인증서 발급에 필요한 키입니다:\n-----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----",
            "ssl certificate renew private key:\n-----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----",
        ],
        expected_rule="pem_private_key",
        min_confidence="1.0",
        expected_action="mask",
        notes="PEM private key 블록",
    )
    _append_positive_rows(
        rows,
        prefix="TP-JWT",
        category="jwt_token",
        values=[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde",
            "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER",
            "eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210qwer",
            "eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF",
        ],
        templates=[
            "로그인 세션 bearer 토큰은 {value} 입니다.",
            "login session auth bearer: {value}",
        ],
        expected_rule="jwt_token",
        min_confidence="1.0",
        expected_action="alert",
        notes="JWT 문맥",
    )
    _append_positive_rows(
        rows,
        prefix="TP-GH",
        category="github_pat",
        values=[
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh",
            "ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab",
            "ghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890",
            "ghr_MmNnBbVvCcXxZzLlKkJjHhGgFfDdSsAa001122",
        ],
        templates=[
            "github repo push 용 토큰은 {value} 입니다.",
            "commit push repo github token: {value}",
        ],
        expected_rule="github_pat",
        min_confidence="1.0",
        expected_action="mask",
        notes="GitHub 토큰 문맥",
    )

    assert len(rows) == 150, len(rows)
    return rows


def generate_false_positive_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_negative_rows(rows, prefix="FP-PASS", category="kr_passport", values=["M12345678", "AB1234567", "MA9876543", "K76543210", "P12345678"], templates=["{value}", "const sample = {value}; return sample;"], expected_rule="kr_passport", max_confidence="0.4", expected_action="pass", notes="문맥 없음 또는 코드 문맥에서 threshold 미만", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-PASS-") and row["input_text"].startswith("const sample"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="FP-LIC", category="kr_driver_license", values=["11-23-456789-01", "12-34-567890-12", "13-45-678901-23", "26-12-345678-90", "28-98-765432-10"], templates=["const code = '{value}'; return code;", "{value}"], expected_rule="kr_driver_license", max_confidence="0.4", expected_action="pass", notes="코드 상수 또는 문맥 없는 관리코드", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-LIC-") and row["input_text"].startswith("const code"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="FP-PHONE", category="kr_phone", values=["01012345678", "010-1234-5678", "01122334455", "018.5555.7777", "019-9999-1234"], templates=["const port = '{value}'; return port;", "socket_port={value}"], expected_rule="kr_phone", max_confidence="0.4", expected_action="pass", notes="코드/식별자 숫자열", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-PHONE-") and row["input_text"].startswith("const port"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="FP-EMAIL", category="email", values=["test@example.com", "demo@internal.org", "sample@service.io", "user@local.dev", "person@dummy.net"], templates=["const user = '{value}'; return user;", "{value}"], expected_rule="email", max_confidence="0.4", expected_action="pass", notes="예제 이메일 상수", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-EMAIL-") and row["input_text"].startswith("const user"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="FP-AWS", category="aws_access_key", values=["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE", "ABIAIOSFODNN7EXAMPLE", "ACCAIOSFODNN7EXAMPLE", "AKIA1234567890ABCD12"], templates=["import boto3\nconst awsKey = '{value}';", "{value}"], expected_rule="aws_access_key", max_confidence="0.4", expected_action="pass", notes="코드 예제 또는 문맥 없는 키 모양 문자열", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-AWS-") and row["input_text"].startswith("import boto3"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="FP-API", category="api_key_assignment", values=["generated_token_value_1234567890", "placeholder_secret_ABCDEF123456", "tmp_auth_token_9876543210", "dev_private_key_1234567890ab", "runtime_access_token_4455667788"], keys=["api_key", "secret_key", "access_token", "auth_token", "private_key"], templates=["import hashlib\n{key} = {value}"], expected_rule="api_key_assignment", max_confidence="0.12", expected_action="pass", notes="설정 코드 할당문 오탐 억제", total=15)

    _append_negative_rows(rows, prefix="FP-PWD", category="password_assignment", values=["process.env.DB_PASSWORD", "${VAULT_SECRET_DB_PASS}", "PASSWORD_HINT_TEXT", "old_password_hash_value", "settings.default_password"], keys=["db_password", "password", "passwd", "pwd", "reset_password_url"], templates=["const {key} = {value}; return {key};", "{key}={value}"], expected_rule="password_assignment", max_confidence="0.4", expected_action="pass", notes="참조값/힌트/해시 필드 오탐 억제", total=15)
    for row in rows:
        if row["case_id"].startswith("FP-PWD-") and "return" in row["input_text"]:
            row["max_confidence"] = "0.3"

    _append_negative_rows(rows, prefix="FP-PEM", category="pem_private_key", values=["MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd", "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345", "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011", "MIICXAIBAAKBgQCexamplepayloadforpemprivatekey0123456789ABCDEFGHIJKLMNOP"], templates=["def get_key():\n    return '''-----BEGIN RSA PRIVATE KEY-----\\n{value}\\n-----END RSA PRIVATE KEY-----'''"], expected_rule="pem_private_key", max_confidence="0.12", expected_action="pass", notes="코드 내 PEM 예제", total=15)

    _append_negative_rows(rows, prefix="FP-JWT", category="jwt_token", values=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde", "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER", "eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210qwer", "eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF"], templates=["const token = '{value}'; return token;"], expected_rule="jwt_token", max_confidence="0.12", expected_action="pass", notes="코드 예제 JWT", total=15)

    _append_negative_rows(rows, prefix="FP-GH", category="github_pat", values=["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh", "ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "ghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890", "ghr_MmNnBbVvCcXxZzLlKkJjHhGgFfDdSsAa001122"], templates=["const demo = '{value}'; return demo;"], expected_rule="github_pat", max_confidence="0.12", expected_action="pass", notes="코드 예제 GitHub 토큰", total=15)

    assert len(rows) == 150, len(rows)
    return rows


def generate_realistic_true_positive_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_positive_rows(rows, prefix="RTP-RRN", category="kr_rrn", values=["880515-1104333", "950720-2218199", "000301-3600132", "751103-1389080"], templates=["customer onboarding\nresident_registration_number: \"{value}\"", "member_rrn={value}\nidentification completed=true", "본인확인 신청서\n주민등록번호 {value}"], expected_rule="kr_rrn", min_confidence="0.8", expected_action="mask", notes="현실형 JSON/YAML/설문 문맥")

    _append_positive_rows(rows, prefix="RTP-CARD", category="credit_card", values=["4539-1488-0343-6467", "5425-2334-3010-9903", "6011-0009-9013-9424", "4556737586899855"], templates=["payment request\ncard_number: \"{value}\"", "billing.card={value}\npayment_status=pending", "신용카드 결제 정보\n승인 대상 카드 {value}"], expected_rule="credit_card", min_confidence="0.6", expected_action="mask", notes="결제/청구 문맥")

    _append_positive_rows(rows, prefix="RTP-PHONE", category="kr_phone", values=["010-1234-5678", "01098765432", "011-223-7788", "019.9999.1234"], templates=["contact profile\nphone: \"{value}\"", "SMS_TO={value}\nmobile verified=true", "긴급 연락처\n핸드폰 번호 {value}"], expected_rule="kr_phone", min_confidence="1.0", expected_action="alert", notes="연락처/문자 발송 문맥")

    _append_positive_rows(rows, prefix="RTP-EMAIL", category="email", values=["notify+security@example.com", "alerts@corp.internal", "billing-team@service.io", "owner@support.dev"], templates=["recipient_email={value}\nsend_enabled=true", "notification:\n  email: \"{value}\"", "mail inbox routing target {value}"], expected_rule="email", min_confidence="1.0", expected_action="alert", notes="알림/수신자 문맥")

    _append_positive_rows(rows, prefix="RTP-PASS", category="kr_passport", values=["M12345678", "AB1234567", "MA9876543", "P12345678"], templates=["traveler profile\npassport_number: \"{value}\"", "passportNo={value}\nvisa_check=required", "출입국 신청서\n여권 번호 {value}"], expected_rule="kr_passport", min_confidence="1.0", expected_action="alert", notes="여권/비자 문맥")

    _append_positive_rows(rows, prefix="RTP-LIC", category="kr_driver_license", values=["11-23-456789-01", "12-34-567890-12", "26-12-345678-90", "28-98-765432-10"], templates=["driver_profile\nlicense_number: \"{value}\"", "driving_license={value}\npolice_check=true", "운전면허 발급 정보\n면허 번호 {value}"], expected_rule="kr_driver_license", min_confidence="1.0", expected_action="alert", notes="면허/발급 문맥")

    _append_positive_rows(rows, prefix="RTP-AWS", category="aws_access_key", values=["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE", "ABIAIOSFODNN7EXAMPLE", "ACCAIOSFODNN7EXAMPLE"], templates=["cloud deploy credential\nAWS_ACCESS_KEY_ID={value}", "infra account bootstrap\nAWS_ACCESS_KEY_ID: \"{value}\"", "배포용 클라우드 계정 키\nexport AWS_ACCESS_KEY_ID={value}"], expected_rule="aws_access_key", min_confidence="1.0", expected_action="mask", notes="Docker/.env/배포 문맥")

    _append_positive_rows(rows, prefix="RTP-API", category="api_key_assignment", values=["sk-proj-abcdef1234567890ABCDEFGHIJ", "tok_1234567890ABCDEFghijklmnop", "svcKEY_000011112222333344445555", "private_token_abcdefghijklmnop1234"], keys=["API_KEY", "secret_key", "access_token", "auth_token"], templates=["external integration credential\n{key}={value}", "issued service key\n{key}: \"{value}\"", "연동용 서비스키\n\"{key}\": \"{value}\""], expected_rule="api_key_assignment", min_confidence="1.0", expected_action="alert", notes=".env/Compose/YAML 실전 문맥")

    _append_positive_rows(rows, prefix="RTP-PWD", category="password_assignment", values=["ProdLogin!2026", "Migrate#Pass88", "Vault!Gate77", "Admin?Panel55", "Svc*Auth44", "Batch%Job33"], keys=["DB_PASSWORD", "MYSQL_PASSWORD", "SPRING_DATASOURCE_PASSWORD", "LOGIN_PASSWORD", "PW", "APP_PASSPHRASE"], templates=[".env\n{key}={value}", "services:\n  api:\n    environment:\n      {key}: \"{value}\"", "apiVersion: v1\nkind: Secret\nstringData:\n  {key}: {value}"], expected_rule="password_assignment", min_confidence="0.49", expected_action="pass", notes="dotenv/Docker Compose/Kubernetes Secret 후보 추출")

    _append_positive_rows(rows, prefix="RTP-PEM", category="pem_private_key", values=["MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd", "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345", "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011"], templates=["certificate renew private key\n-----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----", "apiVersion: v1\nkind: Secret\nstringData:\n  tls.key: |\n    -----BEGIN RSA PRIVATE KEY-----\n    {value}\n    -----END RSA PRIVATE KEY-----", "ssl private key block\n-----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----"], expected_rule="pem_private_key", min_confidence="1.0", expected_action="mask", notes="Kubernetes Secret/TLS 문맥")

    _append_positive_rows(rows, prefix="RTP-JWT", category="jwt_token", values=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde", "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER", "eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF"], templates=["Authorization: Bearer {value}", "login session\nauth_token={value}", "headers:\n  Authorization: \"Bearer {value}\""], expected_rule="jwt_token", min_confidence="1.0", expected_action="alert", notes="Bearer/Auth 헤더 문맥")

    _append_positive_rows(rows, prefix="RTP-GH", category="github_pat", values=["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh", "ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "ghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890"], templates=["github repo push token\nGITHUB_PAT={value}", "commit push automation\nGH_TOKEN: \"{value}\"", "깃허브 리포 배포 토큰\nexport GITHUB_PAT={value}"], expected_rule="github_pat", min_confidence="1.0", expected_action="mask", notes="GitHub Actions/CLI 문맥")

    assert len(rows) == 150, len(rows)
    return rows


def generate_realistic_false_positive_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_negative_rows(rows, prefix="RFP-RRN", category="kr_rrn", values=["880515-1104333", "950720-2218199", "000301-3600132", "751103-1389080"], templates=["const fixtureResidentNo = \"{value}\"; return fixtureResidentNo;", "schema.example.rrn={value}", "README sample resident number {value}"], expected_rule="kr_rrn", max_confidence="0.4", expected_action="pass", notes="샘플 데이터/문서 문맥")
    for row in rows:
        if row["case_id"].startswith("RFP-RRN-") and row["input_text"].startswith("const fixtureResidentNo"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-CARD", category="credit_card", values=["4539-1488-0343-6467", "5425-2334-3010-9903", "6011-0009-9013-9424", "4556737586899855"], templates=["const demoCard = \"{value}\"; return demoCard;", "docs.example.card={value}", "sample card number {value}"], expected_rule="credit_card", max_confidence="0.4", expected_action="pass", notes="문서/데모 카드번호")
    for row in rows:
        if row["case_id"].startswith("RFP-CARD-") and row["input_text"].startswith("const demoCard"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-PHONE", category="kr_phone", values=["010-1234-5678", "01098765432", "011-223-7788", "019.9999.1234"], templates=["const samplePhone = \"{value}\"; return samplePhone;", "docs.phone.example={value}", "placeholder contact number {value}"], expected_rule="kr_phone", max_confidence="0.4", expected_action="pass", notes="문서/테스트 fixture 번호")
    for row in rows:
        if row["case_id"].startswith("RFP-PHONE-") and row["input_text"].startswith("const samplePhone"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-EMAIL", category="email", values=["notify@example.com", "demo@corp.internal", "billing@service.io", "owner@support.dev"], templates=["const sampleEmail = \"{value}\"; return sampleEmail;", "docs.recipient.example={value}", "placeholder recipient {value}"], expected_rule="email", max_confidence="0.4", expected_action="pass", notes="예제 수신자 이메일")
    for row in rows:
        if row["case_id"].startswith("RFP-EMAIL-") and row["input_text"].startswith("const sampleEmail"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-PASS", category="kr_passport", values=["M12345678", "AB1234567", "MA9876543", "P12345678"], templates=["const passportExample = \"{value}\"; return passportExample;", "sample.passport.no={value}", "README passport example {value}"], expected_rule="kr_passport", max_confidence="0.4", expected_action="pass", notes="예제 여권번호")
    for row in rows:
        if row["case_id"].startswith("RFP-PASS-") and row["input_text"].startswith("const passportExample"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-LIC", category="kr_driver_license", values=["11-23-456789-01", "12-34-567890-12", "26-12-345678-90", "28-98-765432-10"], templates=["const licenseExample = \"{value}\"; return licenseExample;", "sample.license.no={value}", "README driver license example {value}"], expected_rule="kr_driver_license", max_confidence="0.4", expected_action="pass", notes="예제 면허번호")
    for row in rows:
        if row["case_id"].startswith("RFP-LIC-") and row["input_text"].startswith("const licenseExample"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-AWS", category="aws_access_key", values=["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE", "ABIAIOSFODNN7EXAMPLE", "ACCAIOSFODNN7EXAMPLE"], templates=["const demoAwsKey = \"{value}\"; return demoAwsKey;", "docs.example.aws_key={value}", "sample aws key {value}"], expected_rule="aws_access_key", max_confidence="0.4", expected_action="pass", notes="예제 AWS 키 문자열")
    for row in rows:
        if row["case_id"].startswith("RFP-AWS-") and row["input_text"].startswith("const demoAwsKey"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-API", category="api_key_assignment", values=["process.env.SERVICE_API_KEY", "process.env.SECRET_KEY_REF", "runtime_access_token_ref_445566", "generated_private_key_ref_778899"], keys=["API_KEY", "secret_key", "access_token", "auth_token"], templates=["import os\n{key}={value}", "service config\n{key}: {value}", "reference only\n\"{key}\": \"{value}\""], expected_rule="api_key_assignment", max_confidence="0.4", expected_action="pass", notes="실제 비밀값이 아닌 참조/런타임 값")
    for row in rows:
        if row["case_id"].startswith("RFP-API-") and row["input_text"].startswith("import os"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-PWD", category="password_assignment", values=["${DB_PASSWORD}", "process.env.DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", "$DB_PASSWORD", "{{ .Values.dbPassword }}", "${MYSQL_PASSWORD:-changeme}"], keys=["DB_PASSWORD", "MYSQL_PASSWORD", "SPRING_DATASOURCE_PASSWORD", "LOGIN_PASSWORD", "PW", "APP_PASSPHRASE"], templates=[".env\n{key}={value}", "services:\n  api:\n    environment:\n      {key}: \"{value}\"", "env:\n  {key}: {value}"], expected_rule="password_assignment", max_confidence="0.4", expected_action="pass", notes="GitHub Actions/Docker/.env 비밀 참조값", total=18)
    for row in rows:
        if row["case_id"].startswith("RFP-PWD-") and "process.env" in row["input_text"]:
            row["max_confidence"] = "0.3"

    _append_negative_rows(rows, prefix="RFP-PEM", category="pem_private_key", values=["MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd", "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345", "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011"], templates=["def load_key():\n    return '''-----BEGIN RSA PRIVATE KEY-----\\n{value}\\n-----END RSA PRIVATE KEY-----'''", "example tls key\n-----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----", "README snippet -> -----BEGIN RSA PRIVATE KEY-----\n{value}\n-----END RSA PRIVATE KEY-----"], expected_rule="pem_private_key", max_confidence="0.4", expected_action="pass", notes="문서/코드 예제 PEM")
    for row in rows:
        if row["case_id"].startswith("RFP-PEM-") and row["input_text"].startswith("def load_key"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-JWT", category="jwt_token", values=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde", "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER", "eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF"], templates=["const jwtExample = '{value}'; return jwtExample;", "docs.example.jwt={value}", "sample bearer token {value}"], expected_rule="jwt_token", max_confidence="0.4", expected_action="pass", notes="문서/샘플 JWT")
    for row in rows:
        if row["case_id"].startswith("RFP-JWT-") and row["input_text"].startswith("const jwtExample"):
            row["max_confidence"] = "0.12"

    _append_negative_rows(rows, prefix="RFP-GH", category="github_pat", values=["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh", "ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "ghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890"], templates=["const githubPatExample = '{value}'; return githubPatExample;", "docs.example.gh_pat={value}", "sample personal token {value}"], expected_rule="github_pat", max_confidence="0.4", expected_action="pass", notes="문서/예제 GitHub PAT")
    for row in rows:
        if row["case_id"].startswith("RFP-GH-") and row["input_text"].startswith("const githubPatExample"):
            row["max_confidence"] = "0.12"

    assert len(rows) == 150, len(rows)
    return rows


def generate_false_negative_risk_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_positive_inputs(rows, prefix="FNR-RRN", category="kr_rrn", inputs=["\"rrn\":\"880515-1104333\"", "residentNo = \"9507202218199\"", "주민등록번호:\"000301-3600132\"", "applicant_rrn=7511031389080"], expected_rule="kr_rrn", min_confidence="0.8", expected_action="mask", notes="JSON/속성/무구분자 주민번호")
    _append_positive_inputs(rows, prefix="FNR-CARD", category="credit_card", inputs=["\"card_number\":\"4539-1488-0343-6467\"", "payment_card = \"5425233430109903\"", "billing.card: 6011 0009 9013 9424", "checkout_pan=4556737586899855"], expected_rule="credit_card", min_confidence="0.6", expected_action="mask", notes="JSON/공백 구분 카드번호")
    _append_positive_inputs(rows, prefix="FNR-PHONE", category="kr_phone", inputs=["\"phone\":\"010-1234-5678\"", "primary_phone=\"01098765432\"", "contact.mobile: 011-223-7788", "SMS_TO=019.9999.1234"], expected_rule="kr_phone", min_confidence="1.0", expected_action="alert", notes="JSON/YAML/평문 연락처")
    _append_positive_inputs(rows, prefix="FNR-EMAIL", category="email", inputs=["\"recipient_email\":\"notify+ops@example.com\"", "owner_email=alerts@corp.internal", "mail to billing-team@service.io", "recipient: contact@support.dev"], expected_rule="email", min_confidence="1.0", expected_action="alert", notes="plus-tag/subdomain 이메일")
    _append_positive_inputs(rows, prefix="FNR-PASS", category="kr_passport", inputs=["\"passport_number\":\"M12345678\"", "passportNo=AB1234567", "travel_doc = \"MA9876543\"", "여권번호: P12345678"], expected_rule="kr_passport", min_confidence="1.0", expected_action="alert", notes="JSON/YAML/한글 라벨 여권")
    _append_positive_inputs(rows, prefix="FNR-LIC", category="kr_driver_license", inputs=["\"driver_license\":\"11-23-456789-01\"", "license_no=12-34-567890-12", "면허번호: 26-12-345678-90", "license: \"28-98-765432-10\""], expected_rule="kr_driver_license", min_confidence="1.0", expected_action="alert", notes="속성/문서 라벨 면허번호")
    _append_positive_inputs(rows, prefix="FNR-AWS", category="aws_access_key", inputs=["cloud deploy credential\nAWS_ACCESS_KEY_ID=\"AKIAIOSFODNN7EXAMPLE\"", "infra account bootstrap\nAWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE", "클라우드 계정 키\nABIAIOSFODNN7EXAMPLE", "deploy account key\nACCAIOSFODNN7EXAMPLE"], expected_rule="aws_access_key", min_confidence="1.0", expected_action="mask", notes="배포/클라우드 문맥의 AWS 키")
    _append_positive_inputs(rows, prefix="FNR-API", category="api_key_assignment", inputs=["external integration\n\"API_KEY\":\"sk-proj-abcdef1234567890ABCDEFGHIJ\"", "issued service key\nsecret_key = tok_1234567890ABCDEFghijklmnop", "연동용 서비스키\nauth_token:\"svcKEY_000011112222333344445555\"", "external issued credential\nprivate_key=private_token_abcdefghijklmnop1234"], expected_rule="api_key_assignment", min_confidence="1.0", expected_action="alert", notes="JSON/속성 형태 API 키")
    _append_positive_inputs(rows, prefix="FNR-PWD", category="password_assignment", inputs=["pw: \"Alpha!234\"", "\"password\":\"Beta#5678\"", "'db_password' : 'Gamma$9012'", "passphrase=Delta^3456"], expected_rule="password_assignment", min_confidence="0.49", expected_action="pass", notes="라벨 포함 패스워드 candidate 추출")
    _append_positive_inputs(rows, prefix="FNR-PEM", category="pem_private_key", inputs=["certificate renew\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd\n-----END RSA PRIVATE KEY-----", "stringData:\n  tls.key: |\n    -----BEGIN RSA PRIVATE KEY-----\n    MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345\n    -----END RSA PRIVATE KEY-----", "ssl private key\n-----BEGIN RSA PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE\n-----END RSA PRIVATE KEY-----", "private key block\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011\n-----END RSA PRIVATE KEY-----"], expected_rule="pem_private_key", min_confidence="1.0", expected_action="mask", notes="들여쓰기/멀티라인 PEM 블록")
    _append_positive_inputs(rows, prefix="FNR-JWT", category="jwt_token", inputs=["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "auth_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde", "login session\nbearer eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER", "headers: Authorization=Bearer eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF"], expected_rule="jwt_token", min_confidence="1.0", expected_action="alert", notes="Bearer 헤더/속성 JWT")
    _append_positive_inputs(rows, prefix="FNR-GH", category="github_pat", inputs=["github repo push token\nGITHUB_PAT=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "commit push automation\nGH_TOKEN=\"gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh\"", "repo secret\nexport GITHUB_PAT=ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "깃허브 푸시 토큰\nghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890"], expected_rule="github_pat", min_confidence="1.0", expected_action="mask", notes="env/export/GitHub token")

    assert len(rows) == 48, len(rows)
    return rows


def generate_over_detection_risk_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    _append_negative_inputs(rows, prefix="ODR-RRN", category="kr_rrn", inputs=["const rrnFixture = \"880515-1104333\"; return rrnFixture;", "schema.example.rrn=9507202218199", "sample resident no 000301-3600132", "README resident example 7511031389080"], expected_rule="kr_rrn", max_confidence="0.4", expected_action="pass", notes="예제/fixture 주민번호")
    _append_negative_inputs(rows, prefix="ODR-CARD", category="credit_card", inputs=["const sampleCard = \"4539-1488-0343-6467\"; return sampleCard;", "docs.example.card=5425233430109903", "test pan 6011 0009 9013 9424", "README example 4556737586899855"], expected_rule="credit_card", max_confidence="0.4", expected_action="pass", notes="문서/테스트 카드번호")
    _append_negative_inputs(rows, prefix="ODR-PHONE", category="kr_phone", inputs=["const samplePhone = \"010-1234-5678\"; return samplePhone;", "docs.phone.example=01098765432", "fixture mobile 011-223-7788", "placeholder number 019.9999.1234"], expected_rule="kr_phone", max_confidence="0.4", expected_action="pass", notes="문서/fixture 휴대전화")
    _append_negative_inputs(rows, prefix="ODR-EMAIL", category="email", inputs=["const sampleEmail = \"notify@example.com\"; return sampleEmail;", "docs.recipient.example=alerts@corp.internal", "fixture mailbox billing@service.io", "placeholder recipient owner@support.dev"], expected_rule="email", max_confidence="0.4", expected_action="pass", notes="문서/fixture 이메일")
    _append_negative_inputs(rows, prefix="ODR-PASS", category="kr_passport", inputs=["const passportExample = \"M12345678\"; return passportExample;", "sample.passport.no=AB1234567", "fixture travel doc MA9876543", "README passport example P12345678"], expected_rule="kr_passport", max_confidence="0.4", expected_action="pass", notes="예제 여권번호")
    _append_negative_inputs(rows, prefix="ODR-LIC", category="kr_driver_license", inputs=["const licenseExample = \"11-23-456789-01\"; return licenseExample;", "sample.license.no=12-34-567890-12", "fixture driving number 26-12-345678-90", "README license example 28-98-765432-10"], expected_rule="kr_driver_license", max_confidence="0.4", expected_action="pass", notes="예제 면허번호")
    _append_negative_inputs(rows, prefix="ODR-AWS", category="aws_access_key", inputs=["const demoAwsKey = \"AKIAIOSFODNN7EXAMPLE\"; return demoAwsKey;", "docs.example.aws_key=ASIAIOSFODNN7EXAMPLE", "fixture aws key ABIAIOSFODNN7EXAMPLE", "README sample ACCAIOSFODNN7EXAMPLE"], expected_rule="aws_access_key", max_confidence="0.4", expected_action="pass", notes="예제 AWS 키")
    _append_negative_inputs(rows, prefix="ODR-API", category="api_key_assignment", inputs=["import os\nAPI_KEY=process.env.SERVICE_API_KEY", "reference only\nsecret_key=process.env.SECRET_KEY_REF", "docs config\n\"access_token\":\"runtime_access_token_ref_445566\"", "template config\nauth_token=generated_private_key_ref_778899"], expected_rule="api_key_assignment", max_confidence="0.4", expected_action="pass", notes="런타임 참조/템플릿 API 키")
    _append_negative_inputs(rows, prefix="ODR-PWD", category="password_assignment", inputs=["DB_PASSWORD=${DB_PASSWORD}", "db_password=process.env.DB_PASSWORD", "password_hint=remember-me-next-time", "password: ${{ secrets.DB_PASSWORD }}"], expected_rule="password_assignment", max_confidence="0.4", expected_action="pass", notes="비밀값 참조/힌트/워크플로 표현식")
    _append_negative_inputs(rows, prefix="ODR-PEM", category="pem_private_key", inputs=["def load_key():\n    return '''-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd\\n-----END RSA PRIVATE KEY-----'''", "example tls key\n-----BEGIN RSA PRIVATE KEY-----\nMIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDVexampleabcdef12345\n-----END RSA PRIVATE KEY-----", "README snippet -> -----BEGIN RSA PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgexample9876543210ABCDE\n-----END RSA PRIVATE KEY-----", "fixture pem block\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfaketextpayload0011\n-----END RSA PRIVATE KEY-----"], expected_rule="pem_private_key", max_confidence="0.4", expected_action="pass", notes="문서/코드 예제 PEM")
    _append_negative_inputs(rows, prefix="ODR-JWT", category="jwt_token", inputs=["const jwtExample = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'; return jwtExample;", "docs.example.jwt=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2aWNlIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde", "sample bearer token eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJhcHAifQ.qwertyuiopasdfghjklzxcvbnm1234567890QWER", "fixture jwt eyJhbGciOiJIUzUxMiJ9.eyJzY29wZSI6ImFwaSJ9.poiuytrewqlkjhgfdsamnbvcxz1234567890ASDF"], expected_rule="jwt_token", max_confidence="0.4", expected_action="pass", notes="문서/예제 JWT")
    _append_negative_inputs(rows, prefix="ODR-GH", category="github_pat", inputs=["const githubPatExample = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'; return githubPatExample;", "docs.example.gh_pat=gho_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh", "sample personal token ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "fixture gh token ghs_QwertyUiopAsdfGhjkLzxcVbnm1234567890"], expected_rule="github_pat", max_confidence="0.4", expected_action="pass", notes="문서/예제 GitHub PAT")

    assert len(rows) == 48, len(rows)
    return rows


def main() -> int:
    tp_rows = generate_true_positive_rows()
    fp_rows = generate_false_positive_rows()
    realistic_tp_rows = generate_realistic_true_positive_rows()
    realistic_fp_rows = generate_realistic_false_positive_rows()
    false_negative_risk_rows = generate_false_negative_risk_rows()
    over_detection_risk_rows = generate_over_detection_risk_rows()

    write_csv(TP_PATH, POSITIVE_FIELDS, tp_rows)
    write_csv(FP_PATH, NEGATIVE_FIELDS, fp_rows)
    write_csv(RTP_PATH, POSITIVE_FIELDS, realistic_tp_rows)
    write_csv(RFP_PATH, NEGATIVE_FIELDS, realistic_fp_rows)
    write_csv(FNR_PATH, POSITIVE_FIELDS, false_negative_risk_rows)
    write_csv(ODR_PATH, NEGATIVE_FIELDS, over_detection_risk_rows)

    print(
        "generated "
        f"base_tp={len(tp_rows)} "
        f"base_fp={len(fp_rows)} "
        f"realistic_tp={len(realistic_tp_rows)} "
        f"realistic_fp={len(realistic_fp_rows)} "
        f"fn_risk={len(false_negative_risk_rows)} "
        f"over_risk={len(over_detection_risk_rows)} "
        f"total={len(tp_rows) + len(fp_rows) + len(realistic_tp_rows) + len(realistic_fp_rows) + len(false_negative_risk_rows) + len(over_detection_risk_rows)}"
    )
    for path in (TP_PATH, FP_PATH, RTP_PATH, RFP_PATH, FNR_PATH, ODR_PATH):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())