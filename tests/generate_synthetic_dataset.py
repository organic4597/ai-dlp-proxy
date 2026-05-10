#!/usr/bin/env python3
"""
한국어 PII 합성 데이터셋 생성기.

규격에 맞는 랜덤 PII 값을 직접 생성하여 TP / FP / FN 케이스를 만든다.
각 PII 타입별 체크섬/형식 검증을 통과하는 실질적인 값만 생성.

출력:
  tests/synthetic_true_positive.csv
  tests/synthetic_false_positive.csv
  tests/synthetic_realistic_true_positive.csv
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import random
import re
import string
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = int(time.time())  # 매 실행마다 다른 랜덤 값

rng = random.Random(SEED)

# ════════════════════════════════════════════════════════════════
# 1. PII 생성 함수 — 규격·체크섬을 통과하는 값만 생성
# ════════════════════════════════════════════════════════════════

def gen_kr_rrn() -> str:
    """주민등록번호 — 체크섬 통과, 실존 가능 생년월일.

    뒷자리 7자리 구조: gender(1) + region(4) + seq(1) + check(1)
    정규식 패턴: [1-4]\d{6} = 7자리
    """
    while True:
        year  = rng.randint(40, 99)   # 1940~1999 생
        month = rng.randint(1, 12)
        max_day = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month]
        day   = rng.randint(1, max_day)
        gender = rng.choice([1, 2])  # 1900년대 남/여

        front = f"{year:02d}{month:02d}{day:02d}"
        # 뒷 7자리: gender(1) + 5자리 임의 = 6자리 (체크섬 제외 12자리)
        back6 = f"{gender}{rng.randint(0, 99999):05d}"  # gender + 5자리
        digits12 = front + back6  # 12자리
        weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        total = sum(int(d) * w for d, w in zip(digits12, weights))
        check = (11 - (total % 11)) % 10
        if check >= 10:
            continue
        # 최종: 앞6자리-뒷7자리 (gender+5digits+check)
        full = front + "-" + back6 + str(check)
        return full


def gen_kr_phone() -> str:
    """한국 휴대전화번호.
    010: 11자리 (010-XXXX-XXXX)
    011/016/017/019: 10자리 (XXX-XXX-XXXX) 또는 11자리 혼용.
    """
    prefix = rng.choice(["010", "010", "010", "011", "016", "017", "019"])
    if prefix == "010":
        mid  = rng.randint(1000, 9999)  # 4자리
        last = rng.randint(1000, 9999)
    else:
        # 구형 번호: 3자리 또는 4자리 중간
        if rng.random() < 0.4:
            mid  = rng.randint(100, 999)   # 3자리 중간 (XXX-XXX-XXXX = 10자리)
        else:
            mid  = rng.randint(1000, 9999) # 4자리 중간 (XXX-XXXX-XXXX = 11자리)
        last = rng.randint(1000, 9999)
    sep = rng.choice(["-", "-", " ", ""])
    return f"{prefix}{sep}{mid}{sep}{last}"


def _luhn_check(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def gen_credit_card() -> str:
    """신용카드번호 — Luhn 체크섬 통과."""
    # Visa: 4xxx, Mastercard: 51-55, Discover: 6011
    prefixes = ["4", "51", "52", "53", "54", "55", "6011"]
    prefix = rng.choice(prefixes)
    length = 16

    while True:
        # 앞자리 고정 후 나머지 랜덤 (체크섬 자리 제외)
        rest_len = length - len(prefix) - 1
        rest = "".join(str(rng.randint(0, 9)) for _ in range(rest_len))
        partial = prefix + rest
        # 체크섬 자리 계산
        total = 0
        rev = partial[::-1]
        for i, d in enumerate(rev):
            n = int(d)
            if i % 2 == 0:  # 체크섬 자리는 짝수 인덱스가 됨
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        check = (10 - (total % 10)) % 10
        full = partial + str(check)
        if _luhn_check(full):
            # 포맷 선택: XXXX-XXXX-XXXX-XXXX 또는 붙이기
            if rng.random() < 0.6:
                return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:]}"
            return full


def gen_email() -> str:
    """이메일 주소 — 실존 형식."""
    domains = [
        "gmail.com", "naver.com", "kakao.com", "daum.net",
        "hanmail.net", "nate.com", "korea.ac.kr", "snu.ac.kr",
        "outlook.com", "company.co.kr", "example.com",
    ]
    local_chars = string.ascii_lowercase + string.digits
    local_len = rng.randint(5, 14)
    local = "".join(rng.choices(local_chars, k=local_len))
    # 중간에 . 또는 _ 삽입 (50% 확률)
    if rng.random() < 0.5 and local_len > 5:
        pos = rng.randint(2, local_len - 2)
        sep = rng.choice([".", "_"])
        local = local[:pos] + sep + local[pos:]
    return f"{local}@{rng.choice(domains)}"


def gen_kr_passport() -> str:
    """한국 여권번호 — M/S/A + 8자리 숫자."""
    letter = rng.choice(["M", "S", "A", "R"])
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return letter + digits


def gen_kr_driver_license() -> str:
    """한국 운전면허번호 — NN-NN-NNNNNN-NN 형식."""
    region  = rng.randint(11, 28)   # 지역코드 11~28
    year    = rng.choice(list(range(90, 100)) + list(range(0, 26)))  # 90~99, 00~25
    seq     = rng.randint(100000, 999999)
    check   = rng.randint(10, 99)
    return f"{region:02d}-{year:02d}-{seq:06d}-{check:02d}"


def gen_aws_access_key() -> str:
    """AWS Access Key ID — AKIA + 16자리 대문자+숫자."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(rng.choices(chars, k=16))
    return "AKIA" + suffix


def gen_github_pat() -> str:
    """GitHub Personal Access Token — ghp_ + 36자리."""
    chars = string.ascii_letters + string.digits
    token = "".join(rng.choices(chars, k=36))
    return "ghp_" + token


def gen_jwt() -> str:
    """JWT — header.payload.signature 형식 (실제 구조 준수)."""
    import base64, json

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_data = {
        "sub": str(rng.randint(10000, 9999999)),
        "name": rng.choice(["kim", "lee", "park", "choi"]) + str(rng.randint(1, 99)),
        "iat": int(time.time()) - rng.randint(0, 86400),
        "exp": int(time.time()) + rng.randint(3600, 86400),
    }
    payload = b64url(json.dumps(payload_data).encode())
    # 서명: 실제 HMAC 대신 랜덤 바이트 (검증 불필요)
    sig_bytes = bytes(rng.randint(0, 255) for _ in range(32))
    sig = b64url(sig_bytes)
    return f"{header}.{payload}.{sig}"


def gen_api_key() -> str:
    """API 키 — 32자리 hex 또는 base62."""
    style = rng.choice(["hex32", "hex40", "base62_32"])
    if style == "hex32":
        return "".join(rng.choices(string.hexdigits[:16], k=32))
    elif style == "hex40":
        return "".join(rng.choices(string.hexdigits[:16], k=40))
    else:
        chars = string.ascii_letters + string.digits
        return "".join(rng.choices(chars, k=32))


def gen_password() -> str:
    """비밀번호 — 실제 강도 높은 패스워드 형식."""
    parts = [
        "".join(rng.choices(string.ascii_uppercase, k=rng.randint(1, 3))),
        "".join(rng.choices(string.ascii_lowercase, k=rng.randint(4, 7))),
        "".join(rng.choices(string.digits, k=rng.randint(2, 4))),
        rng.choice(["!", "@", "#", "$", "%", "&", "*"]),
    ]
    p = list("".join(parts))
    rng.shuffle(p)
    return "".join(p)


# ════════════════════════════════════════════════════════════════
# 1b. 포맷 변형 — 동일 PII를 다양한 표기법으로 출력 (regex 탐지 가능 범위)
# ════════════════════════════════════════════════════════════════

def _vary_rrn(raw: str) -> str:
    """주민등록번호 표기 변형."""
    d = re.sub(r"\D", "", raw)
    return rng.choice([
        f"{d[:6]}-{d[6:]}",    # 880515-1234567 (표준)
        f"{d[:6]} {d[6:]}",    # 880515 1234567 (공백)
        d,                      # 8805151234567 (구분자 없음)
    ])


def _vary_phone(raw: str) -> str:
    """전화번호 표기 변형 — 모두 regex 탐지 가능한 포맷."""
    d = re.sub(r"\D", "", raw)
    p = d[:3]
    rest = d[3:]
    # 중간+끝 분리: 뒤에서 4자리가 끝, 나머지가 중간
    e, m = rest[-4:], rest[:-4]
    return rng.choice([
        f"{p}-{m}-{e}",    # 010-1234-5678 또는 010-123-5678 (자릿수 자동)
        f"{p} {m} {e}",    # 010 1234 5678
        f"{p}.{m}.{e}",    # 010.1234.5678
        d,                   # 01012345678
        f"{p}{m}-{e}",     # 0101234-5678 (앞 붙임)
        f"{p}-{m}{e}",     # 010-12345678 (뒤 붙임)
    ])


def _vary_card(raw: str) -> str:
    """신용카드 표기 변형."""
    d = re.sub(r"\D", "", raw)
    return rng.choice([
        f"{d[:4]}-{d[4:8]}-{d[8:12]}-{d[12:]}",  # XXXX-XXXX-XXXX-XXXX
        f"{d[:4]} {d[4:8]} {d[8:12]} {d[12:]}",  # XXXX XXXX XXXX XXXX
        d,                                          # XXXXXXXXXXXXXXXX
        f"{d[:4]}-{d[4:8]} {d[8:12]}-{d[12:]}",  # 혼합 구분자
        f"{d[:6]}-{d[6:12]}-{d[12:]}",            # XXXXXX-XXXXXX-XXXX
        f"{d[:4]} {d[4:6]}-{d[6:10]}-{d[10:]}",  # 비표준 그룹핑
    ])


def _vary_email(raw: str) -> str:
    """이메일 표기 변형 (plus addressing, 대소문자, 서브도메인)."""
    local, domain = raw.split("@", 1)
    extra_domains = ["m.naver.com", "mail.google.com", "kr.ibm.com",
                     "dev.kakao.com", "corp.samsung.com"]
    return rng.choice([
        raw,                                            # 기본
        f"{local}+noreply@{domain}",                   # plus tag
        f"{local}+work@{domain}",                      # plus tag 2
        raw.upper(),                                    # 대문자 (RFC 허용)
        f"{local}@{rng.choice(extra_domains)}",        # 다른 도메인
        f"{local.replace('.', '_')}@{domain}",         # 점→언더스코어
    ])


def _vary_passport(raw: str) -> str:
    """여권번호 표기 변형 — regex \\b[A-Z]{1,2}\\d{7,8}\\b 통과 포맷만."""
    letters = ["M", "S", "A", "R", "PM", "PS"]
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    letter = rng.choice(letters)
    return letter + digits    # PM12345678 (공백 없이 연속 — 공백 포함 시 regex 미탐)


def _vary_github_pat(raw: str) -> str:
    """GitHub PAT — 모든 유효 prefix 포함 (ghp/gho/ghu/ghs/ghr)."""
    chars = string.ascii_letters + string.digits
    suffix = "".join(rng.choices(chars, k=rng.randint(36, 40)))
    prefix = rng.choice(["ghp", "gho", "ghu", "ghs", "ghr"])
    return f"{prefix}_{suffix}"


def _vary_aws(raw: str) -> str:
    """AWS Access Key — prefix 변형 포함."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(rng.choices(chars, k=16))
    prefix = rng.choice(["AKIA", "ABIA", "ACCA", "ASIA"])
    return prefix + suffix


def _vary_api_key(raw: str) -> str:
    """API 키 — 길이·문자셋·형식 다양화."""
    chars_hex = string.hexdigits[:16]
    chars_b62 = string.ascii_letters + string.digits
    style = rng.choice(["hex32", "hex40", "base62_32", "uuid_style", "sk_prefix"])
    if style == "hex32":
        return "".join(rng.choices(chars_hex, k=32))
    elif style == "hex40":
        return "".join(rng.choices(chars_hex, k=40))
    elif style == "uuid_style":
        h = "".join(rng.choices(chars_hex, k=32))
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    elif style == "sk_prefix":
        return "sk-" + "".join(rng.choices(chars_b62, k=48))
    else:
        return "".join(rng.choices(chars_b62, k=32))


_VARIANT_FNS: dict[str, callable] = {
    "kr_rrn":             _vary_rrn,
    "kr_phone":           _vary_phone,
    "credit_card":        _vary_card,
    "email":              _vary_email,
    "kr_passport":        _vary_passport,
    "kr_driver_license":  lambda v: v,          # regex가 dash 필수 — 변형 없음
    "aws_access_key":     _vary_aws,
    "github_pat":         _vary_github_pat,
    "jwt_token":          lambda v: v,          # 구조 고정
    "api_key_assignment": _vary_api_key,
}


def _apply_variant(rule: str, raw: str) -> str:
    fn = _VARIANT_FNS.get(rule)
    return fn(raw) if fn else raw


# ════════════════════════════════════════════════════════════════
# 1c. FN 위험 포맷 — regex를 회피하는 변조 표기 (탐지 누락 위험)
#     → regex 커버리지 갭 발견용 (ML 필터가 아닌 regex 개선 참고)
# ════════════════════════════════════════════════════════════════

def _fn_phone(raw: str) -> tuple[str, str]:
    d = re.sub(r"\D", "", raw)
    p, m, e = d[:3], d[3:7], d[7:]
    return rng.choice([
        (f"+82-{d[1:3]}-{m}-{e}",          "국제번호 +82"),
        (f"({p}){m}-{e}",                   "괄호 지역코드"),
        (f"{p}\u2013{m}\u2013{e}",          "en-dash"),
        (f"{p}-{m[:2]}**-{e}",             "중간 부분마스킹"),
        (f"\uacf5\uc77c\uacf5-{m}-{e}",   "한글 앞자리 (공일공)"),
        (f"{d[:3]}/{d[3:7]}/{d[7:]}",      "슬래시"),
    ])


def _fn_rrn(raw: str) -> tuple[str, str]:
    d = re.sub(r"\D", "", raw)
    return rng.choice([
        (f"{d[:6]}/{d[6:]}",               "슬래시 구분"),
        (f"{d[:2]}/{d[2:4]}/{d[4:6]}-{d[6:]}", "날짜 슬래시"),
        (f"{d[:6]}-{d[6:9]}****",          "뒷자리 부분마스킹"),
        (f"{d[:4]}**-{d[6:]}",             "앞자리 부분마스킹"),
        (f"{d[:6]}_{d[6:]}",               "언더스코어"),
    ])


def _fn_card(raw: str) -> tuple[str, str]:
    d = re.sub(r"\D", "", raw)
    return rng.choice([
        (f"{d[:4]}.{d[4:8]}.{d[8:12]}.{d[12:]}", "점 구분"),
        (f"{d[:4]}\u2013{d[4:8]}\u2013{d[8:12]}\u2013{d[12:]}", "en-dash"),
        (f"{d[:4]} **** **** {d[12:]}",    "중간 마스킹"),
        (f"{d[:4]}/{d[4:8]}/{d[8:12]}/{d[12:]}", "슬래시"),
        (f"{d[:4]}#{d[4:8]}#{d[8:12]}#{d[12:]}", "해시"),
    ])


def _fn_email(raw: str) -> tuple[str, str]:
    local, domain = raw.split("@", 1)
    return rng.choice([
        (raw.replace("@", " [at] "),       "[at] 치환"),
        (raw.replace(".", "[.]"),           "[.] 치환"),
        (f"{local} @ {domain}",            "@ 주변 공백"),
        (raw.replace("@", "(at)"),         "(at) 치환"),
        (f"{local}[골뱅이]{domain}",       "한글 치환"),
    ])


_FN_RISK_FNS: dict[str, callable] = {
    "kr_phone":    _fn_phone,
    "kr_rrn":      _fn_rrn,
    "credit_card": _fn_card,
    "email":       _fn_email,
}



KR_NAMES = ["김민준", "이서연", "박도윤", "최지우", "정시우", "강하은", "조민서", "윤채원",
            "장예준", "임수아", "오지호", "한가을", "서준혁", "노윤아", "문태양"]
COMPANY_NAMES = ["삼성전자", "카카오", "네이버", "현대자동차", "LG전자", "SK하이닉스",
                  "롯데쇼핑", "신한은행", "KB금융", "포스코"]

def _name() -> str:
    return rng.choice(KR_NAMES)

def _company() -> str:
    return rng.choice(COMPANY_NAMES)


TP_TEMPLATES: dict[str, list[str]] = {
    "kr_rrn": [
        "주민 등록 번호: {v}",
        "본인확인 주민등록번호 = {v}",
        "{name} 고객님의 resident identification: {v}",
        "신분확인용 주민등록번호는 {v} 입니다.",
        "생년월일 기반 본인확인 값 {v}",
        "고객 정보\n이름: {name}\n주민번호: {v}\n연락처: 010-xxxx-xxxx",
        "resident_registration_number: \"{v}\"",
        "rrn={v} 처리 완료",
        "identification number {v} confirmed",
        "주민등록번호 입력 완료 — {v}",
        "신분증 번호: {v} (발급기관: 행정안전부)",
        "birth registration: {v}",
        "{name}님 본인인증 완료: {v}",
        "주민번호 앞뒤 7자리 확인 {v}",
        "고객정보 수집 동의서\n주민등록번호: {v}",
    ],
    "kr_phone": [
        "전화번호: {v}",
        "연락처 정보 mobile={v}",
        "{name}의 휴대폰 번호는 {v}",
        "긴급 연락처: {v}",
        "contact: {v}",
        "phone number {v}",
        "통화 요청 번호 {v}",
        "담당자 핸드폰: {v}",
        "모바일 번호 입력: {v}",
        "call me at {v}",
        "연락처\n{name}: {v}",
        "수신자 전화번호: {v}",
        "비상연락망 등록 {v}",
        "모바일 인증번호 발송 대상: {v}",
        "my number is {v}",
    ],
    "credit_card": [
        "카드 결제 승인 번호: {v}",
        "신용카드 정보 payment card = {v}",
        "billing card number: {v}",
        "결제 카드 번호 {v}",
        "credit card: {v}",
        "카드 명세서 번호 {v}",
        "payment method: card {v}",
        "카드번호 {v} 로 결제 요청",
        "카드 결제 정보\n번호: {v}\n유효기간: {exp}",
        "card_number={v}",
        "신용카드 번호: {v} (유효기간 {exp})",
        "purchase authorized — card {v}",
        "결제수단: {v}",
        "credit billing: {v} expires {exp}",
        "카드 번호 입력 완료: {v}",
    ],
    "email": [
        "이메일: {v}",
        "연락처 메일 주소 {v}",
        "수신자 email={v}",
        "담당자 이메일: {v}",
        "send to {v}",
        "mail recipient: {v}",
        "{name}의 이메일 주소는 {v} 입니다",
        "회신 주소: {v}",
        "inbox {v}",
        "이메일 주소 등록: {v}",
        "contact email {v}",
        "메일 보내기 → {v}",
        "고객 이메일: {v}",
        "email address for {name}: {v}",
        "수신 메일: {v}",
    ],
    "kr_passport": [
        "여권번호: {v}",
        "passport number {v}",
        "출국 여권 정보 {v}",
        "{name} 여권: {v}",
        "비자 신청 여권번호 {v}",
        "입국 여권 번호 = {v}",
        "passport: {v} departure confirmed",
        "여권 스캔 결과 {v}",
        "airport check — passport {v}",
        "visa application passport {v}",
        "{name}님 여권번호 {v} 확인",
        "여권번호 입력 {v}",
        "passport id: {v}",
        "여행서류 여권 {v}",
        "출입국 기록 여권번호: {v}",
    ],
    "kr_driver_license": [
        "운전면허번호: {v}",
        "driving license {v}",
        "면허 발급 번호 {v}",
        "{name} 운전면허 {v}",
        "license number {v} confirmed",
        "경찰청 운전면허 조회 {v}",
        "면허 정보 = {v}",
        "driver license id: {v}",
        "운전면허 발급기관 확인 {v}",
        "license: {v} 유효",
        "{name}의 운전면허번호 {v}",
        "면허번호 등록 {v}",
        "driving licence {v} issued",
        "도로교통법 면허 {v}",
        "운전면허증 번호 {v}",
    ],
    "aws_access_key": [
        "aws_access_key_id = {v}",
        "AWS_ACCESS_KEY_ID={v}",
        "클라우드 배포 설정 access_key: {v}",
        "aws access key: {v}",
        "인프라 계정 access_key_id={v}",
        "AWS 설정\naws_access_key_id = {v}\naws_secret_access_key = {secret}",
        "cloud deploy key {v}",
        "account access: {v}",
        "export AWS_ACCESS_KEY_ID={v}",
        "terraform variable aws_key = {v}",
        ".env 파일\nAWS_ACCESS_KEY_ID={v}",
        "AWS credential: {v}",
        "액세스 키 발급 완료: {v}",
        "infra config access_key={v}",
        "aws_access_key_id: {v}",
    ],
    "github_pat": [
        "github_token = {v}",
        "GITHUB_TOKEN={v}",
        "깃헙 personal access token: {v}",
        "repo 접근용 토큰 {v}",
        "git remote auth token {v}",
        "commit push token={v}",
        "github pat: {v}",
        "GitHub PAT\n{v}",
        "export GITHUB_TOKEN={v}",
        "CI 토큰 설정 github_token={v}",
        "깃허브 API 인증: {v}",
        "personal access token {v} generated",
        "repo token: {v}",
        "GitHub Actions secret GITHUB_TOKEN={v}",
        "token for github: {v}",
    ],
    "jwt_token": [
        "Authorization: Bearer {v}",
        "bearer token={v}",
        "세션 JWT: {v}",
        "로그인 토큰 {v}",
        "auth_token={v}",
        "access token (JWT): {v}",
        "decode jwt: {v}",
        "토큰 검증 {v}",
        "session token: {v}",
        "login jwt {v}",
        "인가 토큰 Bearer {v}",
        "JWT 발급 완료 {v}",
        "token: {v}",
        "auth header: Bearer {v}",
        "서비스 jwt token {v}",
    ],
    "api_key_assignment": [
        "api_key = \"{v}\"",
        "API_KEY={v}",
        "secret_key: {v}",
        "access_token=\"{v}\"",
        "api-key: {v}",
        "auth_token={v}",
        "private_key=\"{v}\"",
        "api_key={v}",
        "secret-key={v}",
        "access-token: {v}",
        "API_KEY설정: api_key={v}",
        "external api_key: {v}",
        "secret_key = {v}",
        "access_token: {v}",
        "auth-token={v}",
    ],
}

# FP 템플릿 — 같은 형식이지만 명백히 코드/예제 문맥
FP_TEMPLATES: dict[str, list[str]] = {
    "kr_rrn": [
        "# 예시용 주민번호: {v} (테스트 데이터)",
        "test_rrn = \"{v}\"  # 단위 테스트용",
        "주민번호 형식 예시: 880101-1234567 또는 {v}",
        "// 더미 데이터: {v}",
        "sample_rrn = \"{v}\"",
        "FORMAT: YYMMDD-GXXXXXXC, example {v}",
    ],
    "kr_phone": [
        "# test phone: {v}",
        "phone_regex_test = \"{v}\"  # 정규식 검증용",
        "예시 전화번호: {v} (실제 번호 아님)",
        "dummy_phone = \"{v}\"",
        "mock phone number {v}",
        "// 테스트 연락처 {v}",
    ],
    "credit_card": [
        "# 테스트용 카드번호 {v}",
        "test_card_number = \"{v}\"",
        "// dummy card: {v}",
        "sample_payment_number = \"{v}\"  # 실결제 아님",
        "card regex test {v}",
        "test_credit_card={v}  # ci test",
    ],
    "email": [
        "# example: {v}",
        "// placeholder email {v}",
        "no-reply@example.com 또는 {v} 같은 형식",
        "test_email = \"{v}\"",
        "sample_email_addr = \"{v}\"  # 더미",
        "dummy_recipient={v}",
    ],
    "aws_access_key": [
        "# EXAMPLE KEY — not real: {v}",
        "// placeholder aws_access_key_id = {v}",
        "test_key = \"{v}\"  # 테스트용",
        "sample_access_key = {v}  # CI 환경 아님",
        "aws_access_key_id = \"YOUR_KEY_HERE\"  # e.g. {v}",
        "fake_aws_key={v}  # unit test",
    ],
    "api_key_assignment": [
        "api_key = \"YOUR_API_KEY\"  # e.g. {v}",
        "# placeholder: api_key={v}",
        "example_api_key = \"{v}\"  # 실제 키 아님",
        "// test api_key {v}",
        "sample_service_key={v}  # mock",
        "access_token = \"<TOKEN>\"  # like {v}",
    ],
    "kr_passport": [
        "# example passport: {v}",
        "test_passport_num = \"{v}\"",
        "// dummy passport {v}",
        "sample_passport={v}  # 테스트",
        "여권번호 형식 예시 {v}",
        "mock_passport_id=\"{v}\"",
    ],
}

# ════════════════════════════════════════════════════════════════
# 3. 데이터 생성 로직
# ════════════════════════════════════════════════════════════════

def _fill(template: str, value: str) -> str:
    name    = _name()
    company = _company()
    exp     = f"{rng.randint(1,12):02d}/{rng.randint(25,30)}"
    secret  = gen_api_key()
    return (template
            .replace("{v}", value)
            .replace("{name}", name)
            .replace("{company}", company)
            .replace("{exp}", exp)
            .replace("{secret}", secret))


GENERATORS: dict[str, callable] = {
    "kr_rrn":             gen_kr_rrn,
    "kr_phone":           gen_kr_phone,
    "credit_card":        gen_credit_card,
    "email":              gen_email,
    "kr_passport":        gen_kr_passport,
    "kr_driver_license":  gen_kr_driver_license,
    "aws_access_key":     gen_aws_access_key,
    "github_pat":         gen_github_pat,
    "jwt_token":          gen_jwt,
    "api_key_assignment": gen_api_key,
    # password_assignment은 regex_stage에 독립 규칙 없음 — api_key 패턴 내 처리
}


def generate_tp(n_per_rule: int = 50) -> list[dict]:
    """True Positive 케이스 생성 — 포맷 변형 포함."""
    rows = []
    for rule, gen_fn in GENERATORS.items():
        templates = TP_TEMPLATES.get(rule, ["{v}"])
        for i in range(n_per_rule):
            raw      = gen_fn()
            value    = _apply_variant(rule, raw)   # 포맷 변형
            template = templates[i % len(templates)]
            text     = _fill(template, value)
            rows.append({
                "case_id":         f"SYN-TP-{rule.upper()[:8]}-{i+1:04d}",
                "category":        rule,
                "input_text":      text,
                "expected_rule":   rule,
                "min_confidence":  0.8 if rule in ("kr_rrn", "credit_card") else 0.5,
                "expected_action": "mask",
                "notes":           f"합성 TP — 규격+포맷변형 seed={SEED}",
            })
    return rows


def generate_fp(n_per_rule: int = 30) -> list[dict]:
    """False Positive 케이스 — 코드/예제 문맥."""
    rows = []
    for rule, templates in FP_TEMPLATES.items():
        gen_fn = GENERATORS[rule]
        for i in range(n_per_rule):
            value    = gen_fn()
            template = templates[i % len(templates)]
            text     = _fill(template, value)
            rows.append({
                "case_id":         f"SYN-FP-{rule.upper()[:8]}-{i+1:04d}",
                "category":        rule,
                "input_text":      text,
                "expected_rule":   rule,
                "min_confidence":  0.0,
                "expected_action": "pass",
                "notes":           f"합성 FP — 코드/테스트 문맥 seed={SEED}",
            })
    return rows


def generate_realistic_tp(n_per_rule: int = 40) -> list[dict]:
    """현실형 TP — JSON/YAML/대화/설문 등 복합 문맥."""
    realistic_wrappers = [
        # JSON 문맥
        lambda rule, v: f'{{\n  "user_id": "{rng.randint(10000,99999)}",\n  "{rule}": "{v}",\n  "verified": true\n}}',
        # YAML 문맥
        lambda rule, v: f"user_profile:\n  name: {_name()}\n  {rule}: {v}\n  role: user",
        # 자연어 상담
        lambda rule, v: f"{_name()} 고객이 {rule.replace('_',' ')} 정보를 제출했습니다: {v}",
        # Markdown 문서
        lambda rule, v: f"## 고객 정보\n- **{rule}**: `{v}`\n- **회사**: {_company()}",
        # Python dict
        lambda rule, v: f"customer = {{\n    '{rule}': '{v}',\n    'status': 'active'\n}}",
        # 슬랙 메시지 형식
        lambda rule, v: f"[{_company()}] {_name()} 님이 {rule} 공유: {v}",
        # CSV 행 형식
        lambda rule, v: f"{_name()},{v},{_company()},active",
        # SQL INSERT
        lambda rule, v: f"INSERT INTO users ({rule}, name) VALUES ('{v}', '{_name()}');",
        # 이메일 본문
        lambda rule, v: f"안녕하세요,\n\n{_name()} 님의 {rule} 정보를 안내드립니다.\n값: {v}\n\n감사합니다.",
        # 로그 형식
        lambda rule, v: f"[INFO] user={_name()} action=submit field={rule} value={v} ts={int(time.time())}",
    ]
    rows = []
    for rule, gen_fn in GENERATORS.items():
        for i in range(n_per_rule):
            raw     = gen_fn()
            value   = _apply_variant(rule, raw)    # 포맷 변형
            wrapper = realistic_wrappers[i % len(realistic_wrappers)]
            text    = wrapper(rule, value)
            rows.append({
                "case_id":         f"SYN-RTP-{rule.upper()[:8]}-{i+1:04d}",
                "category":        rule,
                "input_text":      text,
                "expected_rule":   rule,
                "min_confidence":  0.5,
                "expected_action": "mask",
                "notes":           f"합성 현실형 TP — 복합 문맥+포맷변형 seed={SEED}",
            })
    return rows


def generate_fn_risk(n_per_rule: int = 25) -> list[dict]:
    """FN 위험 케이스 — regex를 회피하는 변조 포맷.
    실제 PII이지만 현재 탐지 패턴이 잡지 못하는 케이스.
    regex 커버리지 개선 참고용.
    """
    rows = []
    for rule, fn_fn in _FN_RISK_FNS.items():
        gen_fn    = GENERATORS[rule]
        templates = TP_TEMPLATES.get(rule, ["{v}"])
        for i in range(n_per_rule):
            raw           = gen_fn()
            value, label  = fn_fn(raw)
            template      = templates[i % len(templates)]
            text          = _fill(template, value)
            rows.append({
                "case_id":         f"SYN-FN-{rule.upper()[:8]}-{i+1:04d}",
                "category":        rule,
                "input_text":      text,
                "expected_rule":   rule,
                "min_confidence":  0.5,
                "expected_action": "mask",
                "notes":           f"합성 FN위험 — [{label}] 변조 포맷 seed={SEED}",
            })
    return rows


# ════════════════════════════════════════════════════════════════
# 4. CSV 저장
# ════════════════════════════════════════════════════════════════

FIELDNAMES = ["case_id", "category", "input_text", "expected_rule",
              "min_confidence", "expected_action", "notes"]


def write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  → {path.name}  ({len(rows)}건)")


def main() -> None:
    print(f"[synthetic_dataset] seed={SEED}")

    tp_rows  = generate_tp(n_per_rule=50)
    fp_rows  = generate_fp(n_per_rule=30)
    rtp_rows = generate_realistic_tp(n_per_rule=40)
    fn_rows  = generate_fn_risk(n_per_rule=25)

    write_csv(HERE / "synthetic_true_positive.csv",          tp_rows)
    write_csv(HERE / "synthetic_false_positive.csv",         fp_rows)
    write_csv(HERE / "synthetic_realistic_true_positive.csv", rtp_rows)
    write_csv(HERE / "synthetic_false_negative_risk.csv",    fn_rows)

    total = len(tp_rows) + len(fp_rows) + len(rtp_rows) + len(fn_rows)
    print(f"\n합계: {total}건")
    print(f"  TP     {len(tp_rows):>5}건  ({len(GENERATORS)} 규칙 × 50) — 포맷 변형 포함")
    print(f"  FP     {len(fp_rows):>5}건  ({len(FP_TEMPLATES)} 규칙 × 30) — 코드/예제 문맥")
    print(f"  RTP    {len(rtp_rows):>5}건  ({len(GENERATORS)} 규칙 × 40) — JSON/YAML/SQL/로그 문맥")
    print(f"  FN위험 {len(fn_rows):>5}건  ({len(_FN_RISK_FNS)} 규칙 × 25) — 변조 포맷 (탐지 누락 위험)")

    # 포맷 변형 샘플 출력
    print("\n── 전화번호 포맷 변형 샘플 ──")
    phone_tp = [r for r in tp_rows if r["category"] == "kr_phone"][:8]
    for r in phone_tp:
        import re as _re
        m = _re.search(r"[\d\-\.\s+공일영]{8,}", r["input_text"])
        val = m.group(0).strip() if m else r["input_text"][:30]
        print(f"  {val!r}")

    print("\n── 신용카드 포맷 변형 샘플 ──")
    card_tp = [r for r in tp_rows if r["category"] == "credit_card"][:5]
    for r in card_tp:
        m = _re.search(r"[\d\-\s]{13,25}", r["input_text"])
        val = m.group(0).strip() if m else r["input_text"][:30]
        print(f"  {val!r}")

    print("\n── FN 위험 샘플 (탐지 회피 포맷) ──")
    for row in fn_rows[:6]:
        print(f"  [{row['category']}] {row['notes'].split('—')[1].strip()}  →  {row['input_text'][:60]!r}")


if __name__ == "__main__":
    main()
