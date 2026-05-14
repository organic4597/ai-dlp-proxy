"""
SLM 파인튜닝용 데이터셋 생성기 v2
====================================
위협 모델: AI Agent / MCP 도구 사용 중 발생하는 PII 유출

핵심 인사이트:
  - 사용자가 직접 PII를 입력하는 경우는 드뭄
  - Agent가 tool_result로 가져온 데이터가 LLM 컨텍스트에 그대로 삽입됨
  - Regex는 패턴을 잡지만 "이 데이터가 실제 사람의 정보인가" 판단 못 함
  - SLM의 역할: 문맥 기반 판단 (테스트 데이터 vs 실제 데이터, 마스킹 여부 등)
"""
from __future__ import annotations

import base64
import json
import random
import re
import sys
from pathlib import Path

random.seed(42)

REPO_ROOT = Path(__file__).parent.parent
OUT_TRAIN = REPO_ROOT / "tests" / "slm_train_dataset.jsonl"
OUT_EVAL  = REPO_ROOT / "tests" / "slm_eval_dataset.jsonl"

SYSTEM_PROMPT = (
    "당신은 개인정보(PII) 탐지 전문 AI입니다. "
    "주어진 텍스트에서 개인정보를 찾아 JSON 배열로만 반환하세요. "
    "출력 형식: [[\"rule_id\", start, end], ...] — 규칙ID와 문자 오프셋만 포함합니다. "
    "<<<...>>> 로 이미 마스킹된 항목은 무시합니다. "
    "테스트/예시 데이터, 공개 정보, 가상 인물은 PII로 분류하지 않습니다. "
    "마크다운 없이 순수 JSON만 출력합니다. "
    "PII가 없으면 [] 를 반환합니다."
)

NAMES_KR = [
    "홍길동", "김철수", "이영희", "박민준", "최지은", "정우성", "강다은",
    "윤서준", "임소연", "한지민", "조현우", "신예린", "오태양", "배수진",
    "문성호", "권나래", "유재석", "김지원", "이준호", "박서연", "황민서",
    "송유나", "안진우", "류하은", "남궁현", "백수현", "노은결", "서지훈",
]
PHONES = [
    "010-1234-5678", "010-9876-5432", "010-2345-6789", "010-3456-7890",
    "010-4567-8901", "010-5678-9012", "010-7777-8888", "010-1111-2222",
    "010-3333-4444", "010-6789-0123",
]
RRNS = [
    "880515-1104333", "950720-2218199", "000301-3600132", "751103-1389080",
    "010614-4542353", "870925-1384567", "920411-2394678", "851204-1029384",
]
CORP_EMAILS = [
    "jkim@kakaobank.com", "mpark@samsung.com", "shlee@naver.com",
    "bhong@lgcns.com", "ychoi@hyundai.com", "kmin@coupang.com",
    "swjung@kakao.com", "jyoh@krafton.com", "hkwon@krafton.com",
]
ADDRESSES = [
    "서울시 강남구 테헤란로 123", "부산시 해운대구 우동 1234번지",
    "경기도 성남시 분당구 판교로 456", "인천시 연수구 송도동 789",
    "서울시 마포구 홍익로 32", "대전시 유성구 대학로 99",
    "서울시 종로구 사직로 130", "경기도 수원시 영통구 삼성로 129",
]
INTERNAL_IPS = ["192.168.1.100", "10.0.0.45", "172.16.254.1", "192.168.0.200",
                "10.10.1.55", "192.168.2.30"]
PUBLIC_IPS   = ["203.0.113.42", "198.51.100.7", "185.220.101.33", "104.21.3.200"]
ALL_IPS = INTERNAL_IPS + PUBLIC_IPS
AWS_KEY_IDS = ["AKIAIOSFODNN7EXAMPLE", "AKIAJ5KXAMPL12345AB", "AKIAI44QH8DHBEXAMPLE"]
AWS_SECRETS = [
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
]
OPENAI_KEYS = [
    "sk-proj-abc123def456ghi789jkl012mno345pqr",
    "sk-proj-XyZ9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT",
]
DB_PASSWORDS = ["P@ssw0rd!2024", "Prod#Secret789", "MyDB_Pass!@#", "Str0ng&Pass2026"]
JWT_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3IxMjM0NTYiLCJuYW1lIjoi7ZmN6ri464-ZIiwiaWF0IjoxNzQ2ODcwNDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImtpbUBjb21wYW55LmNvbSIsInJvbGUiOiJhZG1pbiJ9.signature123",
]
ORGS = ["카카오뱅크", "삼성전자", "네이버", "현대자동차", "LG CNS", "쿠팡", "크래프톤"]
DEPARTMENTS = ["개발팀", "인사팀", "영업팀", "보안팀", "재무팀", "데이터팀"]
CARD_NUMBERS = ["4532-0151-1283-0366", "5425-2334-3010-9903", "3714-496353-98431"]


def _pick(*pools):
    return tuple(random.choice(p) for p in pools)


def _finding(rule, text, start, confidence=0.95):
    return {"rule": rule, "start": start, "end": start + len(text),
            "text": text, "confidence": confidence}


def _find_all(haystack, needle):
    idxs, start = [], 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        idxs.append(idx)
        start = idx + 1
    return idxs


def _offset(text, needle, confidence=0.95, rule=None):
    idx = text.find(needle)
    if idx == -1:
        return None
    r = rule or _guess_rule(needle)
    return _finding(r, needle, idx, confidence)


def _all_offsets(text, needle, confidence, rule):
    results = []
    seen = set()
    for idx in _find_all(text, needle):
        if idx not in seen:
            results.append(_finding(rule, needle, idx, confidence))
            seen.add(idx)
    return results


def _guess_rule(val):
    if re.match(r'\d{6}-\d{7}', val):       return "kr_rrn"
    if re.match(r'010-\d{4}-\d{4}', val):   return "kr_phone"
    if "@" in val:                            return "email"
    if re.match(r'\d+\.\d+\.\d+\.\d+', val):return "ip_address"
    if val.startswith("AKIA"):               return "aws_access_key"
    if val.startswith("sk-proj-"):           return "api_key"
    if val.startswith("eyJ"):               return "jwt_token"
    if re.match(r'\d{4}-\d{4}-\d{4}-\d{4}', val): return "credit_card"
    return "person_name"


def _compact(f: dict) -> list:
    """내부 finding dict → [rule, start, end] compact 형식."""
    return [f["rule"], f["start"], f["end"]]


def _make(user_text, findings):
    compact = [_compact(f) for f in findings] if findings else []
    answer = json.dumps(compact, ensure_ascii=False) if compact else "[]"
    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": f"다음 텍스트에서 개인정보를 탐지하세요:\n\n{user_text}"},
            {"role": "assistant", "content": answer},
        ]
    }


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["start"], f["end"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return sorted(out, key=lambda x: x["start"])


# ── A. 사용자 직접 입력 ────────────────────────────────────────────────────────

def gen_A():
    samples = []

    for _ in range(130):
        name, phone, addr = _pick(NAMES_KR, PHONES, ADDRESSES)
        templates = [
            (f"INSERT INTO customers (name, phone, address) VALUES\n"
             f"('{name}', '{phone}', '{addr}');\n-- Duplicate entry 에러남 왜?",
             [(name, "person_name", 0.91), (phone, "kr_phone", 0.99), (addr, "address", 0.88)]),
            (f"customer = {{\n  'name': '{name}',\n  'phone': '{phone}',\n"
             f"  'addr': '{addr}'\n}}\nsend_notification(customer)  # TypeError",
             [(name, "person_name", 0.91), (phone, "kr_phone", 0.99), (addr, "address", 0.88)]),
        ]
        text, pii_list = random.choice(templates)
        findings = _dedup([f for v, r, c in pii_list if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(130):
        rows, pii_vals = [], []
        for _ in range(random.randint(2, 4)):
            name, phone, addr = _pick(NAMES_KR, PHONES, ADDRESSES)
            rows.append(f"{name},{phone},{addr}")
            pii_vals.extend([(name, "person_name", 0.91), (phone, "kr_phone", 0.99), (addr, "address", 0.88)])
        text = "이름,연락처,주소\n" + "\n".join(rows) + "\n\n이 CSV 파싱 코드 짜줘"
        findings = _dedup([f for v, r, c in pii_vals if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(120):
        name, phone, rrn = _pick(NAMES_KR, PHONES, RRNS)
        templates = [
            (f"Traceback:\n  File 'api.py', line 42\n"
             f"ValueError: Invalid RRN for {name}: {rrn}\n\n이 에러 왜 나는지?",
             [(name, "person_name", 0.88), (rrn, "kr_rrn", 0.99)]),
            (f"ERROR ValidationError: phone '{phone}' does not match for user '{name}'\n이 로그 찾아줘",
             [(name, "person_name", 0.88), (phone, "kr_phone", 0.99)]),
        ]
        text, pii_list = random.choice(templates)
        findings = _dedup([f for v, r, c in pii_list if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(120):
        name = random.choice(NAMES_KR)
        email = random.choice(CORP_EMAILS)
        templates = [
            (f"{name}님한테 이 PR 리뷰 요청 보내야 하는데 연락처 좀",
             [(name, "person_name", 0.85)]),
            (f"{name} 대리가 보낸 이메일({email}) 요약해줘",
             [(name, "person_name", 0.85), (email, "email", 0.97)]),
        ]
        text, pii_list = random.choice(templates)
        findings = _dedup([f for v, r, c in pii_list if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    return samples


# ── B-1. DB 쿼리 결과 ──────────────────────────────────────────────────────────

def gen_B1():
    samples = []

    for _ in range(400):
        rows_text, all_pii = [], []
        for _ in range(random.randint(1, 4)):
            name, phone, addr, rrn = _pick(NAMES_KR, PHONES, ADDRESSES, RRNS)
            rows_text.append(f"| {name} | {phone} | {addr} | {rrn} |")
            all_pii.extend([(name, "person_name", 0.92), (phone, "kr_phone", 0.99),
                            (addr, "address", 0.90), (rrn, "kr_rrn", 0.99)])
        query = random.choice([
            "SELECT name, phone, address, rrn FROM customers LIMIT 10",
            "SELECT c.name, c.phone, o.address FROM customers c JOIN orders o ON c.id=o.cid",
            "SELECT * FROM user_profiles WHERE created_at > '2026-01-01'",
        ])
        text = (f"<tool_result tool_name='database_query'>\nQuery: {query}\n"
                f"| name | phone | address | rrn |\n|------|-------|---------|-----|\n"
                + "\n".join(rows_text) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(400):
        real_rows, real_pii = [], []
        dummy_rows = [
            "| test_user | 010-0000-0000 | 테스트 주소 | 000000-0000000 |",
            "| sample_customer | N/A | (주소 미입력) | - |",
            "| dummy_user_1 | 010-9999-9999 | example address | NULL |",
        ]
        for _ in range(random.randint(1, 2)):
            name, phone, addr = _pick(NAMES_KR, PHONES, ADDRESSES)
            real_rows.append(f"| {name} | {phone} | {addr} | (비어있음) |")
            real_pii.extend([(name, "person_name", 0.92), (phone, "kr_phone", 0.99), (addr, "address", 0.88)])
        all_rows = real_rows + random.sample(dummy_rows, k=min(2, len(dummy_rows)))
        random.shuffle(all_rows)
        text = (f"<tool_result tool_name='database_query'>\n"
                f"Query: SELECT * FROM members ORDER BY created_at DESC LIMIT 10\n"
                f"| name | phone | address | rrn |\n|------|-------|---------|-----|\n"
                + "\n".join(all_rows) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in real_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(260):
        rows, all_pii = [], []
        for i in range(random.randint(2, 4)):
            name, phone, addr, rrn = _pick(NAMES_KR, PHONES, ADDRESSES, RRNS)
            rows.append(f"INSERT INTO customers VALUES ({1000+i}, '{name}', '{phone}', '{addr}', '{rrn}');")
            all_pii.extend([(name, "person_name", 0.91), (phone, "kr_phone", 0.99),
                            (addr, "address", 0.88), (rrn, "kr_rrn", 0.99)])
        text = (f"<tool_result tool_name='read_file' path='backup/dump_2026.sql'>\n"
                f"-- MySQL dump 8.0\n-- Table: customers\n"
                + "\n".join(rows) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(260):
        name, phone = _pick(NAMES_KR, PHONES)
        card = random.choice(CARD_NUMBERS)
        addr = random.choice(ADDRESSES)
        text = (f"<tool_result tool_name='database_query'>\n"
                f"Query: SELECT * FROM payments WHERE status='pending'\n"
                f"| customer_name | phone | card_number | delivery_address |\n|---|---|---|---|\n"
                f"| {name} | {phone} | {card} | {addr} |\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.92), (phone, "kr_phone", 0.99),
            (card, "credit_card", 0.99), (addr, "address", 0.88)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    return samples


# ── B-2. 환경변수 / 자격증명 ──────────────────────────────────────────────────

def gen_B2():
    samples = []

    for _ in range(260):
        aws_id = random.choice(AWS_KEY_IDS)
        aws_sec = random.choice(AWS_SECRETS)
        oai_key = random.choice(OPENAI_KEYS)
        db_pass = random.choice(DB_PASSWORDS)
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='bash' command='env | sort'>\n"
                f"AWS_ACCESS_KEY_ID={aws_id}\nAWS_DEFAULT_REGION=ap-northeast-2\n"
                f"AWS_SECRET_ACCESS_KEY={aws_sec}\nDB_HOST={ip}\nDB_PASSWORD={db_pass}\n"
                f"HOME=/root\nOPENAI_API_KEY={oai_key}\n"
                f"PATH=/usr/local/sbin:/usr/local/bin\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (aws_id, "aws_access_key", 0.99), (aws_sec, "aws_secret_key", 0.99),
            (oai_key, "api_key", 0.99), (db_pass, "credential", 0.97),
            (ip, "ip_address", 0.85)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(260):
        db_pass = random.choice(DB_PASSWORDS)
        oai_key = random.choice(OPENAI_KEYS)
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='read_file' path='.env'>\n"
                f"# 데이터베이스 설정\n"
                f"DATABASE_URL=postgresql://admin:{db_pass}@{ip}:5432/prod_db\n"
                f"SECRET_KEY=django-insecure-randomsalt123\n"
                f"OPENAI_API_KEY={oai_key}\nDEBUG=False\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (db_pass, "credential", 0.97), (ip, "ip_address", 0.85),
            (oai_key, "api_key", 0.99)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        db_pass = random.choice(DB_PASSWORDS)
        oai_key = random.choice(OPENAI_KEYS)
        db_pass_b64 = base64.b64encode(db_pass.encode()).decode()
        oai_b64 = base64.b64encode(oai_key.encode()).decode()
        text = (f"<tool_result tool_name='bash' command='kubectl get secret app-secrets -o yaml'>\n"
                f"apiVersion: v1\nkind: Secret\ndata:\n"
                f"  db-password: {db_pass_b64}\n  openai-key: {oai_b64}\n</tool_result>\n\n"
                f"<tool_result tool_name='bash' command='echo {db_pass_b64} | base64 -d'>\n"
                f"{db_pass}\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (db_pass_b64, "credential_b64", 0.90), (oai_b64, "api_key_b64", 0.90),
            (db_pass, "credential", 0.99)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        db_pass = random.choice(DB_PASSWORDS)
        ip = random.choice(INTERNAL_IPS)
        oai_key = random.choice(OPENAI_KEYS)
        text = (f"<tool_result tool_name='read_file' path='docker-compose.yml'>\n"
                f"version: '3.8'\nservices:\n  app:\n    environment:\n"
                f"      - OPENAI_API_KEY={oai_key}\n"
                f"      - DATABASE_URL=postgresql://prod:{db_pass}@{ip}/app\n"
                f"  db:\n    image: postgres:15\n    environment:\n"
                f"      - POSTGRES_PASSWORD={db_pass}\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (oai_key, "api_key", 0.99), (db_pass, "credential", 0.97),
            (ip, "ip_address", 0.85)] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    return samples


# ── B-3. 코드 실행 / REPL ────────────────────────────────────────────────────

def gen_B3():
    samples = []

    for _ in range(330):
        rows, all_pii = [], []
        for i in range(random.randint(3, 6)):
            name, phone, addr = _pick(NAMES_KR, PHONES, ADDRESSES)
            rows.append(f"{i}  {name:<8}  {phone}  {addr}")
            all_pii.extend([(name, "person_name", 0.91), (phone, "kr_phone", 0.99), (addr, "address", 0.88)])
        text = (f"<tool_result tool_name='python_repl'>\n"
                f">>> df = pd.read_csv('customers.csv')\n"
                f">>> df.head({len(rows)})\n   name      phone         address\n"
                + "\n".join(rows) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(260):
        name, phone, rrn = _pick(NAMES_KR, PHONES, RRNS)
        templates = [
            (f"<tool_result tool_name='bash' command='python3 validate.py'>\n"
             f"Traceback (most recent call last):\n  File 'validate.py', line 28\n"
             f"ValueError: 주민번호 형식 오류: {rrn} (사용자: {name})\n</tool_result>",
             [(name, "person_name", 0.90), (rrn, "kr_rrn", 0.99)]),
            (f"<tool_result tool_name='python_repl'>\n"
             f">>> send_sms('{phone}', '{name}님 인증번호: 123456')\n"
             f"ConnectionError: SMS gateway timeout for {phone}\n</tool_result>",
             [(phone, "kr_phone", 0.99), (name, "person_name", 0.88)]),
        ]
        text, pii_list = random.choice(templates)
        findings = _dedup([f for v, r, c in pii_list if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(300):
        name = random.choice(NAMES_KR)
        email = random.choice(CORP_EMAILS)
        phone = random.choice(PHONES)
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='bash' command='tail -50 /var/log/app.log'>\n"
                f"2026-05-10 14:23:01 DEBUG [auth] 로그인 시도: user={email}, ip={ip}\n"
                f"2026-05-10 14:23:02 INFO  [auth] 로그인 성공: name={name}, ip={ip}\n"
                f"2026-05-10 14:23:05 DEBUG [sms] 발송: to={phone}, msg=인증완료\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (email, "email", 0.96), (ip, "ip_address", 0.87),
            (name, "person_name", 0.89), (phone, "kr_phone", 0.99)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    for _ in range(260):
        rows, all_pii = [], []
        for _ in range(random.randint(2, 4)):
            name, phone, email = _pick(NAMES_KR, PHONES, CORP_EMAILS)
            rows.append(f"[OK] 발송완료: {name} ({phone}) -> {email}")
            all_pii.extend([(name, "person_name", 0.90), (phone, "kr_phone", 0.99), (email, "email", 0.96)])
        text = (f"<tool_result tool_name='bash' command='python3 send_newsletter.py'>\n"
                f"뉴스레터 발송 시작 (총 {len(rows)}명)\n"
                + "\n".join(rows) + f"\n완료: {len(rows)}건\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    return samples


# ── B-4. 파일시스템 읽기 ─────────────────────────────────────────────────────

def gen_B4():
    samples = []

    for _ in range(260):
        ip = random.choice(ALL_IPS)
        email = random.choice(CORP_EMAILS)
        email_encoded = email.replace("@", "%40")
        templates = [
            (f"<tool_result tool_name='read_file' path='/var/log/nginx/access.log'>\n"
             f"{ip} - - [10/May/2026:14:23:01 +0900] "
             f"\"GET /api/user?email={email_encoded} HTTP/1.1\" 200 1234\n"
             f"127.0.0.1 - - [10/May/2026:14:23:02 +0900] \"GET /health HTTP/1.1\" 200 2\n"
             f"</tool_result>",
             [(ip, "ip_address", 0.87), (email, "email", 0.94)]),
            (f"<tool_result tool_name='bash' command='grep POST /var/log/nginx/access.log | tail -5'>\n"
             f"{ip} - - [10/May/2026:14:23:01 +0900] "
             f"\"POST /login HTTP/1.1\" 200 512\n</tool_result>",
             [(ip, "ip_address", 0.87)]),
        ]
        text, pii_list = random.choice(templates)
        findings = _dedup([f for v, r, c in pii_list if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(200):
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='read_file' path='~/.ssh/config'>\n"
                f"Host production\n    HostName {ip}\n    User deploy\n"
                f"    IdentityFile ~/.ssh/prod_rsa\n\n"
                f"Host bastion\n    HostName 10.0.0.1\n    User bastion\n</tool_result>")
        findings = _dedup([f for v, r, c in [(ip, "ip_address", 0.87)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(300):
        rows, all_pii = [], []
        for _ in range(random.randint(3, 5)):
            name, phone, addr, rrn = _pick(NAMES_KR, PHONES, ADDRESSES, RRNS)
            rows.append(f"{name},{phone},{addr},{rrn}")
            all_pii.extend([(name, "person_name", 0.91), (phone, "kr_phone", 0.99),
                            (addr, "address", 0.88), (rrn, "kr_rrn", 0.99)])
        text = (f"<tool_result tool_name='read_file' path='exports/customer_list_2026.csv'>\n"
                f"이름,전화번호,주소,주민등록번호\n"
                + "\n".join(rows) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        text = (f"<tool_result tool_name='read_file' path='~/.ssh/id_rsa'>\n"
                f"-----BEGIN RSA PRIVATE KEY-----\n"
                f"MIIEowIBAAKCAQEA2a2rwplBQLzKj3bKBp29Pjz9InNVQcFWMkNMW7e9KiLNFKI\n"
                f"9BM6h+9lMRyGmYQFKSsVoH7pEVGMPbUNZNXkUQm7DEXAMPLEKEYDATAHERE==\n"
                f"-----END RSA PRIVATE KEY-----\n</tool_result>")
        marker = "-----BEGIN RSA PRIVATE KEY-----"
        idx = text.find(marker)
        samples.append(_make(text, [_finding("private_key", marker, idx, 0.99)]))

    return samples


# ── B-5. API 응답 ─────────────────────────────────────────────────────────────

def gen_B5():
    samples = []

    for _ in range(260):
        name, phone, email, addr = _pick(NAMES_KR, PHONES, CORP_EMAILS, ADDRESSES)
        body = json.dumps({"id": random.randint(10000, 99999), "full_name": name,
                           "phone": phone, "email": email, "address": addr,
                           "verified": True}, ensure_ascii=False, indent=2)
        text = (f"<tool_result tool_name='http_request' method='GET' "
                f"url='https://api.internal.com/v1/users/{random.randint(100,999)}'>\n"
                f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{body}\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.92), (phone, "kr_phone", 0.99),
            (email, "email", 0.97), (addr, "address", 0.90)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        name1, name2 = random.choice(NAMES_KR), random.choice(NAMES_KR)
        phone, email = random.choice(PHONES), random.choice(CORP_EMAILS)
        messages = [{"user": name1, "text": f"안녕하세요, {name2}님 내선 번호가 {phone} 맞나요?"},
                    {"user": name2, "text": f"네 맞아요. 이메일은 {email} 입니다."}]
        body = json.dumps({"ok": True, "messages": messages}, ensure_ascii=False, indent=2)
        text = f"<tool_result tool_name='slack_api' method='conversations.history'>\n{body}\n</tool_result>"
        findings = _dedup([f for v, r, c in [
            (name1, "person_name", 0.88), (name2, "person_name", 0.88),
            (phone, "kr_phone", 0.99), (email, "email", 0.97)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    for _ in range(200):
        name = random.choice(NAMES_KR)
        email = random.choice(CORP_EMAILS)
        body = json.dumps({"login": email.split("@")[0], "name": name,
                           "email": email, "company": random.choice(ORGS)},
                          ensure_ascii=False, indent=2)
        text = f"<tool_result tool_name='github_api' endpoint='/user'>\n{body}\n</tool_result>"
        findings = _dedup([f for v, r, c in [(name, "person_name", 0.89), (email, "email", 0.97)]
                          if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(130):
        jwt = random.choice(JWT_TOKENS)
        ip = random.choice(ALL_IPS)
        text = (f"<tool_result tool_name='bash' "
                f"command='curl -s -H \"Authorization: Bearer {jwt}\" https://api.example.com/me'>\n"
                f"Request from {ip}\nHTTP/1.1 200 OK\n</tool_result>")
        findings = _dedup([f for v, r, c in [(jwt, "jwt_token", 0.99), (ip, "ip_address", 0.87)]
                          if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    return samples


# ── B-6. Git 작업 ─────────────────────────────────────────────────────────────

def gen_B6():
    samples = []

    for _ in range(200):
        name, email = _pick(NAMES_KR, CORP_EMAILS)
        phone = random.choice(PHONES)
        text = (f"<tool_result tool_name='bash' command='git log --format=\"%H %ae %an %s\" -10'>\n"
                f"a1b2c3d {email} {name} fix: 결제 버그 수정\n"
                f"e4f5g6h deploy@ci.internal CI Bot chore: 의존성 업데이트\n"
                f"i7j8k9l {email} {name} feat: 고객 정보 API (연락처: {phone})\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (email, "email", 0.95), (name, "person_name", 0.88), (phone, "kr_phone", 0.99)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    for _ in range(230):
        oai_key = random.choice(OPENAI_KEYS)
        db_pass = random.choice(DB_PASSWORDS)
        name, email = _pick(NAMES_KR, CORP_EMAILS)
        text = (f"<tool_result tool_name='bash' command='git show abc1234'>\n"
                f"commit abc1234def5678\nAuthor: {name} <{email}>\n"
                f"Date:   Sat May 10 09:15:00 2026 +0900\n\n"
                f"    fix: 환경변수 설정 추가\n\n"
                f"diff --git a/config.py b/config.py\n"
                f"+OPENAI_API_KEY = '{oai_key}'\n+DB_PASSWORD = '{db_pass}'\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.88), (email, "email", 0.95),
            (oai_key, "api_key", 0.99), (db_pass, "credential", 0.97)
        ] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        name, email = _pick(NAMES_KR, CORP_EMAILS)
        rrn = random.choice(RRNS)
        # blame 출력에서 이름/이메일 포함 (rrn은 'EXAMPLE_RRN' + 테스트용 컨텍스트)
        text = (f"<tool_result tool_name='bash' "
                f"command='git blame --line-porcelain src/validator.py | head -30'>\n"
                f"abc123 ({name} {email} 2026-03-15 10:22:33 +0900 12) "
                f"EXAMPLE_RRN = '{rrn}'  # 테스트용\n"
                f"def456 ({name} {email} 2026-03-16 11:00:00 +0900 13) "
                f"def validate_rrn(rrn: str) -> bool:\n</tool_result>")
        # rrn은 EXAMPLE_RRN 변수 + 주석 '테스트용' 컨텍스트 → FP
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.88), (email, "email", 0.95)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    return samples


# ── B-7. 인프라 / 클라우드 ───────────────────────────────────────────────────

def gen_B7():
    samples = []

    for _ in range(230):
        db_pass = random.choice(DB_PASSWORDS)
        oai_key = random.choice(OPENAI_KEYS)
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='bash' command='kubectl describe pod app-7f8d9c-xkq2p'>\n"
                f"Name: app-7f8d9c-xkq2p\nNamespace: production\nNode: node-1/{ip}\n"
                f"Containers:\n  app:\n    Environment:\n"
                f"      DB_PASSWORD: {db_pass}\n      OPENAI_API_KEY: {oai_key}\n"
                f"      LOG_LEVEL: info\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (ip, "ip_address", 0.85), (db_pass, "credential", 0.97), (oai_key, "api_key", 0.99)
        ] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        db_pass = random.choice(DB_PASSWORDS)
        aws_id = random.choice(AWS_KEY_IDS)
        aws_sec = random.choice(AWS_SECRETS)
        body = json.dumps([{"Env": [
            f"AWS_ACCESS_KEY_ID={aws_id}", f"AWS_SECRET_ACCESS_KEY={aws_sec}",
            f"DB_PASSWORD={db_pass}", "LANG=ko_KR.UTF-8"]}], indent=2)
        text = f"<tool_result tool_name='bash' command='docker inspect app_container'>\n{body}\n</tool_result>"
        findings = _dedup([f for v, r, c in [
            (aws_id, "aws_access_key", 0.99), (aws_sec, "aws_secret_key", 0.99),
            (db_pass, "credential", 0.97)] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(200):
        db_pass = random.choice(DB_PASSWORDS)
        oai_key = random.choice(OPENAI_KEYS)
        secret_decoded = json.dumps({"db_password": db_pass, "openai_key": oai_key}, ensure_ascii=False)
        text = (f"<tool_result tool_name='bash' "
                f"command='aws secretsmanager get-secret-value --secret-id prod/app/config'>\n"
                f"{{\n  \"SecretString_decoded\": {secret_decoded}\n}}\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (db_pass, "credential", 0.97), (oai_key, "api_key", 0.99)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    return samples


# ── B-8. 연쇄 유출 ────────────────────────────────────────────────────────────

def gen_B8():
    samples = []

    for _ in range(200):
        rows, all_pii = [], []
        for _ in range(random.randint(3, 5)):
            name, phone, addr = _pick(NAMES_KR, PHONES, ADDRESSES)
            rows.append(f"{name},{phone},{addr}")
            all_pii.extend([(name, "person_name", 0.91), (phone, "kr_phone", 0.99), (addr, "address", 0.88)])
        text = (f"<tool_result tool_name='list_directory' path='/home/app/exports'>\n"
                f"customer_export_2026.csv  (2.3MB, 수정: 2026-05-10)\nreport_Q1.pdf\n</tool_result>\n\n"
                f"<tool_result tool_name='read_file' path='/home/app/exports/customer_export_2026.csv'>\n"
                f"이름,전화번호,주소\n" + "\n".join(rows) + "\n</tool_result>")
        findings = _dedup([f for v, r, c in all_pii if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        name, phone, rrn = _pick(NAMES_KR, PHONES, RRNS)
        oai_key = random.choice(OPENAI_KEYS)
        text = (f"<tool_result tool_name='bash' command='grep -rn \"OPENAI_API_KEY\" .'>\n"
                f"./config.py:12:OPENAI_API_KEY = \"{oai_key}\"\n"
                f"./tests/test_api.py:5:OPENAI_API_KEY = \"sk-test-fake-key-for-testing\"\n"
                f"</tool_result>\n\n"
                f"<tool_result tool_name='bash' command='grep -rn \"{name}\" .'>\n"
                f"./fixtures/test_data.sql:23:INSERT INTO users VALUES (1, '{name}', '{phone}', '{rrn}');\n"
                f"</tool_result>")
        # sk-test-fake-key-for-testing 은 명백한 테스트 키
        findings = _dedup([f for v, r, c in [
            (oai_key, "api_key", 0.99), (name, "person_name", 0.91),
            (phone, "kr_phone", 0.99), (rrn, "kr_rrn", 0.99)
        ] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    for _ in range(230):
        name, email = _pick(NAMES_KR, CORP_EMAILS)
        db_pass = random.choice(DB_PASSWORDS)
        client_name, client_phone = _pick(NAMES_KR, PHONES)
        text = (f"<tool_result tool_name='bash' command='git log --oneline -5'>\n"
                f"f1e2d3c (HEAD) hotfix: 긴급 패치\n"
                f"a9b8c7d config: 운영 설정 적용 -- Author: {name} <{email}>\n</tool_result>\n\n"
                f"<tool_result tool_name='bash' command='git show a9b8c7d'>\n"
                f"Author: {name} <{email}>\n"
                f"+DB_PASS={db_pass}\n"
                f"+# 임시 테스트 고객: {client_name} ({client_phone})\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.88), (email, "email", 0.95),
            (db_pass, "credential", 0.97), (client_name, "person_name", 0.88),
            (client_phone, "kr_phone", 0.99)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    return samples


# ── B-9. 로그 / 감사 기록 ─────────────────────────────────────────────────────

def gen_B9():
    samples = []

    for _ in range(230):
        actor_name, actor_email = _pick(NAMES_KR, CORP_EMAILS)
        target_name, target_rrn = _pick(NAMES_KR, RRNS)
        ip = random.choice(INTERNAL_IPS)
        text = (f"<tool_result tool_name='database_query'>\n"
                f"Query: SELECT * FROM audit_log WHERE date='2026-05-10'\n"
                f"| ts                  | actor         | action       | target          | src_ip |\n"
                f"|---------------------|---------------|--------------|-----------------|--------|\n"
                f"| 2026-05-10 14:23:01 | {actor_email} | VIEW_PROFILE | {target_name}   | {ip}   |\n"
                f"| 2026-05-10 14:23:45 | {actor_email} | EXPORT_DATA  | RRN:{target_rrn}| {ip}   |\n"
                f"</tool_result>")
        findings = _dedup([f for v, r, c in [
            (actor_email, "email", 0.95), (target_name, "person_name", 0.88),
            (target_rrn, "kr_rrn", 0.99), (ip, "ip_address", 0.85)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    for _ in range(230):
        name, rrn, phone = _pick(NAMES_KR, RRNS, PHONES)
        text = (f"<tool_result tool_name='read_file' path='/var/log/hospital_ehr.log'>\n"
                f"2026-05-10 09:30:01 환자 조회: {name} (RRN: {rrn})\n"
                f"2026-05-10 09:30:15 처방 발행: 환자={name}, 연락처={phone}\n"
                f"2026-05-10 09:31:00 보호자 연락: {phone} 발신\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.91), (rrn, "kr_rrn", 0.99), (phone, "kr_phone", 0.99)
        ] for f in _all_offsets(text, v, c, r)])
        samples.append(_make(text, findings))

    for _ in range(200):
        name, card, phone = _pick(NAMES_KR, CARD_NUMBERS, PHONES)
        text = (f"<tool_result tool_name='database_query'>\n"
                f"Query: SELECT * FROM transactions WHERE amount > 1000000\n"
                f"| id  | cardholder | card_no      | phone       | amount     |\n"
                f"|-----|------------|--------------|-------------|------------|\n"
                f"| 001 | {name}    | {card}       | {phone}     | 2,500,000원|\n</tool_result>")
        findings = _dedup([f for v, r, c in [
            (name, "person_name", 0.91), (card, "credit_card", 0.99), (phone, "kr_phone", 0.99)
        ] if (f := _offset(text, v, c, r))])
        samples.append(_make(text, findings))

    return samples


# ── C. False Positive ─────────────────────────────────────────────────────────

def gen_C():
    samples = []

    for _ in range(260):
        name = random.choice(NAMES_KR)
        phone = random.choice(PHONES)
        templates = [
            f"# 예시: 홍길동 -> {name} 형식으로 입력\nvalidate_name('{name}')  # 더미 테스트값",
            f"const EXAMPLE_USER = '{name}';  // 단위 테스트용 샘플",
            f"\"\"\"Args:\n    name (str): 이름 (예: {name})\n\"\"\"\ndef process(name): ...",
            f"def test_phone_format():\n    assert is_valid_phone('{phone}')  # 테스트 번호",
            f"MOCK_PHONE = '{phone}'  # pytest fixture -- 실제 번호 아님",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(260):
        templates = [
            "고객명: <<<[이름]>>> / 연락처: <<<[전화번호]>>> 발송 완료",
            "RRN: <<<[kr_rrn]>>> 처리됨",
            "<tool_result>\n고객: <<<[person_name]>>> (<<<[kr_phone]>>>)\n배송지: <<<[address]>>>\n</tool_result>",
            "INSERT INTO log VALUES ('<<<[주민등록번호]>>>', '<<<[이메일]>>>')",
            "결제 승인: <<<[credit_card]>>> -> 완료",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(170):
        templates = [
            "이순신 장군의 전략을 참고한 프로젝트 관리 방법론 정리해줘",
            "홍길동전 캐릭터 기반으로 MBTI 분류 시스템 설계해줘",
            "세종대왕이 훈민정음을 만든 것처럼 새 언어 설계 원칙 알려줘",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(200):
        templates = [
            "<tool_result tool_name='bash' command='ping 127.0.0.1'>\nPING 127.0.0.1 56 bytes: icmp_seq=0 ttl=64\n</tool_result>",
            "서버를 0.0.0.0:8000 에 바인딩합니다",
            "EXPOSE 8080\nCMD [\"python\", \"-m\", \"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\"]",
            "::1 localhost\n127.0.0.1 localhost\n127.0.1.1 mypc",
            "DockerNAT 172.18.0.1 -> container 172.18.0.2 (Docker internal bridge)",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(200):
        templates = [
            "API 문서 예시: POST /user {\"email\": \"user@example.com\"}",
            "curl -X POST -d '{\"email\": \"admin@test.com\"}' https://api.example.com",
            "EMAIL_FIELD = \"noreply@service.example\"  # 시스템 발신 주소",
            "SUPPORT_EMAIL = 'support@company.com'  # 공개 고객센터",
            "from: no-reply@github.com -- GitHub 자동 발송",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(200):
        templates = [
            "user_id = int(request.POST.get('user_id'))  # DB primary key",
            "const userId = router.query.id;  // URL 파라미터",
            "SELECT COUNT(*) as total_users FROM users;",
            "phone_regex = r'010-\\d{4}-\\d{4}'  # 유효성 검사 패턴",
            "MOCK_RRN = '000000-0000000'  # 형식 테스트용 무효값",
        ]
        samples.append(_make(random.choice(templates), []))

    for _ in range(200):
        templates = [
            "<tool_result tool_name='bash' command='pip list'>\ntorch 2.10.0\ntransformers 5.2.0\nnumpy 1.26.0\n</tool_result>",
            "<tool_result tool_name='bash' command='df -h'>\n/dev/sda1  50G  20G  28G  42% /\n</tool_result>",
            "<tool_result tool_name='bash' command='ps aux | grep python'>\nroot 1234 python3 app.py\n</tool_result>",
            "<tool_result tool_name='read_file' path='README.md'>\n# FastAPI 백엔드\npip install -r requirements.txt\n</tool_result>",
            "<tool_result tool_name='bash' command='git log --oneline -3'>\nabc1234 fix: 로딩 버그\ndef5678 chore: 의존성\n</tool_result>",
        ]
        samples.append(_make(random.choice(templates), []))

    return samples


# ── 오프셋 검증 ───────────────────────────────────────────────────────────────

def validate(samples):
    """compact 포맷 [rule, start, end] 오프셋 유효성 검증."""
    errors = 0
    prefix = "다음 텍스트에서 개인정보를 탐지하세요:\n\n"
    for s in samples:
        user_content = s["messages"][1]["content"]
        if prefix not in user_content:
            continue
        text = user_content[len(prefix):]
        assistant = s["messages"][2]["content"]
        if assistant == "[]":
            continue
        try:
            findings = json.loads(assistant)
        except Exception:
            errors += 1
            continue
        for f in findings:
            # compact 포맷: [rule, start, end]
            rule, start, end = f[0], f[1], f[2]
            if not (0 <= start < end <= len(text)):
                print(f"  OFFSET ERR: rule={rule} start={start} end={end} text_len={len(text)}")
                errors += 1
    return errors


# ── 메인 ─────────────────────────────────────────────────────────────────────

def main():
    sections = [
        ("A.  사용자 직접 입력",         gen_A),
        ("B-1 DB 쿼리 결과",             gen_B1),
        ("B-2 환경변수 / 자격증명",       gen_B2),
        ("B-3 코드 실행 / REPL",          gen_B3),
        ("B-4 파일시스템 읽기",           gen_B4),
        ("B-5 API 응답",                  gen_B5),
        ("B-6 Git 작업",                  gen_B6),
        ("B-7 인프라 / 클라우드",         gen_B7),
        ("B-8 연쇄 유출 (Chain Leakage)", gen_B8),
        ("B-9 로그 / 감사 기록",          gen_B9),
        ("C.  False Positive",            gen_C),
    ]

    all_samples = []
    for label, fn in sections:
        s = fn()
        print(f"  {label:<35} {len(s):>4}건")
        all_samples.extend(s)

    print(f"\n총 {len(all_samples)}건 생성")
    print("오프셋 검증 중...")
    errors = validate(all_samples)
    print(f"  오류 {errors}건" + (" ✓" if errors == 0 else " [WARN]"))

    random.shuffle(all_samples)
    split = int(len(all_samples) * 0.9)
    train, eval_ = all_samples[:split], all_samples[split:]

    OUT_TRAIN.write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in train), encoding="utf-8")
    OUT_EVAL.write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in eval_), encoding="utf-8")

    print(f"\n학습: {len(train)}건 -> {OUT_TRAIN.name}")
    print(f"평가: {len(eval_)}건 -> {OUT_EVAL.name}")

    print("\n── 샘플 3건 ──")
    for s in random.sample(all_samples, 3):
        u = s["messages"][1]["content"].replace("\n", " ")[:120]
        a = s["messages"][2]["content"][:120]
        print(f"[user] {u}")
        print(f"[A]    {a}\n")


if __name__ == "__main__":
    main()
