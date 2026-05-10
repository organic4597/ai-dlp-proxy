# SLM 파인튜닝 데이터 생성 계획 — MCP/Agent 도구 실행 기반 PII 유출 위협 분석

## 1. 핵심 위협 모델

### 왜 Agent tool_result가 위험한가?

```
사용자 프롬프트 (PII 적음)
        ↓
 [Agent Planning]
        ↓
 tool_call: bash("cat /home/app/exports/customers.csv")
        ↓
 tool_result: [이름,전화번호,주소,주민번호 3만 건]
        ↓
 ← LLM 컨텍스트에 전체 삽입 ← ← ← ← ← ← ←
        ↓
 [DLP 프록시가 없으면 그대로 외부 LLM API로 전송됨]
```

**핵심 포인트**: 사용자가 의도하지 않아도 Agent가 수집한 데이터가 LLM 컨텍스트(= 프롬프트)에 삽입되면 외부로 유출된다. Regex는 이미 잘 잡는다. SLM의 역할은 **문맥 기반 판단**이다.

---

## 2. 위협 시나리오 심층 분석

### 2.1 파일시스템 도구 (read_file, list_directory)

**유출 경로:**
```
Agent: "프로젝트 파일 구조 파악해줘"
  → list_directory("/home/app")
  → 결과: customer_export_2026.csv, backup.sql, .env, id_rsa ...
  → Agent: read_file("customer_export_2026.csv")
  → 3만 명 고객 데이터 LLM 컨텍스트 삽입
```

**실제 유출 데이터 유형:**
- `.env` 파일: DB 비밀번호, API 키, Secret Key
- `*.csv`, `*.xlsx`: 고객 명단, 주문 기록
- `backup/dump.sql`: INSERT 구문에 실제 고객 데이터
- `~/.ssh/id_rsa`: 개인키 (-----BEGIN RSA PRIVATE KEY-----)
- `~/.ssh/config`: 서버 호스트, 사용자명, IP
- `config.yaml`, `settings.json`: DB 접속 정보
- `/var/log/*.log`: 이름, 이메일, IP, 주민번호가 포함된 로그

**SLM 판단 포인트:**
```
read_file(".env")  → DB_PASSWORD=P@ssw0rd!2024  →  TP (자격증명)
read_file("README.md")  → "pip install ..."  →  FP (개발 문서)
read_file("test_fixtures.json")  → "name": "test_user"  →  FP (테스트 데이터)
```

---

### 2.2 셸 실행 (bash, shell_exec)

**유출 경로:**
```
Agent: "서버 상태 확인해줘"
  → bash("env")          ← AWS_ACCESS_KEY_ID, DB_PASSWORD 전체 덤프
  → bash("ps aux")       ← 실행 중인 프로세스 + 사용자명
  → bash("who")          ← 접속 중인 사용자 + IP
  → bash("cat /etc/passwd")  ← 시스템 계정 목록 + 실명
  → bash("history")      ← 과거 명령어 (파라미터에 비밀번호 포함 가능)
```

**고위험 명령어 패턴:**
| 명령어 | 유출 내용 |
|--------|-----------|
| `env` / `printenv` | API 키, DB 비밀번호, 토큰 전부 |
| `cat ~/.bashrc` | export 구문에 자격증명 |
| `ps auxef` | 프로세스 args에 비밀번호 가능 |
| `netstat -an` | 내부 IP, 포트, 연결 상태 |
| `last -50` | 접속 로그 (사용자 + IP + 시간) |
| `grep -r "password" .` | 코드에서 하드코딩된 비번 발굴 |
| `tail -f /var/log/app.log` | 실시간 사용자 활동 (이름, 이메일, 폰) |

**SLM 판단 포인트:**
```
env 결과: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  →  TP (API 키)
env 결과: HOME=/root, PATH=/usr/bin  →  FP (시스템 변수)
ps 결과: root 1234 python3 app.py  →  FP (프로세스, 개인정보 아님)
```

---

### 2.3 데이터베이스 쿼리 (database_query, sql_execute)

**유출 경로:**
```
Agent: "고객 불만 원인 분석해줘"
  → database_query("SELECT * FROM customer_complaints LIMIT 100")
  → 결과: 이름, 전화번호, 주소, 주민번호 100행
  → Agent: 분석 결과를 외부 LLM에게 전송
```

**고위험 쿼리 패턴:**
```sql
-- 직접 유출
SELECT * FROM customers;
SELECT name, phone, rrn FROM users WHERE status='active';

-- JOIN 으로 연결 → 더 많은 정보
SELECT c.name, c.phone, o.address, p.card_number
FROM customers c JOIN orders o JOIN payments p;

-- 덤프 파일 읽기
-- backup.sql: INSERT INTO customers VALUES ('홍길동', '010-1234-5678', ...);

-- 감사 로그 — 누가 언제 어떤 데이터 접근했는지
SELECT * FROM audit_log WHERE action='EXPORT';
```

**혼합 데이터 (SLM 핵심 판단 케이스):**
```
쿼리 결과 10행 중:
  8행: test_user, sample@example.com  → FP
  2행: 홍길동, 010-1234-5678, jkim@kakaobank.com  → TP
```
→ SLM은 테스트 행은 무시하고 실제 데이터만 탐지해야 함

---

### 2.4 API 호출 결과 (http_request, api_call)

**내부 API (가장 위험):**
```json
// GET /api/users/1234 → 응답
{
  "full_name": "김철수",
  "phone": "010-1234-5678",
  "rrn": "880515-1104333",
  "address": "서울시 강남구 테헤란로 123"
}
```

**외부 SaaS API:**

| API | 유출 데이터 |
|-----|-----------|
| Slack `conversations.history` | 메시지에 언급된 이름, 전화번호, 이메일 |
| GitHub `/user` | 이름, 이메일, 소속 회사, 주소 |
| Google People API | 연락처 전체 (이름, 폰, 이메일, 주소) |
| Stripe `customers.list` | 청구 이름, 이메일, 카드 last4, 주소 |
| HubSpot CRM | 영업 대상 고객 연락처 전체 |
| Notion API | 페이지 내용에 포함된 회의록, 고객 정보 |

**JWT 토큰 노출:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
→ 디코딩하면 sub, name, email 포함 가능
→ 토큰 자체도 자격증명
```

---

### 2.5 Git 작업 (git log, git show, git blame)

**유출 시나리오:**
```bash
# 1. 커밋 작성자 이메일 + 이름 노출
git log --format="%ae %an" → jkim@kakaobank.com 김철수

# 2. 실수로 커밋된 자격증명
git show abc1234
+OPENAI_API_KEY = 'sk-proj-abc123...'
+DB_PASSWORD = 'Prod#Secret789'

# 3. 코드에 실제 테스트 데이터 (이름, 주민번호)
git blame src/validator.py
→ 홍길동 <hong@company.com> ... test_rrn = '880515-1104333'

# 4. PR 설명에 실제 고객 데이터 포함
git log --format="%B" → "Fix: 홍길동(010-1234-5678) 결제 오류 수정"
```

**SLM 판단 포인트:**
```
git blame → EXAMPLE_RRN = '880515-1104333'  # 테스트용 → FP (변수명+주석으로 판단)
git blame → user.rrn = '880515-1104333'  # 운영 데이터 → TP
git log → Author: 김철수 <jkim@kakaobank.com> → TP (실제 기여자)
git log → Author: CI Bot <ci@github.com> → FP (시스템 계정)
```

---

### 2.6 인프라 / 클라우드 도구

**Kubernetes:**
```bash
# 시크릿 덤프 (base64 인코딩)
kubectl get secret app-secrets -o yaml
→ data:
    db-password: UEBzc3cwcmQhMjAyNA==  (base64)
    openai-key:  c2stcHJvai1hYmMxMjM=  (base64)

# base64 디코딩하면 바로 평문
echo UEBzc3cwcmQhMjAyNA== | base64 -d → P@ssw0rd!2024

# Pod 환경변수에 시크릿
kubectl describe pod → DB_PASSWORD: P@ssw0rd!2024
```

**Docker:**
```bash
docker inspect app_container
→ "Env": [
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG...",
    "DB_PASSWORD=Prod#Secret789"
  ]
```

**AWS CLI:**
```bash
aws secretsmanager get-secret-value --secret-id prod/app/config
→ {"SecretString": "{\"db_password\":\"Prod#Secret789\",\"openai_key\":\"sk-proj-...\"}"}

aws iam get-user
→ {"User": {"UserName": "jkim", "Arn": "arn:aws:iam::123456789012:user/jkim"}}
```

---

### 2.7 코드 실행 / REPL 출력

**pandas/numpy 데이터 출력:**
```python
>>> df = pd.read_csv('customers.csv')
>>> df.head(10)
   이름      전화번호         주소                주민번호
0  홍길동  010-1234-5678  서울시 강남구...  880515-1104333
1  김철수  010-9876-5432  부산시 해운대...  950720-2218199
...
```

**에러 메시지에 PII 포함:**
```python
ValueError: Invalid RRN for 홍길동: 880515-1104333
KeyError: 'email' not found for user 010-1234-5678
SMTPException: Cannot send to jkim@kakaobank.com: Invalid domain
```

**디버그 로거 출력:**
```python
logger.debug(f"Processing user {user.name} ({user.email})")
logger.info(f"SMS sent to {user.phone}")
# → 로그 파일 전체 tail 하면 수백명 정보 노출
```

---

### 2.8 연쇄 유출 (Chain Leakage) — 가장 과소평가된 위협

**시나리오 1: 파일 탐색 → 읽기 → 덤프**
```
Agent: "배포 준비 도와줘"
  Step 1: list_directory("/home/app") → customer_export_2026.csv 발견
  Step 2: read_file("customer_export_2026.csv") → 전체 고객 덤프
  Step 3: 이 내용 전체가 다음 LLM 호출에 컨텍스트로 포함됨
```

**시나리오 2: grep → 코드 분석 → 자격증명 발굴**
```
Agent: "API 키 사용 현황 파악해줘"
  Step 1: bash("grep -rn 'API_KEY' .") → config.py:12:OPENAI_API_KEY='sk-proj-...'
  Step 2: read_file("config.py") → 파일 전체 (다른 자격증명도 포함)
  Step 3: bash("git log config.py") → 커밋 히스토리에서 이전 키도 노출
```

**시나리오 3: DB 연결 정보 발굴 → 직접 쿼리**
```
Agent: "DB 스키마 파악해줘"
  Step 1: read_file(".env") → DB_HOST=192.168.1.100, DB_PASSWORD=...
  Step 2: database_query("SHOW TABLES") → 테이블 목록
  Step 3: database_query("SELECT * FROM customers LIMIT 5") → 고객 5명 정보
```

---

## 3. SLM 핵심 판단 케이스 (FP vs TP 경계)

| 텍스트 | 판단 | 이유 |
|--------|------|------|
| `"name": "test_user"` | FP | "test_" 접두사 → 테스트 데이터 |
| `"name": "홍길동"` in DB 쿼리 결과 | TP | 실제 DB 응답 |
| `EXAMPLE_RRN = '880515-1104333'  # 테스트용` | FP | 변수명 + 주석이 테스트임을 명시 |
| `INSERT INTO users VALUES (..., '880515-1104333', ...)` | TP | 실제 DB dump |
| `email: "admin@example.com"` | FP | example.com = 공개 테스트 도메인 |
| `email: "jkim@kakaobank.com"` | TP | 실제 금융기관 이메일 |
| `password: "****"` | FP | 이미 마스킹됨 |
| `password: "P@ssw0rd!2024"` in .env | TP | 평문 자격증명 |
| `Bearer sk-test-fake-key-for-testing` | FP | 명백한 테스트 키 |
| `Bearer sk-proj-abc123def456ghi789` | TP | 실제 OpenAI 키 형식 |
| `127.0.0.1` | FP | localhost, 개인정보 아님 |
| `192.168.1.100` in kubectl describe | TP | 내부 서버 실제 IP |
| `0.0.0.0:8080` | FP | 바인딩 주소, 개인정보 아님 |
| `curl -H "Authorization: Bearer eyJhbGci..."` | TP | JWT 토큰 자격증명 |
| `git log → CI Bot <ci@github.com>` | FP | 시스템 계정 |
| `git log → 김철수 <jkim@kakaobank.com>` | TP | 실제 기여자 |
| `test_data.sql: EXAMPLE_USER = '홍길동'` | FP | 픽스처 데이터 |
| `backup_2026.sql: INSERT INTO customers ('홍길동'...)` | TP | 운영 DB 덤프 |
| `<<<[person_name]>>>` | FP | DLP가 이미 마스킹 |
| `base64 디코딩된 DB 비밀번호` | TP | 자격증명 (인코딩 방식 무관) |

---

## 4. 데이터셋 구성 (3,000건)

| 카테고리 | 건수 | 비중 | 핵심 학습 목표 |
|----------|------|------|---------------|
| A. 사용자 직접 입력 | 150 | 5% | 에러 메시지 PII, 자연어 이름 |
| B-1. DB 쿼리 결과 | 400 | 13% | 혼합 데이터, SQL dump |
| B-2. 환경변수/자격증명 | 300 | 10% | env, .env, k8s, docker |
| B-3. 코드 실행/REPL | 350 | 12% | pandas, traceback, logger |
| B-4. 파일시스템 읽기 | 300 | 10% | CSV, 로그, SSH 설정 |
| B-5. API 응답 | 250 | 8% | 내부/외부 API, JWT |
| B-6. Git 작업 | 200 | 7% | blame, show, log |
| B-7. 인프라/클라우드 | 200 | 7% | kubectl, docker, AWS |
| B-8. 연쇄 유출 | 200 | 7% | multi-step tool chain |
| B-9. 로그/감사 기록 | 200 | 7% | audit log, 의료/금융 |
| C. False Positive | 450 | 15% | 테스트 데이터, 마스킹, 공개정보 |
| **합계** | **3,000** | **100%** | |

**분할:** train 2,700건 / eval 300건 (9:1)

---

## 5. 구현 현황

- `tests/build_slm_dataset.py` — 데이터셋 생성기 v2 (완료)
- `tests/slm_train_dataset.jsonl` — 2,700건 (재생성 완료)
- `tests/slm_eval_dataset.jsonl` — 300건 (재생성 완료)
- `scripts/train_dlp_slm.py` — 학습 스크립트 (Qwen3.5-4B, LoRA/QLoRA)

**원격 서버 (192.168.1.18) 디렉터리:**
```
/qwen_tunning/
├── data/
│   ├── slm_train_dataset.jsonl  ← 재전송 필요
│   └── slm_eval_dataset.jsonl   ← 재전송 필요
└── scripts/
    ├── train_dlp_slm.py
    └── run_train.sh
```

---

## 6. 학습 후 기대 효과

| 시나리오 | Regex | ML | SLM (파인튜닝 후) |
|----------|-------|----|------------------|
| `env` 덤프 — AWS 키 | ✅ | ✅ | ✅ |
| DB 쿼리 결과 — 고객 이름 | ❌ | ❌ | ✅ |
| 혼합 결과 — 일부만 실제 PII | ❌ | ❌ | ✅ |
| git blame — 기여자 이메일 | ✅ | △ | ✅ |
| `EXAMPLE_RRN = '...'` 테스트 상수 | ❌ (FP 발생) | ❌ | ✅ (FP 억제) |
| k8s secret base64 | ❌ | ❌ | ✅ |
| 연쇄 도구 호출 후 PII 누적 | ❌ | ❌ | ✅ |
| test_user, example.com 필터 | ❌ (FP) | △ | ✅ (FP 억제) |
