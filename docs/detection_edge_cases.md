# ai-dlp-proxy 탐지 엣지케이스 분석

> **테스트 환경**: gemma-4-2b-it-q4_k_m.gguf · CPU only · llama-cpp-python v0.3.20  
> **Regex 규칙 수**: 12개  
> **작성일**: 2026-04-15  
> **데이터 출처**: `detection_edge_cases.json` (전 항목 실측 기반)

---

## 목차

1. [미탐 (False Negative) — 10건](#1-미탐-false-negative--10건)
2. [오탐 (False Positive) — 10건](#2-오탐-false-positive--10건)
3. [Regex 단독 한계 — 10건](#3-regex-단독-한계--10건)
4. [SLM 단독 한계 — 10건](#4-slm-단독-한계--10건)
5. [요약 및 시사점](#5-요약-및-시사점)

---

## 1. 미탐 (False Negative) — 10건

감지되어야 하는데 **Regex + SLM 파이프라인 모두**에서 감지가 안 된 케이스.

| ID | 카테고리 | 설명 | 실패 원인 요약 |
|---|---|---|---|
| FN-01 | 주민등록번호 | 앞자리 내부 공백 삽입 | 패턴이 앞-뒷자리 사이 구분자만 허용 |
| FN-02 | 주민등록번호 | 자연어로 분산 서술 | 연속된 13자리 아니면 매칭 불가 |
| FN-03 | 신용카드 | 한글 발음으로 서술 | 숫자 없어 regex 불가, SLM도 미탐 |
| FN-04 | 전화번호 | 한글 발음으로 서술 | 숫자 없어 regex 불가, SLM도 미탐 |
| FN-05 | API 키 | 값만 단독 노출 (할당문 없음) | `key=value` 형식 요구, SLM도 미탐 |
| FN-06 | PEM Private Key | SLM 단독 사용 시 | SLM 분류 범주에 private key 없음 |
| FN-07 | 여권번호 | 소문자 입력 | 패턴이 `[A-Z]` 대문자만 허용 |
| FN-08 | GitHub 토큰 | Fine-grained PAT 형식 | `github_pat_` 접두어 패턴 미포함 |
| FN-09 | 신용카드 | 점(.) 구분자 사용 | 구분자 `[-\s]?`가 점 허용 안 함 |
| FN-10 | 사업자등록번호 | 규칙 자체 미정의 | RULES에 패턴 없음 |

### 상세

#### FN-01 · 주민등록번호 앞자리 내부 공백

```
입력: "주민 번호는 90 12 15 - 1 23 45 67 이에요."
기대: detected=true, rule=kr_rrn
실제: detected=false
```

`kr_rrn` 패턴의 `[-\s]?`는 앞자리(6자리)와 뒷자리(7자리) 사이의 구분자만 허용한다. 앞자리 내부(`90 12 15`)에 삽입된 공백은 처리하지 못한다.

---

#### FN-02 · 자연어 분산 서술 주민번호

```
입력: "저는 1990년 12월 15일생이고 뒷번호는 1234567로 등록되어 있어요."
기대: detected=true, rule=kr_rrn
실제: detected=false  (SLM 단독은 date_of_birth로 탐지 성공)
```

Regex는 연속된 `YYMMDD-NNNNNNN` 패턴을 요구한다. 앞자리와 뒷자리가 문장 내에서 분리되면 단일 패턴으로 포착할 수 없다. SLM 단독 테스트에서는 `date_of_birth`로 탐지에 성공했으나 규칙 레이블 정확도가 낮다.

---

#### FN-03 · 신용카드 한글 발음 서술

```
입력: "제 카드 앞 네 자리는 사오삼이이고 나머지는 천오백 두 자리씩 이어요."
기대: detected=true, rule=credit_card
실제: detected=false  (SLM 응답시간 1,379ms — 사실상 추론 미실행)
```

숫자가 전혀 없어 regex 매칭이 불가하다. SLM도 1,379ms(정상 추론 시 15,000~36,000ms) 응답으로 즉시 빈 배열을 반환했다. 한글 발음→아라비아 숫자 변환 추론은 2B 파라미터 한계 이상이다.

---

#### FN-04 · 전화번호 한글 발음 서술

```
입력: "제 전화는 공일공에 일이삼사에 오육칠팔 입니다."
기대: detected=true, rule=kr_phone
실제: detected=false  (SLM 33,888ms 추론 후 미탐)
```

SLM이 충분한 시간(33초)을 추론했음에도 `공=0, 일=1` 매핑을 PII 탐지로 연결하지 못했다.

---

#### FN-05 · API 키 값 단독 노출

```
입력: "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef"
기대: detected=true, rule=api_key_assignment
실제: detected=false  (SLM 1,676ms — 즉시 반환)
```

`api_key_assignment` 패턴은 `api_key = <value>` 형식의 할당문을 요구한다. 값만 단독으로 전송하면 regex도, SLM도 모두 탐지에 실패한다. `sk-`, `sk-proj-` 접두어 기반 별도 패턴이 없는 것이 근본 원인이다.

---

#### FN-06 · PEM Private Key (SLM 단독 사용 시)

```
입력: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3...\n-----END RSA PRIVATE KEY-----"
기대: detected=true, rule=pem_private_key
실제(SLM): detected=false  (1,866ms — 즉시 반환)
```

**Regex는 정확히 탐지한다.** SLM 단독으로만 운용하는 경우에만 미탐이 발생한다. SLM의 분류 범주(person_name, address, account_number 등)에 private key가 명시되어 있지 않아 분류 자체가 실패한다.

---

#### FN-07 · 소문자 여권번호

```
입력: "여권번호: m12345678"
기대: detected=true, rule=kr_passport
실제: detected=false
```

`kr_passport` 패턴 `[A-Z]{1,2}\d{7,8}`이 대문자만 허용한다. `re.IGNORECASE` 플래그 또는 `[A-Za-z]` 클래스로 수정하면 해결된다.

---

#### FN-08 · GitHub Fine-grained PAT

```
입력: "GitHub 토큰: github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
기대: detected=true, rule=github_pat
실제: detected=false
```

`github_pat` 패턴이 Classic PAT 접두어(ghp_, gho_, ghu_, ghs_, ghr_)만 포함한다. 2022년 도입된 Fine-grained PAT(`github_pat_` 형식)는 커버하지 않는다.

---

#### FN-09 · 점(.) 구분자 신용카드

```
입력: "카드번호: 4532.0151.1283.0366"
기대: detected=true, rule=credit_card
실제: detected=false
```

`credit_card` 패턴의 구분자가 `[-\s]?`로 하이픈과 공백만 허용한다. 점(.), 슬래시(/), 콤마(,) 등 다른 구분자를 사용하면 미탐이 발생한다.

---

#### FN-10 · 사업자등록번호

```
입력: "사업자번호: 123-45-67890"
기대: detected=true, rule=kr_business_reg
실제: detected=false
```

한국 사업자등록번호(3-2-5 자릿수, 10자리) 패턴 자체가 RULES에 정의되어 있지 않다. `us_ssn` 패턴(`\d{3}-\d{2}-\d{4}`)과 자릿수가 달라 오탐도 발생하지 않는다.

---

## 2. 오탐 (False Positive) — 10건

감지가 안 되어야 하는데 **Regex에서 감지가 된** 케이스. 전 항목 실측 기반.

| ID | 카테고리 | 오탐 입력 | 탐지된 Rule | 원인 요약 |
|---|---|---|---|---|
| FP-01 | 신용카드 | 제품 시리얼 번호 | `credit_card` | Luhn 우연 통과 |
| FP-02 | 패스워드 | 환경변수 참조 `${VAULT_SECRET}` | `password_assignment`* | 참조값을 실제 패스워드로 오인 |
| FP-03 | 패스워드 | `reset_password_url=https://...` | `password_assignment`* | password_ 접두어 필드 과탐 |
| FP-04 | AWS Access Key | `AKIA` 접두어 내부 코드 | `aws_access_key` | 접두어 기반 탐지, 체크섬 없음 |
| FP-05 | GitHub PAT | `ghp_` 접두어 내부 식별자 | `github_pat` | 접두어+길이 기반, 유효성 미검증 |
| FP-06 | 여권번호 | `AB1234567` 제품코드 | `kr_passport` | 영문+숫자 조합 과탐 |
| FP-07 | 운전면허번호 | `12-34-567890-12` 관리코드 | `kr_driver_license` | 지역코드 검증 없음 |
| FP-08 | 신용카드 | 은행 계좌번호 | `credit_card` | 14자리 하이픈 구분 숫자 과탐 |
| FP-09 | JWT 토큰 | 문서 예제에 삽입된 공개 JWT | `jwt_token` | 서명 검증 없어 유효/무효 구분 불가 |
| FP-10 | 전화번호 | `010` 접두어 포트 번호 | `kr_phone` | 구분자 없는 연속 숫자도 탐지 |

> \* `password_assignment`는 현재 미구현 패턴. 기본 형식: `(?i)(?:password|passwd|pwd)\s*[=:]\s*\S+`  
> 복잡한 판단(환경변수 참조 여부, 힌트 vs 실제값)은 SLM 또는 추후 구현할 regex 파이프라인에서 처리 필요.

### 상세

#### FP-01 · 시리얼 번호 Luhn 통과

```
입력: "제품 시리얼: 4532015112830366"
탐지: rule=credit_card, match="4532015112830366"
```

Luhn 알고리즘만으로는 카드번호와 우연히 동일한 체크섬을 가진 시리얼 번호를 구분할 수 없다. 컨텍스트 키워드("시리얼") 활용 로직이 없어 오탐이 발생한다.

---

#### FP-02 · 환경변수 참조 패스워드 오탐

```
입력: "설정: DB_PASSWORD=${VAULT_SECRET_DB_PASS}"
탐지: rule=password_assignment, match="${VAULT_SECRET_DB_PASS}"  (* 도입 예정 패턴)
```

기본 password_assignment 패턴 `(?i)(?:password|passwd|pwd)\s*[=:]\s*\S+`이 `password=` 뒤의 모든 토큰을 캡처한다. 환경변수 참조(`${...}`)나 Vault 경로는 실제 패스워드가 아니지만 패턴이 구분하지 못해 오탐이 발생한다. 이 판단은 SLM 또는 추후 컨텍스트 인식 파이프라인에서 처리해야 한다.

---

#### FP-03 · password_ 접두어 필드 오탐

```
입력: "회원가입: reset_password_url=https://auth.example.com/reset?token=abc123"
탐지: rule=password_assignment, match="https://auth.example.com/reset?token=abc123"  (* 도입 예정 패턴)
```

패턴이 `password`를 포함하는 모든 키 이름을 탐지 대상으로 처리한다. `reset_password_url`, `password_hint`, `old_password_hash` 등 패스워드 값이 아닌 URL·힌트·해시 레퍼런스도 오탐된다. 키 이름 정확 매칭(`\bpassword\b`) 또는 제외 목록 적용이 필요하며, 최종 판단은 SLM 단계가 적합하다.

---

#### FP-04 · AKIA 접두어 내부 코드

```
입력: "내부코드: AKIATEST0001234567AB"
탐지: rule=aws_access_key, match="AKIATEST0001234567AB"
```

`AKIA[0-9A-Z]{16}` 패턴이 접두어와 길이만으로 탐지한다. 실제 AWS Access Key와 구분할 체크섬이나 외부 검증 수단이 없어 동일 형식의 내부 코드가 오탐된다.

---

#### FP-05 · ghp_ 내부 식별자

```
입력: "테스트 ID: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
탐지: rule=github_pat, match="ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12345"
```

접두어(ghp_) + 길이(36+) 기반 탐지만 수행한다. GitHub API로 유효성을 검증하지 않아 만료·폐기된 토큰이나 동일 형식의 내부 식별자도 오탐된다.

---

#### FP-06 · 제품코드 여권번호 오탐

```
입력: "제품코드: AB1234567"
탐지: rule=kr_passport, match="AB1234567"
```

`[A-Z]{1,2}\d{7,8}` 패턴이 SKU, 모델번호, 시리얼 등 영문+숫자 조합 코드를 과탐한다. 여권번호 발행국 코드(M, A 등) 검증이나 체크섬이 없다.

---

#### FP-07 · 관리코드 운전면허번호 오탐

```
입력: "코드번호: 12-34-567890-12"
탐지: rule=kr_driver_license, match="12-34-567890-12"
```

`\d{2}-\d{2}-\d{6}-\d{2}` 형식이 운전면허 외 내부 관리 코드 체계와 중복된다. 지역코드(앞 2자리: 01~28) 검증이 없어 임의의 숫자도 탐지된다.

---

#### FP-08 · 은행 계좌번호 신용카드 오탐

```
입력: "국민은행 계좌: 765402-01-123456"
탐지: rule=credit_card, match="765402-01-123456"
```

`credit_card` 패턴 `(?:\d[-\s]?){13,19}`이 하이픈 구분 14자리 숫자를 전부 포함한다. 해당 계좌번호가 Luhn 체크를 우연히 통과하면 신용카드로 오탐된다. 전용 `kr_bank_account` 패턴이 없어 구분이 불가하다.

---

#### FP-09 · 공개 예제 JWT 토큰

```
입력: "JWT 예시: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflK..."
탐지: rule=jwt_token
```

JWT 패턴이 `eyJ...` 구조만으로 탐지한다. 서명 검증이나 만료 확인이 없어 공개된 예제 토큰, 강의 자료, 기술 문서에서 필연적으로 오탐이 발생한다.

---

#### FP-10 · 포트 번호 전화번호 오탐

```
입력: "바인딩 포트: 01012345678"
탐지: rule=kr_phone, match="01012345678"
```

`(?:010|011|...)[-.]?\d{3,4}[-.]?\d{4}` 패턴이 구분자 없는 연속 숫자도 허용한다. `010` 접두어가 있으면 컨텍스트와 무관하게 탐지된다.

---

## 3. Regex 단독 한계 — 10건

Regex 패턴만으로 탐지가 구조적으로 불가능하거나 매우 어려운 입력 유형.

| ID | 카테고리 | 입력 예시 | 실패 원인 |
|---|---|---|---|
| R-01 | 자연어 표현 | 한글 발음으로 서술한 전화번호 | 숫자 패턴 없음 |
| R-02 | 비연속 PII | 문장에 분산된 주민번호 구성요소 | 연속 패턴 매칭 불가 |
| R-03 | 미정의 유형 | 사업자등록번호 | 패턴 미정의 |
| R-04 | 미정의 유형 | 은행 계좌번호 | 패턴 미정의 |
| R-05 | 구분자 변형 | 점(.) 구분 카드번호 | `[-\s]?`만 허용 |
| R-06 | 대소문자 | 소문자 여권번호 | `[A-Z]`만 허용 |
| R-07 | 토큰 형식 누락 | Fine-grained GitHub PAT | `github_pat_` 접두어 미포함 |
| R-08 | 컨텍스트 없는 키 | API 키 값 단독 전송 | 할당문 형식 요구 |
| R-09 | 의미 기반 탐지 | 이름·주소를 자연어로 서술 | NER 수준 이해 필요 |
| R-10 | 인코딩 변환 | Base64 인코딩된 주민번호 | 디코딩 전처리 없음 |

### 핵심 케이스 상세

#### R-09 · 의미 기반 탐지 필요

```
입력: "홍길동 씨는 우리 팀 팀장이고 집은 서울 강남구 역삼동이에요."
기대: person_name, address
실제: 미탐
```

이름과 주소는 고정된 패턴이 없어 Regex로는 근본적으로 탐지할 수 없다. NER(Named Entity Recognition) 수준의 언어 이해가 필요하므로 SLM/AI 단계가 필수다.

---

#### R-10 · 인코딩된 PII

```
입력: "data: OTAxMjE1LTEyMzQ1Njc="   (Base64 디코딩 시 "901215-1234567")
기대: kr_rrn
실제: 미탐
```

`OTAxMjE1LTEyMzQ1Njc=`는 `901215-1234567`의 Base64 인코딩이지만, Regex는 원본 문자열만 매칭한다. 디코딩 전처리 파이프라인이 없으면 탐지 불가능하다.

---

## 4. SLM 단독 한계 — 10건

SLM(gemma-4-2b-it)만 사용 시 탐지 실패 또는 분류 오류 케이스. **전 항목 실측 기반.**

| ID | 카테고리 | 결과 유형 | 응답시간 | 원인 요약 |
|---|---|---|---|---|
| S-01 | 신용카드 한글 자연어 | ❌ 미탐 | 1,379ms | 한글 숫자 변환 불가, 즉시 빈 배열 |
| S-02 | API 키 단독 | ❌ 미탐 | 1,676ms | 컨텍스트 없어 의미 파악 불가 |
| S-03 | PEM Private Key | ❌ 미탐 | 1,866ms | 분류 범주에 private key 없음 |
| S-04 | 전화번호 한글 서술 | ❌ 미탐 | 33,888ms | 충분한 추론 후에도 발음-숫자 변환 실패 |
| S-05 | 신용카드 (분류 오류) | ⚠️ 잘못 분류 | 20,423ms | `account_number`로 오분류 |
| S-06 | AWS Access Key (분류 오류) | ⚠️ 잘못 분류 | 15,580ms | `account_number`로 오분류 |
| S-07 | 이메일 (분류 오류) | ⚠️ 잘못 분류 | 15,453ms | `person_name`으로 오분류 |
| S-08 | JWT (분류 오류) | ⚠️ 잘못 분류 | 36,285ms | `account_number`로 오분류 |
| S-09 | 암호화된 세션 쿠키 | ❌ 미탐 | 17,376ms | 암호화 토큰 민감정보 미인식 |
| S-10 | JSON 다중 필드 PII | ⚠️ 부분 탐지 | 31,063ms | 전화번호 누락 (이름+주소만 탐지) |

### 응답 시간 패턴

```
정상 추론:  15,000 ~ 36,000ms
즉시 반환:  1,000 ~  2,000ms  ← 사실상 추론 미실행 (S-01, S-02, S-03)
```

S-01, S-02, S-03의 응답 시간이 1~2초인 것은 모델이 프롬프트를 처리하자마자 빈 배열 `[]`을 즉시 반환했음을 의미한다. 해당 입력이 SLM에게 PII가 아닌 텍스트로 즉각 판단됐다는 증거다.

### 분류 오류 패턴

SLM의 PII 분류 범주는 `person_name`, `address`, `organization`, `date_of_birth`, `account_number`, `ip_address` 등이다. `credit_card`, `aws_access_key`, `email`, `jwt_token` 같은 세분화된 규칙이 없어 모든 민감 토큰이 `account_number`로, 사람 이름을 포함한 이메일이 `person_name`으로 수렴하는 경향이 있다.

### 상세 — S-09 · 암호화된 세션 쿠키

```
입력: "Set-Cookie: session=gAAAAABl9X2kQwHJmMz1ahXUQWkpLqNMbO8... ; HttpOnly"
기대: detected=true
실제: detected=false (17,376ms 추론 후 미탐)
```

17초간 추론했음에도 암호화된 세션값을 민감정보로 인식하지 못했다. `gAAAAA...` 형식은 Fernet 암호화 토큰이지만 SLM에게는 임의의 base64 문자열로 보인다. HTTP 헤더 컨텍스트(`Set-Cookie`)를 이해하더라도 값 자체가 무엇인지 판단하지 못한다.

### 상세 — S-10 · JSON 다중 필드 PII

```
입력: {"name": "홍길동", "phone": "010-1234-5678", "address": "서울시 강남구 역삼동"}
기대: person_name + kr_phone + address (3건)
실제: person_name + address (2건) — 전화번호 누락 (31,063ms)
```

이름과 주소는 탐지했으나 전화번호(`010-1234-5678`)를 별도 Finding으로 반환하지 않았다. SLM의 분류 범주에 `kr_phone`이 없어 전화번호를 독립 PII로 식별하지 못하는 경향이 있다.

---

## 5. 요약 및 시사점

### Regex 강점 / 약점

| 강점 | 약점 |
|---|---|
| 구조화된 PII 고속 탐지 (< 1ms) | 자연어·한글 발음 표현 불가 |
| 확정적 결과 (0 오류 없는 체크섬) | 구분자 변형에 취약 |
| 낮은 리소스 소모 | 컨텍스트 기반 검증 불가 |
| 시리얼/코드와 유사 형식 오탐 발생 | 패턴 미정의 PII 유형 미탐 |

### SLM 강점 / 약점

| 강점 | 약점 |
|---|---|
| 자연어·의미 기반 탐지 | CPU 환경 15~36초 소요 |
| 비연속·분산 PII 인식 가능 | 분류 정확도 낮음 (account_number 수렴) |
| 코드 미정의 PII 유형 탐지 | 구조적 암호화 토큰 미인식 |
| 이름·주소 등 NER 탐지 | 2B 파라미터 한계 (한글 발음-숫자 변환 불가) |

### 파이프라인 권장 구성

```
Request
  │
  ▼
[① Regex Stage]  ─ 고속 패턴 매칭, CRITICAL 규칙 즉시 차단
  │  탐지 결과를 컨텍스트로 전달
  ▼
[② SLM Stage]   ─ 자연어·의미 기반 보완 탐지
  │  regex 미탐 케이스 보완
  ▼
[③ Action]      ─ block / mask / alert
```

**Regex → SLM 직렬 구성**이 현재 최적이다. Regex가 먼저 구조화된 PII를 빠르게 걸러내고, SLM이 Regex 사각지대(자연어, 이름/주소, 비연속 PII)를 보완한다. 두 단계를 독립적으로 사용하면 각각의 약점이 그대로 노출된다.

### 개선 권고 (우선순위 순)

1. **`github_pat_` 접두어 추가** — Fine-grained PAT 미탐, 1줄 수정
2. **`kr_passport` 소문자 허용** — `[A-Za-z]` 또는 `re.IGNORECASE` 적용
3. **점(.) 구분자 허용** — `credit_card` 패턴 구분자를 `[-\s.]?`로 확장
4. **`kr_business_reg` 패턴 추가** — `\d{3}-\d{2}-\d{5}` 형식
5. **`openai_api_key` 패턴 추가** — `sk-(?:proj-)?[A-Za-z0-9]{32,}` 형식
6. **`password_assignment` 기본 패턴 추가** — `(?i)(?:password|passwd|pwd)\s*[=:]\s*\S+` 기본 형식으로 도입, 환경변수 참조·힌트 필드 오탐은 SLM 단계에서 필터링
7. **운전면허 지역코드 검증** — 앞 2자리 01~28 범위 확인으로 오탐 감소
