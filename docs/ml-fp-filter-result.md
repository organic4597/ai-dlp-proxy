---
title: "ML FP 필터 — 구현 결과 및 향후 계획"
date: 2026-05-05
tags: [ml, dlp, xgboost, random-forest, false-positive, result]
draft: false
category: projects
subcategory: github
---

# ML FP 필터 — 구현 결과 및 향후 계획

> **목표**: Regex 스테이지가 탐지한 결과 중 **오탐(False Positive)을 자동으로 걸러내는** 지도학습 모델을 설계·학습·평가한다.  
> 관련 노트북: `notebooks/dlp_fp_filter_ml.ipynb`  
> 관련 데이터 빌더: `tests/build_ml_dataset.py`

---

## 1. 파이프라인 내 ML 모델 위치

현재 파이프라인 흐름은 다음과 같다.

```
사용자 입력 (AI API 요청)
    │
    ▼
① Regex Stage        — 패턴 매칭으로 PII 후보 탐지
    │
    ▼
  [ML FP 필터]  ← 이 문서의 대상
    Regex 결과 중 오탐 suppressed 처리
    │
    ▼
② Asset Stage        — 보호 자산 키워드/임베딩 매칭
    │
    ▼
③ NMS                — 겹치는 finding 중복 제거
    │
    ▼
④ SLM Stage          — Regex가 놓친 문맥 의존 PII 보완
    │
    ▼
⑤ Action 결정        — PASS / ALERT / MASK
```

**Regex Stage 직후, Asset Stage 이전**에 위치하는 이유:

- Regex `Finding` 객체의 feature를 그대로 입력으로 사용 → 변환 비용 없음
- 오탐을 조기에 제거해야 이후 NMS 로직이 오염되지 않음
- SLM에 넘기는 마스킹 텍스트에서 오탐 구간을 마스킹하지 않아도 됨

---

## 2. 학습 데이터

### 2.1 데이터셋 구성

총 **622건**, TP(진짜 PII)와 FP(오탐)를 **1:1로 균형** 맞춤.

| 소스 파일 | 건수 | 라벨 | 설명 |
| :--- | ---: | :--- | :--- |
| `proto_phase1_true_positive.csv` | 150건 | TP(1) | 기본 정탐 케이스 |
| `proto_phase1_realistic_true_positive.csv` | 150건 | TP(1) | 현실형 정탐 (JSON/YAML/설문 문맥) |
| `proto_phase1_false_negative_risk.csv` | 48건 | TP(1) | 미탐 위험 케이스 (탐지해야 할 경계값) |
| `proto_phase1_false_positive.csv` | 150건 | FP(0) | 기본 오탐 케이스 |
| `proto_phase1_realistic_false_positive.csv` | 150건 | FP(0) | 현실형 오탐 (문서/예제/참조값) |
| `proto_phase1_over_detection_risk.csv` | 48건 | FP(0) | 과탐 위험 케이스 (억제해야 할 경계값) |

> 각 케이스에 `RegexStage`를 실제 실행하고 `expected_rule`과 일치하는 Finding만 추출.  
> Finding이 나오지 않은 케이스는 ML 입력이 없으므로 제외 → **최종 622건**.

### 2.2 커버하는 PII 규칙 목록

`kr_rrn`, `kr_passport`, `kr_driver_license`, `kr_phone`, `us_ssn`, `credit_card`, `email`,  
`aws_access_key`, `api_key_assignment`, `pem_private_key`, `jwt_token`, `github_pat`,  
`password_assignment` — 총 13개 규칙

### 2.3 오탐이 발생하는 주요 패턴

Regex는 **값의 형태**만 보기 때문에, 다음 상황에서 오탐이 발생한다.

**코드 안 상수·픽스처**
```python
const rrnFixture = "880515-1104333"; return rrnFixture;
# → const(weak) + return(weak) → 코드 문맥 → 오탐
```

**DB·서비스 연결 문자열 안의 이메일 패턴**
```
postgresql://svc_user@db.prod.company.com:5432/app
# → user@host.domain 형태 → email 패턴 일치 → 오탐
```

**비밀값 참조 표현식 (실제 값 아님)**
```bash
DB_PASSWORD=${DB_PASSWORD}
password: ${{ secrets.DB_PASSWORD }}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-changeme}
```

**README/문서 예제**
```
schema.example.rrn=880515-1104333
sample card number 4539-1488-0343-6467
```

**타임스탬프·일련번호의 주민번호 패턴 우연 일치**
```python
order_id = f"{datetime.now().strftime('%y%m%d')}-{seq:07d}"
# → "260504-0001234" = YYMMDD-NNNNNNN → kr_rrn 패턴 일치
```

---

## 3. 입력 Feature 17개

`tests/build_ml_dataset.py`의 `_extract_features()`에서 Finding 하나당 추출.

### 매치 텍스트 특성

| Feature | 설명 |
| :--- | :--- |
| `match_length` | 탐지된 문자열 길이 |
| `match_digit_ratio` | 숫자 비율 (0~1) |
| `match_alpha_ratio` | 알파벳 비율 (0~1) |
| `match_special_ratio` | 특수문자 비율 (0~1) |
| `match_entropy` | Shannon 엔트로피 — 높을수록 무작위 → 실제 키/토큰 가능성 ↑ |

### 주변 문맥 특성

| Feature | 설명 |
| :--- | :--- |
| `ctx_before_len` | 매치 앞 문맥 길이. 길면 구조화된 문서일 가능성 ↑ |
| `ctx_after_len` | 매치 뒤 문맥 길이 |
| `pii_keyword_hits` | 전후 문맥에 룰별 PII 키워드가 몇 개 있는지 (`주민`, `bearer`, `cloud deploy` 등) |
| `code_signal_strong` | `import`, `def`, `class`, `function`, `#include` 등 강한 코드 시그널 수 |
| `code_signal_weak` | `const`, `return`, `hashlib`, `.js`, `=>` 등 약한 코드 시그널 수 |
| `is_in_quotes` | 매치 바로 앞뒤가 따옴표인지 (`"`, `'`, `` ` ``) |
| `is_assignment_rhs` | 매치 앞 문맥이 `=` 또는 `:` 로 끝나는지 (대입문 우변) |
| `is_in_url` | 매치 앞 문맥에 `://` 가 있거나 `/` 로 끝나는지 |
| `text_total_length` | 입력 텍스트 전체 길이 |

### 규칙 및 신뢰도

| Feature | 설명 |
| :--- | :--- |
| `severity_level` | 룰 심각도 (LOW=1 / MEDIUM=2 / HIGH=3 / CRITICAL=4) |
| `current_confidence` | Regex 스테이지의 최종 신뢰도 (체크섬·코드 패널티·키워드 배율 적용 후) |

---

## 4. 학습 방법

### 4.1 데이터 분할

```
전체 622건
    ├── Train  : 435건 (TP=218, FP=217) — 70%
    ├── Val    :  93건 (TP=46,  FP=47)  — 15%
    └── Test   :  94건 (TP=47,  FP=47)  — 15%
```

Stratified split으로 TP/FP 비율 유지.

### 4.2 전처리

- `rule_name` → One-Hot 인코딩 (카테고리 변수)
- 수치형 feature → StandardScaler 정규화
- 결측값 없음 (데이터 생성 시 보장)

### 4.3 알고리즘 스크리닝 (7개 후보 5-Fold CV)

DLP 특성상 **미탐(FN)이 치명적** → Recall에 2배 가중치를 주는 **F2 스코어**를 기준으로 평가.

| 순위 | 알고리즘 | F2 | Recall | Precision | ROC-AUC |
| :--- | :--- | ---: | ---: | ---: | ---: |
| 1 | **XGBoost** | **0.9809** | **0.9811** | 0.9815 | 0.9944 |
| 2 | SVM (RBF) | 0.9763 | 0.9734 | 0.9887 | 0.9920 |
| 3 | **Random Forest** | **0.9692** | **0.9657** | 0.9850 | **0.9975** |
| 4 | Decision Tree | 0.9685 | 0.9657 | 0.9818 | 0.9734 |
| 5 | Logistic Regression | 0.9528 | 0.9507 | 0.9627 | 0.9894 |
| 6 | KNN | 0.9511 | 0.9469 | — | — |
| 7 | Naive Bayes | 0.9422 | 0.9886 | — | 0.9542 |

F2 상위 3개 (XGBoost, SVM, Random Forest)를 심층 학습 대상으로 선정.

> **Random Forest와 XGBoost를 선택한 이유**:  
> - `pii_keyword_hits=0`이면서 `code_signal_weak=0`인 경우처럼 feature 간 **비선형 조합 관계**를 선형 모델은 표현 못함  
> - 스케일 정규화 없이도 동작 (단위가 다른 feature 혼재)  
> - **Feature Importance** 수치 제공 → 판단 근거 설명 가능 (DLP 감사 요건)  
> - 소규모 데이터(622건)에서 CPU만으로 충분한 성능

### 4.4 두 알고리즘 동작 방식

**Random Forest** — 여러 트리가 독립적으로 학습 후 다수결:
```
트리 1: pii_keyword_hits > 1? → YES → confidence > 0.7? → TP
트리 2: code_signal_weak > 1? → YES → FP
...
300개 트리 투표 → 다수결로 최종 결정
```
각 트리가 랜덤하게 다른 데이터·feature 조합으로 학습 → 한 트리가 과적합돼도 나머지가 보정.

**XGBoost** — 앞 트리의 오류를 다음 트리가 순차 보완:
```
1번 트리: 전체 학습 → 틀린 케이스 가중치 ↑
2번 트리: 1번 오류 집중 학습 → 또 틀린 케이스 가중치 ↑
...300번 반복 → 합산
```

### 4.5 Feature Importance 분석 결과

두 모델이 공통으로 선정한 핵심 3가지:

| 순위 | Feature | 의미 |
| :--- | :--- | :--- |
| 1 | **`pii_keyword_hits`** | 문맥 안에 PII 관련 키워드가 있는가 |
| 2 | **`current_confidence`** | Regex 스테이지가 내린 신뢰도 |
| 3 | **`code_signal_weak`** | 주변에 코드 시그널이 있는가 |

→ **"PII 키워드가 있고, Regex 신뢰도가 높고, 코드 시그널이 없으면 진짜 PII"** 라는 도메인 지식을 데이터가 독립적으로 검증한 결과.

**Random Forest**는 `ctx_before_len`(앞 문맥 길이)을 4위로 높게 평가 — 긴 문서일수록 TP 가능성 ↑.  
**XGBoost**는 `rule_name_api_key_assignment`, `rule_name_kr_rrn` 등 **룰 종류 자체**를 활용 — 룰마다 오탐 패턴이 다르기 때문.

---

## 5. 최종 테스트 결과

### 5.1 테스트셋 성능 (94건, 기본 임계값)

| 모델 | Precision | Recall | F1 | 미탐(FN) | 과탐(FP) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.85 | 0.96 | 0.90 | 2건 | 8건 |
| Random Forest | **1.00** | 0.98 | 0.99 | 1건 | **0건** |
| **XGBoost** | **1.00** | **1.00** | **1.00** | **0건** | **0건** |

### 5.2 DLP 최적 임계값 분석 (Recall ≥ 0.97 조건)

| 모델 | 최적 임계값 | Precision | Recall | F2 | 과탐 | 미탐 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.42 | 0.85 | 0.98 | 0.95 | 8건 | 1건 |
| Random Forest | 0.46 | 1.00 | 0.98 | 0.98 | 0건 | 1건 |
| **XGBoost** | **0.14** | **1.00** | **1.00** | **1.00** | **0건** | **0건** |

**최종 선정: XGBoost, 임계값 0.14** (F2=1.0000)  
모델 저장 경로: `tests/fp_filter_best_model.pkl`

### 5.3 파이프라인 통합 시뮬레이션

```
[기존 — Regex만]
  과탐(FP) : 47건 모두 경보 발생
  미탐(FN) :  0건

[ML 필터 적용 후 — XGBoost]
  과탐 억제 : 47/47건 (100.0%)
  미탐 발생 :  0/47건  (0.0%)
  TP 보존율 : 100.0%
```

> **주의**: 위 수치는 합성 데이터 기준이다. 실제 트래픽 데이터에서는 별도 검증이 필요하다.

---

## 6. 한계 및 개선 계획

### 6.1 현재 한계

| 한계 | 설명 |
| :--- | :--- |
| **합성 데이터 과적합** | 훈련·테스트 데이터가 같은 템플릿으로 생성 → 실제 환경 성능이 낮을 수 있음 |
| **템플릿 다양성 부족** | 현재 케이스가 `const x = "값"; return x;` 형태에 집중 — 실제 개발자 입력 패턴 미반영 |
| **규칙 추가 시 재학습 필요** | 새 PII 규칙을 추가하면 One-Hot feature 차원이 바뀌어 모델을 처음부터 재학습해야 함 |
| **피처 엔지니어링 의존** | `pii_keyword_hits` 계산에 수동 관리 키워드 사전 사용 |

### 6.2 데이터 확장 계획

현재 622건 → 목표 **1,800건 이상** (3배 확장)

| 분류 | 현재 | 목표 | 추가 방법 |
| :--- | ---: | ---: | :--- |
| TP (정상 탐지) | 311건 | 500건 | 다양한 실제 문서 포맷(Kubernetes YAML, .env, GitHub Actions) 추가 |
| FP (오탐) | 311건 | 500건 | DB 연결 문자열, Helm 템플릿, 타임스탬프 ID 패턴 추가 |
| **경계 케이스** | **96건** | **800건** | 가장 우선 — 애매한 상황 집중 확보 |

경계 케이스 예시 (현재 부족한 패턴):
- 문맥 없이 단독 입력된 번호 (자연어 vs 코드 판별 불가)
- SQL 쿼리 안의 주민번호 패턴 (`WHERE rrn = '880515-1234567'`)
- Dockerfile `ENV` 지시어 안의 값
- 테스트 코드의 `@pytest.mark.parametrize`에 들어간 값

### 6.3 모델 개선 계획

**단기 (현 데이터 기반)**
- SHAP 값 기반으로 오분류 케이스 집중 분석
- 임계값을 룰별로 다르게 설정 (예: `kr_rrn`은 더 보수적으로)

**중기 (데이터 확장 후)**
- 실제 AI API 트래픽 데이터로 재학습
- 온라인 학습 방식 도입 — 운영 중 오탐 리포트를 즉시 학습에 반영
- 룰 추가에 독립적인 feature 설계 (룰 이름 One-Hot 제거, 룰 특성 수치화)

**장기 (SLM 파인튜닝 연계)**
- SLM(`gemma-4-2b-it`)을 **QLoRA**로 파인튜닝하여 ML FP 필터와 이중 검증 구조 구축
- QLoRA 학습 데이터: TP/FP 각 500건 + 경계 케이스 800건 = **1,800건** 목표
  - 입력: 실제 텍스트
  - 출력: `[{"rule": "kr_rrn", "start": 47, "end": 61, "text": "...", "confidence": 0.95}]`
- 합성 데이터만으로는 다양성 한계 → 실제 개발자 입력 패턴 반영 필수

---

## 7. 코드 통합 설계 (미구현)

현재 ML 모델은 노트북 단계이며, 파이프라인 통합 코드는 아직 작성되지 않았다.

```
src/engine/pipeline/
├── ml_filter/                      ← 신규 (미구현)
│   ├── __init__.py
│   ├── feature_extractor.py        # Finding → feature vector
│   └── fp_filter.py                # XGBoost 모델 래퍼
└── __init__.py                     # run_pipeline()에 ml_filter 호출 추가 필요
```

통합 시 안전 장치:
- `control.json`에 `ml_filter_enabled: false` 옵션 → 즉시 비활성화 가능
- 모델 로드 실패 시 자동 비활성화 + 경고 로그
- 추론 시간 50ms 초과 시 해당 finding은 keep(안전 우선)
