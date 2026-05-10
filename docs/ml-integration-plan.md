---
title: "DLP 파이프라인 ML 도입 계획서 — 지도학습 기반 False Positive 필터"
date: 2026-04-25
tags: [ml, dlp, supervised-learning, false-positive, plan]
draft: false
category: projects
subcategory: github
---

# DLP 파이프라인 ML 도입 계획서

> 현 파이프라인은 **규칙 기반(Regex + 키워드 + 휴리스틱)** 으로 동작한다.  
> 본 문서는 **지도학습(Supervised Learning)** 을 도입할 후보 위치를 분석하고, 학교 과제 조건(3개 이상 알고리즘 비교 + ipynb + CSV + 발표자료)을 만족하는 구현 계획을 정리한다.

---

## 1. 현재 파이프라인 구조 복습

```
DLPTarget(text, role, field_path)
    │
    ▼
┌─────────────── RegexStage ───────────────┐
│ ① 패턴 매칭                                │
│ ② Validator (Luhn, RRN 체크섬)            │
│ ③ 코드 문맥 감지 (_is_code_context)         │← ML 후보 ②
│ ④ 컨텍스트 키워드 배율 (× 0.6/1.0/1.3)      │← ML 후보 ③
│ ⑤ Validator floor                         │
│ ⑥ Allowlist 검사                          │
│ ⑦ Finding 생성 (confidence 점수)           │← ML 후보 ④
└──────────────────────────────────────────┘
    │
    ▼ AssetStage → NMS → SLMStage → Action 결정
```

---

## 2. ML 도입 가능 위치 후보 5가지

각 후보의 **기대 효과**, **구현 난이도**, **데이터 확보 가능성**, **과제 적합도**를 평가한다.

### 후보 ① — Pre-filter (스캔 대상 판별)
- **위치**: RegexStage 진입 전, target.text를 받아 "스캔할 가치가 있는 텍스트인가?"를 판별
- **출력**: `should_scan: bool` 또는 `priority_score: float`
- **장점**: 시스템 프롬프트, 빈 입력, base64 덩어리 등 명백히 PII가 없는 텍스트는 스킵 → 성능 향상
- **단점**: 너무 보수적이면 미탐 위험. 이미 `DEFAULT_SKIP_ROLES`로 일부 처리됨
- **데이터**: 라벨 만들기 어려움 (모호함)
- **과제 적합도**: ★★☆☆☆

### 후보 ② — 코드 vs 자연어 분류기 (★ 추천)
- **위치**: 현재 `_is_code_context()` 자리. 정규식(`_STRONG_CODE_RE`, `_WEAK_CODE_RE`)을 ML 분류기로 교체
- **출력**: `is_code_prob: float (0~1)`
- **장점**:
  - 현재 정규식은 단순한 토큰 매칭 → false negative 많음 (예: SQL, YAML, 설정 파일)
  - ML로 대체 시 더 정확한 코드 페널티 적용 가능
  - **라벨이 명확**: GitHub에서 코드/자연어 데이터셋 풍부
- **단점**: 모델 추론 오버헤드 (밀리초 단위 영향)
- **과제 적합도**: ★★★★★ (이진 분류, 3개 알고리즘 비교 자연스러움)

### 후보 ③ — 컨텍스트 적합도 회귀 모델
- **위치**: 현재 `_context_multiplier()` 자리. 키워드 카운트(0/1/2+) → 0.6/1.0/1.3 매핑을 회귀로 교체
- **입력**: 매치 전후 200자 컨텍스트 + 룰 이름
- **출력**: `multiplier: float (0.3~1.5)`
- **장점**: 12개 룰별 키워드 사전을 수동 관리하지 않아도 됨
- **단점**: 회귀 라벨 만들기 어려움 (정답 multiplier가 뭔지 모호)
- **과제 적합도**: ★★★☆☆ (회귀 문제로 만들기 까다로움)

### 후보 ④ — False Positive 필터 (★★ 최고 추천)
- **위치**: RegexStage **출력 후**, 각 Finding을 입력으로 받아 "이게 진짜 PII인가?" 분류
- **입력 features**:
  - `rule_name` (one-hot): 12개 빌트인 룰
  - `match_text_length`, `match_digit_ratio`, `match_alpha_ratio`
  - `context_before_length`, `context_after_length`
  - `pii_keyword_hits`: 룰별 키워드 매칭 수
  - `code_signal_strong`, `code_signal_weak`: 코드 시그널 카운트
  - `validator_score`: validator 반환값 (0/1)
  - `is_in_quotes`: 매치가 따옴표 안인지
  - `is_assignment_rhs`: `=` 우변인지
  - `field_path_depth`: messages[N].content 깊이
- **출력**: `is_true_pii: bool`
- **장점**:
  - **가장 임팩트 큼** — 최종 marking/blocking 정확도 직접 개선
  - **데이터 확보 쉬움**: 기존 `tests/run_proto_regex_tests.py`의 7개 데이터셋이 이미 라벨링됨 (TP/FP 구분)
  - Tabular 데이터 → Logistic Regression, Random Forest, XGBoost 비교에 적합
  - **창의성**: 규칙 기반 시스템에 ML 후처리를 결합한 하이브리드 구조
- **단점**: 라벨 데이터셋 규모 확보 필요 (수백~수천 건)
- **과제 적합도**: ★★★★★

### 후보 ⑤ — Action 결정 모델
- **위치**: 현재 `_decide_action()` 자리. findings 집합 → PASS/ALERT/MASK/BLOCK
- **출력**: 4-class 분류
- **장점**: 정책 결정의 자동 학습
- **단점**: 비즈니스 로직이라 ML보다 룰이 명확함 (감사성 측면)
- **과제 적합도**: ★★☆☆☆

---

## 3. 최종 선택: **후보 ④ (False Positive 필터)**

### 선택 이유
1. **과제 조건 완벽 적합**: Tabular 데이터 + 이진 분류 → 3개 이상 알고리즘 비교 자연스러움
2. **데이터 즉시 확보 가능**: 기존 테스트 데이터셋(`tests/run_proto_regex_tests.py`)을 CSV로 변환
3. **창의성/독창성**: "규칙 기반 시스템 위에 ML 게이트를 얹어 false positive를 줄인다" — 산업에서도 실제로 쓰는 하이브리드 구조
4. **실측 가능한 개선**: Precision/Recall로 명확하게 효과 측정

### 통합 위치
```
RegexStage.scan() 결과
    │
    ▼ 모든 Finding 수집
    │
    ▼ FPFilter.predict_proba(finding) → keep_prob
    │
    ▼ keep_prob < 0.5 → finding.suppressed = True
                         finding.metadata["suppressed_reason"] = "ml_fp_filter"
    │
    ▼ 기존 NMS / Action 결정으로 진행
```

기존 `confidence` 점수는 그대로 두고 **추가 게이트**로 동작 → fallback 안전.

---

## 4. 구현 설계

### 4.1 데이터셋 구축

#### 라벨 소스
1. **기존 테스트 데이터셋** (`tests/run_proto_regex_tests.py`):
   - 구역 1, 3 → label=1 (TP)
   - 구역 2, 4 → label=0 (FP)
   - 구역 5, 6 → 경계값, 수동 라벨링
2. **합성 데이터 생성**:
   - Faker 라이브러리로 가짜 PII 생성 (RRN, 카드, 전화 등)
   - GitHub public repo에서 코드 샘플 크롤링 → 코드 컨텍스트 PII 합성
3. **수동 라벨링**: 100~200건 직접 검수

#### CSV 스키마 (`pii_findings.csv`)

| 컬럼 | 타입 | 설명 |
|---|---|---|
| `rule_name` | category | 룰 이름 (kr_rrn, credit_card, ...) |
| `severity_level` | int | 1~4 (LOW~CRITICAL) |
| `match_length` | int | 매치 텍스트 길이 |
| `match_digit_ratio` | float | 숫자 비율 0~1 |
| `match_alpha_ratio` | float | 알파벳 비율 0~1 |
| `match_special_ratio` | float | 특수문자 비율 0~1 |
| `validator_score` | float | 0.0 또는 1.0 (없으면 1.0) |
| `ctx_before_len` | int | 앞 컨텍스트 길이 |
| `ctx_after_len` | int | 뒤 컨텍스트 길이 |
| `pii_keyword_hits` | int | 룰별 PII 키워드 매칭 수 |
| `code_signal_strong` | int | 강한 코드 시그널 카운트 |
| `code_signal_weak` | int | 약한 코드 시그널 카운트 |
| `is_in_quotes` | bool | 따옴표 안 매치 |
| `is_assignment_rhs` | bool | `=` 우변 |
| `is_in_url` | bool | URL 내부 |
| `is_in_path` | bool | 파일 경로 내부 |
| `field_role` | category | user / assistant / tool_def |
| `text_total_length` | int | 전체 텍스트 길이 |
| **`label`** | **bool** | **1=TP(진짜 PII), 0=FP(오탐)** |

목표 데이터 규모: **1500건 이상** (TP:FP ≈ 1:1)

### 4.2 알고리즘 비교

3개 + α 모델을 같은 train/test split으로 비교:

| 알고리즘 | 라이브러리 | 선택 이유 |
|---|---|---|
| **Logistic Regression** | scikit-learn | 베이스라인, 해석 가능 |
| **Random Forest** | scikit-learn | 비선형, feature importance |
| **Gradient Boosting (XGBoost)** | xgboost | tabular 데이터에서 SOTA 성능 |
| **SVM (RBF)** (옵션) | scikit-learn | 비선형 비교군 |
| **MLP (Neural Net)** (옵션) | scikit-learn | 딥러닝 베이스라인 |

### 4.3 평가 지표

DLP 도메인 특성상 **False Negative(미탐)이 치명적** 이므로 단순 accuracy가 아닌 다음을 종합:

| 지표 | 의미 | 목표 |
|---|---|---|
| **Recall (TP)** | 진짜 PII를 놓치지 않는 비율 | ≥ 0.98 (미탐 최소화) |
| **Precision (TP)** | TP 예측 중 실제 TP 비율 | ≥ 0.85 |
| **F2-score** | Recall에 가중치 (β=2) | 최대화 |
| **PR-AUC** | 임계값 무관 종합 성능 | 비교 기준 |
| **Confusion Matrix** | TP/FP/TN/FN 분포 | 시각화 |

**임계값 선택 전략**: ROC가 아닌 **Precision-Recall Curve**에서 Recall ≥ 0.98 보장하는 최저 임계값 선택.

### 4.4 ipynb 구성 계획

```
1. 문제 정의
   1.1 DLP 파이프라인 소개
   1.2 False Positive 문제 사례
   1.3 ML 도입 위치 다이어그램

2. 데이터 탐색 (EDA)
   2.1 라벨 분포
   2.2 룰별 TP/FP 비율
   2.3 feature 상관관계 히트맵
   2.4 코드 문맥 vs 자연어 문맥 분포

3. 전처리
   3.1 카테고리 → one-hot
   3.2 수치형 표준화 (StandardScaler)
   3.3 Train/Validation/Test 80/10/10 분할 (stratified)

4. 모델 학습 (3+개)
   4.1 Logistic Regression + GridSearchCV
   4.2 Random Forest + RandomizedSearchCV
   4.3 XGBoost + Optuna (또는 GridSearchCV)
   4.4 (옵션) SVM, MLP

5. 평가 비교
   5.1 5-fold cross-validation 결과 표
   5.2 Test set Precision/Recall/F2
   5.3 PR Curve 4개 모델 비교
   5.4 Confusion Matrix 4개

6. 해석
   6.1 Random Forest feature importance
   6.2 XGBoost SHAP values
   6.3 오분류 사례 분석 (FN 위주)

7. 통합 시뮬레이션
   7.1 기존 파이프라인 vs ML 게이트 적용 후 비교
   7.2 처리 시간 비교
   7.3 임계값 민감도 분석

8. 결론 및 향후 계획
```

### 4.5 발표자료 구성 (10분 발표 기준)

1. **문제 정의** (1분) — DLP가 뭐고 왜 FP가 문제인지
2. **현 시스템** (1.5분) — Regex 기반 파이프라인 한계
3. **ML 도입 후보 분석** (1.5분) — 5개 후보 비교표, 왜 ④번을 골랐나
4. **데이터셋 설계** (1분) — feature engineering 핵심 포인트
5. **알고리즘 비교** (2분) — 3개 모델 학습 + PR Curve
6. **결과 해석** (1.5분) — feature importance, 오분류 사례
7. **통합 효과** (1분) — Before/After 비교
8. **창의성 어필** (0.5분) — 규칙+ML 하이브리드, DLP 도메인 특화 평가지표

---

## 5. 코드 통합 설계

### 5.1 새 모듈 구조
```
src/engine/pipeline/
├── ml_filter/
│   ├── __init__.py
│   ├── feature_extractor.py    # Finding → feature vector
│   ├── fp_filter.py            # ML 모델 래퍼
│   └── models/
│       └── fp_filter_xgb.pkl   # 학습된 모델
└── regex_stage.py              # 기존 코드 (변경 최소)
```

### 5.2 통합 코드 스케치

```python
# src/engine/pipeline/ml_filter/fp_filter.py
import joblib
from .feature_extractor import extract_features

class FalsePositiveFilter:
    def __init__(self, model_path: str, threshold: float = 0.5):
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def predict(self, finding, target_text: str) -> tuple[bool, float]:
        """Return (keep, prob_true_pii)."""
        features = extract_features(finding, target_text)
        prob = self.model.predict_proba([features])[0][1]
        return prob >= self.threshold, prob
```

```python
# src/engine/pipeline/__init__.py 변경 (최소 침투)
_fp_filter = FalsePositiveFilter("models/fp_filter_xgb.pkl") if ML_FILTER_ENABLED else None

# RegexStage 결과 직후
if _fp_filter:
    for f in regex_new_findings:
        keep, prob = _fp_filter.predict(f, target_text_lookup[f.field_path])
        if not keep:
            f.suppressed = True
            f.metadata["suppressed_reason"] = "ml_fp_filter"
            f.metadata["ml_prob"] = prob
```

### 5.3 안전장치 (Fallback)
- `control.json`에 `ml_filter_enabled: false` 옵션 추가 → 즉시 비활성화 가능
- 모델 로드 실패 시 자동으로 비활성화 + 경고 로그
- 추론 시간 50ms 초과 시 해당 finding은 keep으로 처리 (안전 우선)

---

## 6. 작업 순서 (To-Do)

| 단계 | 작업 | 예상 산출물 |
|---|---|---|
| 1 | 데이터 수집 스크립트 작성 (테스트 픽스처 → CSV) | `tests/build_ml_dataset.py`, `pii_findings.csv` |
| 2 | Faker + GitHub 코드로 합성 데이터 추가 | CSV 행 1500+ |
| 3 | EDA + feature engineering ipynb | `notebooks/01_eda.ipynb` |
| 4 | 3개 알고리즘 학습 비교 ipynb | `notebooks/02_model_comparison.ipynb` |
| 5 | 최적 모델 저장 + 통합 코드 작성 | `fp_filter.py`, `models/*.pkl` |
| 6 | 통합 후 회귀 테스트 (기존 7구역) | TP recall 유지 확인 |
| 7 | 발표 슬라이드 제작 | `presentation.pdf` |

---

## 7. 과제 조건 충족 확인

| 조건 | 충족 여부 | 비고 |
|---|---|---|
| 지도학습 알고리즘 사용 | ✅ | 이진 분류 (TP vs FP) |
| 알고리즘 3개 이상 비교 | ✅ | LR, RF, XGBoost (+ SVM/MLP 옵션) |
| 창의성/독창성 | ✅ | 규칙기반+ML 하이브리드, DLP 도메인 특화 평가 |
| ipynb 제출 | ✅ | EDA + 모델 비교 2개 |
| 입력 CSV 제출 | ✅ | `pii_findings.csv` (자체 구축 데이터셋) |
| 발표자료 제출 | ✅ | 슬라이드 PDF |

---

## 8. 위험 요소와 대응

| 위험 | 대응 |
|---|---|
| 데이터 라벨링 노이즈 | 합성 데이터는 자동 라벨, 수동 검수 비율 유지 |
| 클래스 불균형 | stratified split + class_weight='balanced' |
| Recall 미달 (DLP 치명적) | 임계값 보수적 설정 + ml_filter_enabled 옵션으로 회피 |
| 추론 오버헤드 | XGBoost는 단일 추론 1ms 미만, 전체 영향 미미 |
| 과적합 | 5-fold CV + hold-out test set + early stopping |

---

## 9. 결론

**False Positive 필터(후보 ④)** 가 다음 이유로 최적이다:
- 규칙 기반 시스템의 약점인 **과탐(FP) 직접 해소**
- 기존 테스트 데이터를 학습 데이터로 즉시 활용 가능
- Tabular 이진 분류 → 3개 알고리즘 비교에 자연스러움
- 창의적 포인트: **"하이브리드 DLP — 규칙으로 잡고 ML로 거른다"**
