# SLM 파인튜닝 계획서 — AI DLP Proxy 전용 PII 탐지 모델

> 작성일: 2026-05-10  
> 대상: DLP 파이프라인의 `SLMStage` 교체용 특화 모델

---

## 1. 현황 분석 및 파인튜닝 목적

### 1-1. 현재 SLMStage 동작 방식

```
입력 텍스트 (최대 1,500자 청크)
    │
    ▼
시스템 프롬프트 (영문, 범용 PII 탐지 지시)
    +
GBNF Grammar (JSON 배열 출력 강제)
    │
    ▼
Gemma-4 2B-IT Q4_K_M (llama-cpp-python)
    │
    ▼
JSON 배열 [{rule, start, end, text, confidence}, ...]
```

**현재 문제점:**

| 문제 | 원인 | 영향 |
|---|---|---|
| 코드 문맥 오탐 | 범용 모델이 코드/자연어 구분 약함 | API Key가 코드에 있어도 탐지 |
| 한국어 PII 낮은 재현율 | 사전학습 데이터에 한국 행정 번호 패턴 부족 | 주민등록번호·운전면허 미탐 |
| GBNF Grammar 오버헤드 | 출력 포맷 강제를 sampling 단계에서 수행 | 추론 속도 ~15-20% 저하 |
| Hallucination 오프셋 | 범용 모델이 정확한 char offset 계산 미숙 | match_start/end 오류 |
| 영문 시스템 프롬프트 | 한국어 입력에 언어 혼선 발생 | 응답 품질 불안정 |

### 1-2. 파인튜닝 후 목표

- **Korean PII 재현율**: Regex Stage가 놓친 문맥 의존적 PII를 70% 이상 보완
- **FP 감소**: 코드 컨텍스트 오탐률 ≤ 5%
- **GBNF 없이 JSON 출력**: grammar 강제 없이도 항상 유효한 JSON 반환
- **추론 속도**: GPU 환경 기준 평균 150ms/청크 이하

---

## 2. 기반 모델 선택

### 2-1. 후보 비교

| 모델 | 크기 | 다국어 능력 | 추론속도(CPU) | 추론속도(GPU) | 비고 |
|---|---|---|---|---|---|
| **Qwen2.5-1.5B-Instruct** | 1.5B | ★★★★★ (한국어 우수) | ~2-4s | ~80ms | ✅ **1순위** |
| Gemma-4-2B-IT | 2B | ★★★☆☆ (한국어 보통) | ~3-10s | ~120ms | 현재 사용 중 |
| Phi-3-mini-4k | 3.8B | ★★★☆☆ | ~8-15s | ~200ms | 너무 큼 |
| SmolLM2-1.7B | 1.7B | ★★☆☆☆ (영어 위주) | ~3-5s | ~100ms | 한국어 부적합 |

**선택: Qwen2.5-1.5B-Instruct**

이유:
- 한국어 포함 29개 언어 사전학습 — 한국 행정번호 패턴 기초 지식 보유
- 1.5B 파라미터 → CPU 전용 환경에서도 허용 가능한 속도
- 현재 프로젝트에 이미 `qwen2.5-1.5b-instruct-q4_k_m.gguf` 파일 존재
- Instruction-tuned 베이스라 SFT 안정적

---

## 3. 파인튜닝 방법론

### 3-1. 학습 패러다임: QLoRA (Supervised Fine-Tuning)

```
Qwen2.5-1.5B-Instruct (FP16 / BF16 로드)
    │
    ▼
4-bit NF4 양자화 (bitsandbytes)
    │
    ▼
LoRA 어댑터 삽입 (rank=16, alpha=32)
    대상 레이어: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj
    │
    ▼
SFT (Supervised Fine-Tuning)
    학습 데이터: DLP PII 탐지 Instruction 데이터셋
    │
    ▼
LoRA 병합 → GGUF 변환 (Q4_K_M 또는 Q5_K_M)
    │
    ▼
slm_stage.py 모델 경로 교체
```

**QLoRA 선택 이유:**
- 1.5B 모델 전체 학습은 ~12GB VRAM 필요 → QLoRA로 ~4GB로 감소
- RTX 3060 이상 또는 A100 등 클라우드에서 학습 가능
- LoRA rank=16으로 충분한 표현력 + 과적합 방지

### 3-2. 학습 설정

```python
# QLoRA 설정
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj","k_proj","v_proj","o_proj",
                    "gate_proj","up_proj","down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

training_args = TrainingArguments(
    num_train_epochs=3,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,  # 유효 배치=16
    learning_rate=2e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    bf16=True,                       # A100/H100; V100은 fp16
    max_grad_norm=1.0,
    logging_steps=10,
    save_strategy="epoch",
    eval_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
)
```

---

## 4. 학습 데이터 구성

### 4-1. 데이터 형식 (Instruction Format)

Qwen2.5의 Chat Template에 맞춘 SFT 형식:

```
<|im_start|>system
당신은 개인정보(PII) 탐지 전문가입니다. 입력 텍스트에서 정규식이 탐지하지 못한
문맥 의존적 개인정보를 찾아 JSON 배열로 반환합니다.

탐지 대상 유형:
- person_name: 실존 개인의 이름 (성+이름 조합)
- address: 실제 주소 (도로명, 지번, 도시, 국가 포함)
- organization: 개인과 연관된 기관명 (소속 조합)
- date_of_birth: 생년월일
- medical_info: 의료·건강 정보
- biometric: 생체 정보

주의사항:
- <<<...>>>로 이미 마스킹된 부분은 탐지 제외
- 코드(import/def/class 등) 안의 문자열은 탐지 제외
- 예시·테스트 데이터("홍길동", "test@example.com") 제외
- 정보가 없으면 반드시 [] 반환
- JSON 외 다른 텍스트 금지
<|im_end|>
<|im_start|>user
{입력 텍스트 (최대 1500자)}
<|im_end|>
<|im_start|>assistant
{JSON 배열}
<|im_end|>
```

### 4-2. 데이터셋 구성 계획

**총 목표: 5,000~8,000 샘플 (TP:FP = 6:4)**

#### A. 기존 프로젝트 데이터 활용 (약 1,200샘플)

| 파일 | 샘플수 | 변환 방법 |
|---|---|---|
| `tests/proto_phase1_true_positive.csv` | ~200 | 텍스트+오프셋 → Instruction 변환 |
| `tests/proto_phase1_false_positive.csv` | ~200 | 텍스트 → 빈 배열 `[]` 정답 |
| `tests/synthetic_true_positive.csv` | ~300 | 동일 변환 |
| `tests/synthetic_false_positive.csv` | ~300 | 동일 변환 |
| `tests/proto_phase1_realistic_true_positive.csv` | ~200 | 동일 변환 |

#### B. SLM 특화 합성 데이터 (약 4,000샘플)

RegexStage가 탐지하지 못하는 **문맥 의존적 PII**에 집중:

```
[카테고리 1] 이름 + 소속 조합 (1,000샘플)
예시:
  Input:  "삼성전자 홍길동 과장님께 보내드립니다."
  Output: [{"rule":"person_name","start":5,"end":8,"text":"홍길동","confidence":0.92},
           {"rule":"organization","start":0,"end":4,"text":"삼성전자","confidence":0.85}]

  Input:  "Please forward to John Smith at Kakao Corp."
  Output: [{"rule":"person_name","start":16,"end":26,"text":"John Smith","confidence":0.95},
           {"rule":"organization","start":30,"end":39,"text":"Kakao Corp","confidence":0.80}]

[카테고리 2] 자유형식 주소 (800샘플)
예시:
  Input:  "배송지: 서울특별시 강남구 테헤란로 123, 현대빌딩 5층"
  Output: [{"rule":"address","start":4,"end":33,"text":"서울특별시 강남구 테헤란로 123, 현대빌딩 5층","confidence":0.97}]

[카테고리 3] 의료·건강 정보 (600샘플)
예시:
  Input:  "환자 김OO은 2형 당뇨 진단을 받았으며 메트포르민 500mg을 처방받았습니다."
  Output: [{"rule":"medical_info","start":0,"end":45,"text":"...","confidence":0.94}]

[카테고리 4] 코드 컨텍스트 (1,000샘플 — FP 방지)
예시:
  Input:  "from utils import get_user\nname = '홍길동'  # placeholder\nprint(name)"
  Output: []  ← 코드 내 플레이스홀더 → 탐지 안 함

  Input:  "api_key = 'sk-test-1234'  # test key"
  Output: []  ← 테스트 키 → 탐지 안 함

[카테고리 5] 혼합 문서 (600샘플)
예시:
  Input:  "안녕하세요. 저는 <<<전화번호>>>로 연락주시면 됩니다.
           담당자는 이민수 차장이며, 본사는 판교 소재입니다."
  Output: [{"rule":"person_name","start":61,"end":64,"text":"이민수","confidence":0.91}]
          ← 이미 마스킹된 <<<전화번호>>>는 제외
```

#### C. 데이터 증강 (약 2,000샘플)

| 증강 기법 | 비율 |
|---|---|
| 문장 앞뒤 컨텍스트 길이 변화 (0자~300자) | 30% |
| 한국어 ↔ 영어 혼합 비율 변화 | 25% |
| PII 위치를 문장 앞/중간/끝으로 변형 | 25% |
| 노이즈 추가 (오탈자, 공백 변형) | 20% |

### 4-3. 데이터셋 품질 기준

- **오프셋 정확성 검증**: 정답 `start`/`end`가 실제 `text[start:end]`와 일치하는지 자동 검증
- **레이블 일관성**: 동일 패턴에 대해 일관된 rule명 사용 (12개 Regex 규칙명과 정합)
- **Train/Val/Test 분할**: 70% / 15% / 15% (stratified by rule_name)
- **중복 제거**: SHA-256 기반 입력 텍스트 중복 제거

---

## 5. 학습 후 기능 정의

파인튜닝된 모델은 기존 `SLMStage`에서 다음 방식으로 동작합니다:

### 5-1. RegexStage 보완 역할

```
RegexStage (12개 규칙)
    │ Findings: kr_rrn, credit_card, kr_phone, email ...
    ▼
[Fine-tuned SLMStage] ← 이 단계가 교체됨
    │
    ├─ RegexStage가 탐지한 구간은 <<<...>>>로 마스킹 후 입력
    │  → 중복 탐지 방지 + SLM이 "나머지"에 집중
    │
    ├─ 탐지 대상: 문맥 의존적 PII
    │    - person_name (이름+소속 조합 판단)
    │    - address (자유형식 주소)
    │    - organization (개인과 연관된 기관명)
    │    - date_of_birth (YYYY.MM.DD, "태어난 날" 등 비정형)
    │    - medical_info (진단명, 처방약, 병원 정보)
    │    - biometric (지문, 홍채, 음성 등 언급)
    │
    └─ 탐지 제외:
         - 코드 블록 내 문자열
         - 예시/테스트 데이터 (홍길동, test@example.com)
         - 이미 마스킹된 플레이스홀더
```

### 5-2. 출력 형식 (Grammar 없이 학습으로 보장)

```json
[
  {
    "rule": "person_name",
    "start": 15,
    "end": 18,
    "text": "홍길동",
    "confidence": 0.92
  }
]
```

- `rule`: 위 카테고리 중 하나 (문자열)
- `start` / `end`: 입력 텍스트 기준 바이트 오프셋 (Python `str` 인덱스)
- `text`: `input_text[start:end]`와 일치해야 함
- `confidence`: 0.0~1.0 (0.5 미만은 SLMStage에서 자동 필터링)

### 5-3. GBNF Grammar 제거 가능성

파인튜닝 후:
1. **1차 시도**: Grammar 없이 실행 → 10회 샘플링으로 JSON 파싱 성공률 측정
2. **기준**: 파싱 실패율 < 1% 이면 Grammar 제거
3. **실패 시**: Grammar 유지하되 sampling token 수 절감 (MAX_TOKENS 512 → 256)

---

## 6. 학습 파이프라인 구현

### 6-1. 데이터 생성 스크립트

`tests/generate_slm_finetune_dataset.py`

```python
"""
SLM 파인튜닝용 Instruction 데이터셋 생성.
기존 CSV 데이터 변환 + 합성 데이터 생성.

출력: tests/slm_finetune_dataset.jsonl
  {"messages": [{"role":"system","content":"..."},
                {"role":"user","content":"<입력텍스트>"},
                {"role":"assistant","content":"<JSON배열>"}]}
"""
```

### 6-2. 학습 스크립트

`tests/train_slm_pii.py`

```python
"""
QLoRA 기반 Qwen2.5-1.5B PII 탐지 파인튜닝.

의존성:
  pip install transformers>=4.40 peft>=0.10 trl>=0.8
              bitsandbytes>=0.43 accelerate datasets

실행:
  python tests/train_slm_pii.py \
      --base_model Qwen/Qwen2.5-1.5B-Instruct \
      --dataset tests/slm_finetune_dataset.jsonl \
      --output_dir models/qwen2.5-1.5b-dlp-lora \
      --epochs 3 --batch_size 4 --grad_accum 4

주요 단계:
  1. 베이스 모델 로드 (4-bit NF4)
  2. LoRA 어댑터 설정
  3. SFTTrainer로 학습
  4. 최적 체크포인트 저장
"""
```

### 6-3. GGUF 변환 스크립트

`tests/export_slm_gguf.sh`

```bash
#!/bin/bash
# LoRA 병합 + GGUF Q4_K_M 변환
# 요구사항: llama.cpp 빌드 완료

LORA_DIR="models/qwen2.5-1.5b-dlp-lora"
MERGED_DIR="models/qwen2.5-1.5b-dlp-merged"
GGUF_OUT="models/qwen2.5-1.5b-dlp-q4_k_m.gguf"

# 1. LoRA 병합
python -c "
from peft import AutoPeftModelForCausalLM
import torch
model = AutoPeftModelForCausalLM.from_pretrained('$LORA_DIR', torch_dtype=torch.bfloat16)
model = model.merge_and_unload()
model.save_pretrained('$MERGED_DIR')
"

# 2. GGUF 변환 (llama.cpp convert 스크립트 사용)
python llama.cpp/convert_hf_to_gguf.py $MERGED_DIR \
    --outfile $GGUF_OUT --outtype q4_k_m

echo "완료: $GGUF_OUT"
```

### 6-4. slm_stage.py 교체

현재 저장소 기준으로는 GGUF fallback과 transformers adapter 경로를 각각 아래처럼 두는 편이 맞다.

```python
# slm_stage.py 경로 예시
DEFAULT_MODEL_PATH = str(
  Path(__file__).parents[3] / "models" / "qwen2.5-1.5b-dlp-q4_k_m.gguf"
)

DEFAULT_ADAPTER_MODEL_PATH = str(
  Path(__file__).parents[3] / "fine-tunning" / "sLM" / "merged_v5"
)
```

즉, 현재 첨부된 파인튜닝 산출물은 저장소 내부의 fine-tunning/sLM/merged_v5 아래에 두고,
엔진은 그 경로를 기본 adapter 모델 위치로 사용하면 된다.

---

## 7. 평가 지표 및 검증 계획

### 7-1. 평가 지표

| 지표 | 목표 | 측정 방법 |
|---|---|---|
| Precision | ≥ 0.85 | TP / (TP + FP) |
| Recall | ≥ 0.80 | TP / (TP + FN) |
| F1 Score | ≥ 0.82 | 조화평균 |
| Offset Accuracy | ≥ 0.90 | start/end 정확 일치율 |
| JSON Parse Rate | ≥ 0.99 | 파싱 성공률 |
| Avg Latency (GPU) | ≤ 150ms | 청크당 평균 추론 시간 |
| Avg Latency (CPU) | ≤ 5s | CPU-only 환경 |

### 7-2. 검증 데이터셋

`tests/fixtures/slm_eval/` 구성:

```
slm_eval/
├── pii_only.jsonl        # SLM만 탐지해야 하는 순수 PII (person_name, address 등)
├── code_context.jsonl    # 코드 내 PII-like 패턴 (모두 FP 정답)
├── mixed_kr_en.jsonl     # 한국어+영어 혼합 문서
├── masked_input.jsonl    # 이미 마스킹된 입력 포함
└── edge_cases.jsonl      # 경계 케이스 (이름이 1글자, 불완전한 주소 등)
```

### 7-3. 기존 파이프라인 회귀 테스트

파인튜닝 모델 교체 후 `tests/run_proto_regex_tests.py` 전체 통과 확인:

```bash
python tests/run_proto_regex_tests.py --with-slm
# Regex+SLM 파이프라인 전체 F1이 Regex-only 대비 향상되어야 함
```

---

## 8. 단계별 실행 계획

| 단계 | 작업 | 예상 소요 |
|---|---|---|
| **Phase 1** | 데이터 생성 (`generate_slm_finetune_dataset.py` 작성 + 실행) | 3일 |
| **Phase 2** | 학습 스크립트 작성 (`train_slm_pii.py`) | 1일 |
| **Phase 3** | QLoRA 학습 실행 (Google Colab Pro / Lambda Labs) | 2-4시간 (GPU) |
| **Phase 4** | GGUF 변환 + `slm_stage.py` 교체 | 30분 |
| **Phase 5** | 평가 및 회귀 테스트 | 1일 |
| **Phase 6** | (선택) DPO로 FP 추가 감소 | 1일 |

### Phase 6 선택적 확장: DPO (Direct Preference Optimization)

SFT 이후 FP가 여전히 높을 경우:

```
DPO 학습 데이터:
  chosen: 정확한 탐지 + 코드 FP 올바르게 제외한 응답
  rejected: 코드 내 문자열을 PII로 탐지한 응답
            또는 오프셋이 틀린 응답

목표: 코드 문맥 오탐률 ≤ 2%로 추가 감소
```

---

## 9. 기대 효과 요약

```
[현재 파이프라인]                    [파인튜닝 후]
RegexStage (12규칙)                  RegexStage (12규칙)
    ↓                                    ↓
SLMStage (범용 Gemma 2B)     →     SLMStage (DLP 특화 Qwen 1.5B)
- 한국어 PII 재현율: ~50%            - 한국어 PII 재현율: ~80%+
- 코드 FP: ~20%                      - 코드 FP: ~5%이하
- GBNF grammar 필요                  - Grammar 없이 JSON 출력
- 시스템 프롬프트 의존성 높음        - 태스크 내재화 (프롬프트 단순화)
- 추론 1.5B보다 느림                  - 추론 속도 25% 향상
```

---

## 10. 리소스 요구사항

### 학습 환경 (권장)

| 항목 | 최소 | 권장 |
|---|---|---|
| GPU | RTX 3060 12GB | A100 40GB |
| RAM | 16GB | 32GB |
| 저장소 | 30GB (베이스 모델 + 체크포인트) | 50GB |
| 학습 시간 | ~4시간 (3060) | ~45분 (A100) |

### 클라우드 옵션

- **Google Colab Pro+**: A100 40GB, 월 $50 → 학습 1회 약 $3
- **Lambda Labs**: A10 24GB, 시간당 $0.60 → 학습 1회 약 $3
- **Runpod**: RTX 4090 24GB, 시간당 $0.74

### 추론 환경 (프로덕션)

현재와 동일 — llama-cpp-python + GGUF Q4_K_M:
- Apple Silicon: Metal GPU (~100ms/청크)
- NVIDIA GPU: CUDA (~80ms/청크)  
- CPU-only: (~3-5s/청크, 파라미터 감소로 현재보다 빠름)
