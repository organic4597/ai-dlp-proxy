# DLP sLM (Qwen3.5-4B v5) — 사용 안내

> 현재 저장소 기준 경로: /home1/ai-dlp-proxy/fine-tunning/sLM/

## 1. 디렉터리 구성

```
/home1/ai-dlp-proxy/fine-tunning/sLM/
├── merged_v5/                 # 풀 병합 모델 (HF safetensors, 3.0 GB)
│   ├── config.json
│   ├── generation_config.json
│   ├── model.safetensors
│   ├── tokenizer.json
│   ├── tokenizer_config.json
│   └── chat_template.jinja
├── slm_adapter.py             # 추론 어댑터 (이 파일을 import 해서 사용)
├── blog_v2_to_v5.md           # v2~v5 학습 시행착오 + 결과 분석
└── README_sLM.md              # (이 문서)
```

## 2. 모델 스펙

| 항목 | 값 |
|---|---|
| 베이스 | Qwen/Qwen3.5-4B (Gated DeltaNet 하이브리드) |
| 학습 | QLoRA 4bit NF4 → merge & save (fp16) |
| max_seq | 4096 |
| LoRA | r=16, α=32 |
| 평가 (eval_v2 790건) | **F1 0.917 / P 0.966 / R 0.873** |

## 3. 의존성

```bash
pip install --upgrade transformers>=4.46 accelerate>=1.0 torch>=2.4 safetensors
# (선택) 4bit 로딩
pip install bitsandbytes>=0.43
```

GPU 권장: VRAM ≥ 10 GB (fp16 로딩 기준 ~8 GB).
GPU 부족 시 `load_in_4bit=True` 옵션 사용.

## 4. 빠른 사용 예

```python
import sys
sys.path.insert(0, "/home1/ai-dlp-proxy/fine-tunning/sLM")
from slm_adapter import SLMAdapter

adapter = SLMAdapter(
    model_path="/home1/ai-dlp-proxy/fine-tunning/sLM/merged_v5",
    device="cuda",        # CPU는 사실상 비실용
    dtype="fp16",         # "fp16" | "bf16" | "int4"
)

# 단일 텍스트
findings = adapter.detect("내 이메일은 hong@test.kr, 폰 010-1234-5678")
# → [{"rule": "email", "start": 7, "end": 19, "text": "hong@test.kr", "confidence": 0.85},
#    {"rule": "kr_phone", "start": 24, "end": 37, "text": "010-1234-5678", ...}]

# Regex/Asset 단계가 이미 잡은 영역 제외
findings = adapter.detect(
    "user=root pw=Secret123",
    prior_ranges=[(0, 9)],          # "user=root" 부분은 모델이 다시 잡지 않게
)

# 다중 target 한번에 (멀티턴 메시지/툴결과 묶음 추론)
results_per_target = adapter.detect_combined(
    texts=["text1", "text2", "text3"],
    prior_ranges_per_text=[[(0, 10)], [], []],
)
```

### 출력 schema

```json
{
  "rule": "email | kr_phone | kr_rrn | address | person_name | ip_address | "
          "credential | api_key_assignment | pem_private_key | "
          "aws_access_key | aws_secret_key | jwt_token | credit_card | ...",
  "start": 12,        // 원문 문자열의 char offset
  "end":   24,
  "text":  "hong@test.kr",
  "confidence": 0.85
}
```

> 어댑터 내부에서 라벨 정규화를 수행:
> - `api_key` → `api_key_assignment`
> - `private_key` → `pem_private_key`
> 이외 라벨은 그대로 통과.

## 5. 기존 SLM 스테이지 교체 가이드

현재 저장소의 [src/engine/pipeline/slm_stage.py](src/engine/pipeline/slm_stage.py)는
기본적으로 /home1/ai-dlp-proxy/fine-tunning/sLM/merged_v5 를 보도록 맞춰져 있다.
아래 예시는 standalone import가 필요할 때만 사용하면 된다.

기존 `slm_stage.py` (Gemma GGUF 기반) → 새 `SLMAdapter` 교체:

```python
# /home1/ai-dlp-proxy/src/engine/pipeline/slm_stage.py (가이드)

import sys
sys.path.insert(0, "/home1/ai-dlp-proxy/fine-tunning/sLM")
from slm_adapter import SLMAdapter

class SLMStage:
    def __init__(self, ...):
        self._adapter = SLMAdapter(
            model_path="/home1/ai-dlp-proxy/fine-tunning/sLM/merged_v5",
            device="cuda",
            dtype="fp16",
        )

    def scan(self, targets, prior_findings_per_target=None):
        # prior_findings → (start, end) 튜플 리스트로 변환
        prior_ranges = [
            [(f["start"], f["end"]) for f in (pf or [])]
            for pf in (prior_findings_per_target or [[]] * len(targets))
        ]
        results = self._adapter.detect_combined(
            texts=[t["text"] for t in targets],
            prior_ranges_per_text=prior_ranges,
        )
        return results   # [[finding, ...], [finding, ...], ...]
```

호환 포인트:
- `prior_findings`의 `(start, end)` 50% overlap 시 자동 dedup
- `text` 길이 > 2400자면 자동으로 chunk + recover_spans
- 출력 confidence는 logprob 기반 (현재 0.85 근처 고정값에 가까움)

## 6. 성능 (v5 평가, eval_v2 dataset n=790)

```
Precision : 0.9659
Recall    : 0.8729
F1        : 0.9171
TP=3682  FP=130  FN=536
```

| rule_id | F1 | 비고 |
|---|---:|---|
| `aws_secret_key`, `jwt_token` | 1.000 | 완벽 |
| `email` | 0.949 | URL-encoded(`%40`) 일부 오탐 |
| `api_key`, `kr_phone` | 0.954–0.958 | 정규화 적용 |
| `address` | 0.941 | FP 0 |
| `person_name` | 0.932 | |
| `credential` | 0.886 | 경계 오인식 |
| `aws_access_key` | 0.852 | rule_mismatch 9건 |
| `ip_address` | 0.841 | |
| `kr_rrn` | 0.808 | `RRN:` prefix 오탐 |
| `credit_card` | 0.805 | AMEX rule_mismatch |
| `private_key`, `credential_b64`, `api_key_b64` | 0.000 | 학습 데이터 부족 |

상세 분석 → `blog_v2_to_v5.md` 참조.

## 7. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `OSError: model.safetensors not found` | `model_path` 가 /home1/ai-dlp-proxy/fine-tunning/sLM/merged_v5 디렉터리를 정확히 가리키는지 확인 |
| `CUDA out of memory` | `dtype="int4"` 로 변경 (bitsandbytes 필요) 또는 `max_new_tokens` 축소 |
| FA2 관련 illegal memory access | 어댑터 내부에서 **sdpa**로 강제 설정 — 변경 금지 (Qwen3.5 하이브리드 호환) |
| 처음 호출이 느림 | warm-up 1회 권장: `adapter.detect("warmup")` |
| chunk 경계에서 PII 일부 누락 | `chunk_text(..., overlap=400)`로 상향 (현재 200) |

## 8. 향후 작업 (요약)

- **즉시**: `RULE_NORMALIZE`에 `card_number→credit_card`, `aws_key→aws_access_key` 매핑 추가 → F1 +1.5%p 예상
- **단기**: email `%40` 디코드, `kr_rrn` prefix trim, dummy 화이트리스트
- **중기 (v6 재학습)**: `private_key` / `credential_b64` / `api_key_b64` 데이터 보강
- **장기**: vLLM 서빙 또는 GGUF 변환으로 latency 최적화

상세 로드맵 → `blog_v2_to_v5.md` §6 참조.
