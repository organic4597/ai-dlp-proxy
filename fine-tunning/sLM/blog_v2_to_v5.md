# Qwen3.5-4B로 DLP 전용 PII 탐지 SLM 만들기 — v2부터 v5까지의 시행착오

> 사내 DLP(Data Loss Prevention) 프록시의 SLM 스테이지를 Gemma-2 2B (GGUF)에서
> Qwen3.5-4B QLoRA 파인튜닝 모델로 교체하는 과정. 4번의 학습/평가 사이클을
> 거치며 F1 0.62 → 0.91+로 개선한 기록.

---

## 0. 배경

기존 DLP 파이프라인은 다음과 같은 다단계 방어 구조를 사용한다.

```
사용자 프롬프트 / tool_result
  → Regex 스테이지         (kr_rrn, credit_card, jwt_token 등 결정적 패턴)
  → Asset 스테이지         (.env, kubeconfig 등 키워드 + 임베딩)
  → SLM 스테이지           ← 본 글의 대상
  → ML False-Positive 필터
  → protection_action 결정 + 마스킹
```

SLM이 필요한 이유는 **regex로 못 잡는 문맥의존 PII** 때문이다.

- `홍길동님 010-... 으로 연락` 의 자연어 이름
- `address: 서울시 강남구 테헤란로 152` 의 자유형식 주소
- `db_url=postgresql://prod:Secret@10.0.0.5/app` 같은 자격증명 결합
- tool_result 안의 자연어 PII

기존 SLM은 **Gemma-2 2B Q4_K_M GGUF + GBNF grammar + llama-cpp**로 구동.
요청당 100~300ms, F1 약 0.55 수준. 이걸 Qwen3.5-4B 풀 LoRA 학습 모델로 갈아치우는 게 목표.

### 환경

| 항목 | 값 |
|---|---|
| 베이스 | `Qwen/Qwen3.5-4B` (Gated DeltaNet 하이브리드, 8 attn + 24 deltanet) |
| GPU | RTX 4070 SUPER 12 GB |
| 학습 | QLoRA 4bit NF4, bf16 compute |
| LoRA | r=16, α=32, target=`qk_proj` 등 |
| 데이터 | train 12,398건 / eval 790건 |
| 라벨 | `person_name, kr_phone, kr_rrn, email, address, ip_address, credential, api_key, jwt_token` 외 6종 |

---

## 1. v2 — 베이스라인: 길이가 곧 한계였다

| 설정 | 값 |
|---|---|
| max_seq | 1024 |
| epochs | 3 |
| batch / grad_accum | 1 / 16 |
| 학습 시간 | ~4 h |

**결과 (eval 790건):**

| Precision | Recall | F1 |
|---|---|---|
| 0.912 | 0.465 | **0.616** |

오탐(FP) 189건, **미탐(FN) 2257건**. Precision은 높은데 Recall이 처참. 즉,
**모델이 "확신하는 것만 답하지만, 절반은 그냥 놓치는" 상태**.

원인 가설:
- 학습 시퀀스가 1024 토큰으로 잘려서, 긴 코드/CSV/멀티턴 대화의 뒷부분 PII가 학습 자체에서 빠짐
- assistant 출력 라벨도 잘려나가 일부 정답이 학습 손실로 흘러들지 못함

---

## 2. v3 — epochs를 3 → 5로 늘려 봤다

| 설정 | 값 |
|---|---|
| max_seq | 1024 (그대로) |
| epochs | 5 |
| 학습 시간 | ~5 h |
| train_loss | 0.541 |
| eval_loss | 0.0473 (loss는 분명 더 떨어짐) |

**결과:**

| 지표 | v2 | v3 | Δ |
|---|---|---|---|
| Precision | 0.912 | 0.914 | +0.002 |
| Recall | 0.465 | 0.476 | +0.011 |
| **F1** | **0.616** | **0.626** | +0.010 |

학습 loss는 잘 내려갔는데 평가는 거의 그대로. **train/eval gap은 줄었지만
test set에서 효과가 미미**. 더 학습한다고 해결될 문제가 아니었다.

이 시점에 FP 분석 도구(`scripts/analyze_eval.py`)를 만들어 들여다보니, 흥미로운
패턴을 발견했다.

```
[unknown] FP=174건
  · (rule_mismatch) 'MyDB_Pass!@#'           ← PII는 맞는데 rule 분류 틀림
  · (false_positive) 'sk-test-fake-key'      ← 명백한 fake/test 데이터
  · (false_positive) 'user@example.com'      ← 예시 도메인
  · (false_positive) '10.0.0.1'              ← 사설 IP
[email] FP=18건
  · 'ychoi%40hyundai.com'                    ← URL-encoded 이메일 디코드 (똑똑한 탐지)
[credential] FP=16건
  · 'postgresql://prod:Prod#Secret789@...'   ← 운영 관점에선 좋은 탐지
```

**FP의 50% 이상은 사실 모델이 "더 보수적으로/똑똑하게" 잡은 것**이었다.
정답 라벨러가 fake/test/사설IP를 PII에서 제외했을 뿐. DLP 관점에서는 오히려 칭찬할 일.

진짜 문제는 FN 2200건. 이건 **학습 시퀀스가 잘려서 모델이 못 본 부분이 너무 많다**는 신호.

---

## 3. v4 — max_seq 4배(4096) 시도, 그러나 좌초

가설: **컨텍스트 길이가 부족했다**. v2/v3는 max_seq=1024라서 긴 멀티턴 대화나
코드 블록은 학습 데이터에서 뒷부분이 잘려 학습 자체가 안 됐다.

v4 설정:
- max_seq: **1024 → 4096** (4배)
- attn_implementation: **`flash_attention_2`** 시도

결과: **FA2 + Qwen3.5 GatedDeltaNet 하이브리드 비호환** 충돌로 학습 중단.

```
torch.AcceleratorError: CUDA error: an illegal memory access
  at: _flash_attention_forward → is_fa_with_position_ids
```

원인: Qwen3.5는 8개의 표준 attention layer와 24개의 GatedDeltaNet layer가
교차 배치되는 하이브리드. 표준 attention layer로 흘러가는 position_ids가 FA2의
varlen 처리 경로와 충돌.

**해결**: `attn_implementation="sdpa"`로 변경. PyTorch 2.10 내장 SDPA의
memory-efficient kernel은 FA2와 거의 동등한 성능을 내면서 하이브리드 모델과 호환.

v4는 ~50% 진행 시점에 SSH 세션 종료로 의도치 않게 중단됐고, 그대로 v5로 넘어가기로 결정.

---

## 4. v5 — 컨텍스트 4096 + sdpa + batch 2 로 재출발

| 설정 | v3 | v5 |
|---|---|---|
| max_seq | 1024 | **4096** |
| epochs | 5 | 4 |
| batch / grad_accum | 1 / 16 (eff=16) | **2 / 8** (eff=16) |
| attn_implementation | eager | **sdpa** |
| 학습 시간 | 5 h | **5.5 h** |
| step 시간 | ~16 s/step | **~7 s/step** |
| VRAM | ~6 GB | ~9 GB |

핵심 결정:
1. **batch=2로 올리되 grad_accum=8로 줄여 effective batch는 동일하게 유지**.
   학습 step의 절반인데도 GPU 활용률이 50% → 97%로 올라가면서 wall-clock도 빨라짐.
2. **nohup + 백그라운드 실행**으로 SSH 세션 종료에 영향받지 않게.

학습 결과:

```
train_loss : 0.594
eval_loss  : 0.0485
epochs     : 4
runtime    : 19,880 s (~5.5 h)
```

평가 결과 (790건 전체 완료):

| 지표 | v3 | **v5 (최종)** | Δ |
|---|---|---|---|
| Precision | 0.9140 | **0.9659** | +0.052 |
| Recall | 0.4763 | **0.8729** | +0.397 |
| **F1** | **0.6262** | **0.9171** | **+0.291** |
| TP | 2009 | **3682** | ×1.83 |
| FP | 189 | **130** | -31% |
| FN | 2209 | **536** | **-76%** |

**FN이 76% 감소, TP가 1.83배 증가**. max_seq 확장이 진짜 답이었다는 게 명백히 보인다.
긴 컨텍스트의 후반부에 있던 PII들을 모델이 학습 단계에서 처음 "본" 것이다.

### 라벨별 결과 (v5 최종)

| rule_id | TP | FP | FN | P | R | F1 | 비고 |
|---|---:|---:|---:|---:|---:|---:|---|
| `aws_secret_key` | 35 | 0 | 0 | 1.000 | 1.000 | **1.000** | 완벽 |
| `jwt_token` | 12 | 0 | 0 | 1.000 | 1.000 | **1.000** | 완벽 |
| `email` | 355 | 15 | 23 | 0.959 | 0.939 | 0.949 | URL-encoded(`%40`) 오탐 |
| `api_key` | 125 | 1 | 10 | 0.992 | 0.926 | 0.958 | 정규화 잘 작동 |
| `kr_phone` | 859 | 7 | 76 | 0.992 | 0.919 | 0.954 | |
| `address` | 580 | 0 | 73 | 1.000 | 0.888 | 0.941 | FP 0 |
| `person_name` | 1056 | 14 | 141 | 0.987 | 0.882 | 0.932 | |
| `credential` | 151 | 14 | 25 | 0.915 | 0.858 | 0.886 | 경계 오인식 |
| `aws_access_key` | 26 | 0 | 9 | 1.000 | 0.743 | 0.852 | rule_mismatch 9건 |
| `ip_address` | 175 | 6 | 60 | 0.967 | 0.745 | 0.841 | |
| `kr_rrn` | 250 | 16 | 103 | 0.940 | 0.708 | 0.808 | `RRN:` 접두 포함 |
| `credit_card` | 33 | 0 | 16 | 1.000 | 0.673 | 0.805 | rule_mismatch 16건(AMEX) |
| `private_key` | 0 | 0 | 1 | — | 0.000 | 0.000 | **학습 데이터 부족** |
| `credential_b64` | 0 | 0 | 16 | — | 0.000 | 0.000 | **학습 데이터 부족** |
| `api_key_b64` | 0 | 0 | 8 | — | 0.000 | 0.000 | **학습 데이터 부족** |

### FP/FN 패턴 분석

**1. 후처리로 즉시 잡을 수 있는 항목** (어댑터 보강만으로 해결)
- `email` FP 다수: `%40`(URL-encoded `@`) — 디코드 후 재라벨링 가능
- `kr_rrn` FP: `RRN:` 접두 포함 / `000000-0000000` 더미값 — span trim + 화이트리스트
- `credential` FP: `prod:Pass@host` 결합 패턴 — span boundary 규칙

**2. rule_id 정규화 누락** (어댑터 RULE_NORMALIZE 확장 필요)
- `credit_card` FN 16건 = AMEX 형식(`3714-496353-98431`)을 다른 라벨로 출력
- `aws_access_key` FN 9건 = 동일하게 rule_mismatch
- → **정규화 매핑만 추가해도 F1 0.917 → ~0.93 도달 예상**

**3. 학습 데이터 부족** (v6 데이터 보강 필요)
- `private_key`, `credential_b64`, `api_key_b64` 3종은 학습셋에 거의 없어 모델이 못 배움

**4. 일관된 미탐 패턴**
- `person_name`/`kr_rrn`/`address` FN이 동일 idx(27/38/67/88 등)에서 반복 → 특정 문서 포맷(긴 테이블/리스트)에서 줄단위 누락. chunk overlap 200 → 400 상향으로 회수 가능.

**5. 진짜 오탐은 매우 적음**
- `unknown` FP 79건 중 진짜 오탐은 54건뿐, 그것도 날짜/시간/`DATABASE_URL` 같은 경계성. 후단 룰 화이트리스트로 손쉽게 차단.

---

## 5. 종합 비교

```
              Precision   Recall    F1     train_loss   eval_loss
─────────────────────────────────────────────────────────────────
v2 (1024,3e)    0.912     0.465    0.616      —           —
v3 (1024,5e)    0.914     0.476    0.626    0.541       0.0473
v4 (4096+FA2)   ───── 학습 좌초 (FA2 호환성) ─────
v5 (4096+sdpa)  0.966     0.873    0.917    0.594       0.0485
```

**핵심 교훈:**

1. **eval_loss 만 보고 만족하면 안 된다.** v3의 eval_loss는 v5보다 더 낮았지만
   F1은 압도적으로 떨어졌다. token-level cross-entropy는 잘려서 보지도 못한
   PII에 대해서는 침묵한다.
2. **max_seq는 단순한 메모리 변수가 아니다.** 데이터의 분포에 맞춰 잡지 않으면
   학습 자체가 절반의 정보로 진행된다.
3. **하이브리드 아키텍처는 attention 구현 선택에 민감.** Qwen3.5처럼 GatedDeltaNet과
   표준 attention이 섞인 모델에선 FA2 대신 sdpa가 안전.
4. **batch size를 키우고 grad_accum을 줄이면** effective batch가 같아도 GPU
   throughput이 크게 오른다. VRAM 여유만 있다면 무조건 이득.
5. **FP 절반은 "좋은" FP였다.** 라벨러가 PII에서 빼버린 fake/test 데이터,
   사설 IP, URL-encoded PII를 모델이 잡은 것. DLP 관점에선 오히려 안전망.

---

## 6. 다음 단계

### 6.1 즉시 가능 (코드 변경만, 재학습 X)

**[A] `slm_adapter.py` RULE_NORMALIZE 확장** — 예상 F1 +1.5%p
```python
RULE_NORMALIZE = {
    "api_key": "api_key_assignment",
    "private_key": "pem_private_key",
    # 신규 추가
    "card_number": "credit_card",       # AMEX 패턴 흡수
    "amex": "credit_card",
    "aws_key": "aws_access_key",        # AKIA... 패턴 흡수
    "access_key": "aws_access_key",
}
```

**[B] 후처리 정규화 레이어** — 예상 FP 30~40건 추가 감소
- `email` span에서 `%40` → `@` 디코드 후 boundary 재계산
- `kr_rrn` span 앞의 `RRN:` `주민번호:` 등 prefix trim
- `000000-0000000`, `user@example.com`, `127.0.0.1` 등 더미/예시 화이트리스트
- `credential` span 분리: `host:user:pass@ip` → 자격증명 부분만 추출

**[C] chunk overlap 200 → 400** — person_name/address FN 회수 시도
- 현재 chunk_text(2400자, overlap 200)에서 줄 경계 근처 PII 누락 패턴 관측
- overlap 두 배로 늘리고 recover_spans dedup이 잘 작동하는지 회귀 테스트

**[D] 원격 `slm_stage.py` 교체**
- 출력 schema 호환: `{rule, start, end, text, confidence}`
- prior_findings 50% overlap dedup
- multi-target `detect_combined()` (호출 횟수 절감)
- 기존 GGUF 코드는 `slm_stage_gguf.py.bak`으로 백업, 환경변수로 fallback 가능하게

### 6.2 v6 학습 후보 (재학습 필요)

**[E] 데이터 보강** — `private_key`, `credential_b64`, `api_key_b64` 라벨
- 각 라벨당 최소 200~500건 합성 데이터 추가
- PEM 헤더(`-----BEGIN ... PRIVATE KEY-----`), Base64 패턴 다양화
- 자연어 컨텍스트(이메일/도커파일/CI 로그) 안에 매립

**[F] 라벨링 일관성 정리** — `unknown` FP 54건 분석 기반
- fake/test 샘플(`sk-test-...`, `dummy_user_1`) 정책 결정: 탐지 vs 무시
- 사설 IP / 예시 도메인 일관 처리
- DLP 정책팀과 협의 후 데이터 재라벨

**[G] LoRA r 16 → 32 실험**
- person_name/address recall 추가 향상 가능성 (현재 0.88~0.89)
- VRAM 여유 있음 (현재 9GB / 12GB)

**[H] 추론 최적화**
- vLLM 적용 → throughput 측정
- GGUF Q5_K_M 변환 → 정확도 손실 측정 (목표: F1 손실 < 1%p)
- batch inference path (다중 target 동시 처리)

### 6.3 운영 적용 (별도 트랙)

**[I] 회귀 테스트 자동화**
- eval_v2 + 신규 production trace sample을 CI에 등록
- F1 임계값 미달 시 배포 차단

**[J] Confidence calibration**
- 현재 confidence는 logprob 기반 0.85 고정값에 가까움 → 보정 필요
- ML False-Positive 필터 단계의 입력으로 쓸 수 있게 분포 조정

**[K] 모니터링 지표**
- per-rule 탐지 건수, latency p50/p95/p99
- 실 트래픽에서의 PII 분포 vs 학습셋 분포 drift 감지
- 신규 `unknown` 라벨 출현 빈도 추적 → 학습셋 보강 트리거

### 우선순위 요약

| 우선순위 | 항목 | 예상 효과 | 비용 |
|---|---|---|---|
| **P0** | [A] RULE_NORMALIZE 확장 | F1 +1.5%p | 10분 |
| **P0** | [D] slm_stage.py 교체 | 운영 투입 | 반나절 |
| P1 | [B] 후처리 정규화 | FP -30건 | 2~3시간 |
| P1 | [I] 회귀 테스트 | 안정성 | 반나절 |
| P2 | [C] chunk overlap 상향 | FN 회수 | 1시간 + 평가 |
| P2 | [E] v6 데이터 보강 | b64/pem F1 0 → 0.7+ | 1~2일 + 학습 5h |
| P3 | [G] LoRA r=32 | F1 +0.5%p? | 학습 6h |
| P3 | [H] vLLM/GGUF | latency | 1일 |

---

## 부록 A. 학습 명령

```bash
CUDA_VISIBLE_DEVICES=0 PYTORCH_ALLOC_CONF=expandable_segments:True \
nohup python3 scripts/train_dlp_slm.py \
  --model Qwen/Qwen3.5-4B \
  --train data/slm_train_dataset_v4.jsonl \
  --eval  data/slm_eval_dataset_v2.jsonl \
  --output output/lora_v5 --merged output/merged_v5 \
  --epochs 4 --batch-size 2 --grad-accum 8 \
  --lr 2e-4 --max-seq 4096 \
  --lora-r 16 --lora-alpha 32 --use-qlora \
  >> logs/train_v5.log 2>&1 &
```

## 부록 B. 평가 + FP 분석 명령

```bash
# 평가
PYTHONUNBUFFERED=1 CUDA_VISIBLE_DEVICES=0 \
python3 scripts/eval_v2.py \
  --model output/merged_v5 \
  --eval  data/slm_eval_dataset_v2.jsonl \
  --out   logs/eval_v2_results_v5.jsonl

# FP/FN 분석
python3 scripts/analyze_eval.py \
  --in logs/eval_v2_results_v5.jsonl \
  --top 10 --kind both \
  --out logs/fp_fn_v5.txt
```

## 부록 C. SLM 추론 어댑터 사용

```python
from slm_adapter import SLMAdapter

adapter = SLMAdapter("output/merged_v5", device="cuda")

# 단일 텍스트
findings = adapter.detect("내 이메일은 hong@test.kr 입니다")
# → [{"rule": "email", "start": 7, "end": 19, "text": "hong@test.kr", "confidence": 0.85}]

# 다중 target (원격 SLMStage.scan 패턴)
results_per_target = adapter.detect_combined(
    texts=["text1", "text2", "text3"],
    prior_ranges_per_text=[[(0, 10)], [], []],   # regex가 이미 잡은 영역
)
```
