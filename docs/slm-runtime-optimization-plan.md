# SLM 런타임 최적화 및 어댑터 통합 계획서

> 작성일: 2026-05-14
> 범위: Regex 미처리 영역만 SLM으로 전달하는 런타임 패치 + Qwen3.5-4B 어댑터 보강
> 결론: 학습 데이터/라벨 체계는 유지하고, 추론 단계만 개선한다.

---

## 1. 배경 및 결론

원격 검증 결과를 기준으로 현재 방향은 다음처럼 정리된다.

| 항목 | 결론 |
|---|---|
| 학습 데이터/라벨 분포 | 변경 없음 |
| 라벨 불일치 2건 | 추론 단계 정규화로 해결 (`api_key -> api_key_assignment`, `private_key -> pem_private_key`) |
| severity 결정 | `control.py`의 `_SEVERITY_MAP` 사용 — SLM은 `rule`만 반환하면 됨 |
| 출력 스키마 | `{rule, start, end, text, confidence}` 유지 |
| 런타임 병목 | Regex가 이미 처리한 span까지 SLM 입력으로 다시 보내는 구조 |

핵심 판단은 다음과 같다.

1. **v5 학습은 그대로 진행한다.**
2. **v6 재학습은 하지 않는다.**
3. **패치 범위는 런타임 SLM 입력 축소 + 어댑터 정규화/중복 제거 보강으로 한정한다.**

---

## 2. 현재 문제

현재 파이프라인은 Regex/Asset이 effective finding을 만든 뒤에도, 해당 target의 전체 텍스트를 마스킹한 상태로 SLM에 전달한다.

현재 흐름:

```
Regex/ML/Asset/NMS
    -> effective_findings 계산
    -> target 전체를 마스킹
    -> SLM 입력
    -> SLM 결과를 prior_ranges와 50% overlap 기준으로 후처리 제거
```

이 구조의 문제는 다음과 같다.

1. **입력 비용 낭비**
   - Regex가 이미 처리한 span도 placeholder 형태로 SLM 프롬프트에 남는다.
   - 긴 `tool_result`, 긴 history, 다중 target에서 토큰 낭비가 크다.

2. **중복 제거가 추론 후에만 일어남**
   - 지금도 prior overlap 50% 필터는 있지만, 이미 추론 비용은 지불한 뒤다.

3. **긴 텍스트에서 chunk 수 증가**
   - 현재 `CHUNK_CHARS=1500`, `OVERLAP_CHARS=30`
   - 이미 처리된 span이 많아도 chunk 계산에는 그대로 반영된다.

4. **Regex confidence가 있지만 입력 축소에는 활용되지 않음**
   - threshold 이상이며 `suppressed=False`인 finding은 사실상 "이미 처리된 구간"인데,
     현재는 결과 필터링에만 쓰이고 SLM 입력 축소에는 반영되지 않는다.

---

## 3. 목표 / 비목표

### 목표

1. **Regex/Asset effective finding이 덮은 구간은 SLM 입력에서 제외한다.**
2. **SLM은 이름/주소/기관명 등 Regex가 못 잡는 잔여 문맥에 집중한다.**
3. **기존 출력 스키마와 후처리 규칙은 유지한다.**
4. **Qwen 어댑터 교체 시에도 동일한 처리 원칙을 유지한다.**

### 비목표

1. 학습 데이터셋 재구성
2. 라벨 체계 변경
3. severity 계산 로직 변경
4. Regex Stage의 confidence 계산식 변경

---

## 4. 핵심 설계 원칙

1. **Structured secret는 Regex가 우선권을 가진다.**
   - 주민등록번호, 카드번호, API key, PEM key 등은 Regex/validator 결과를 신뢰한다.

2. **SLM은 미처리 영역만 본다.**
   - threshold 이상이며 `suppressed=False`인 finding이 덮은 span은 SLM 입력 대상에서 제외한다.

3. **threshold 미달 / suppressed finding은 미처리로 간주한다.**
   - allowlist, ML FP 필터, NMS로 억제된 finding은 SLM 입력 축소 기준에 포함하지 않는다.

4. **오프셋은 원문 기준으로 복원 가능해야 한다.**
   - windowed input을 도입해도 최종 `match_start`, `match_end`는 원래 target 기준이어야 한다.

5. **우선은 런타임 최적화, 그 다음 어댑터 교체다.**
   - 현재 GGUF/llama-cpp 경로에서도 먼저 이득을 본 뒤, Qwen 어댑터를 붙인다.

---

## 5. 제안 패치 설계

### 5-1. covered span 산출 기준

SLM 입력 축소에 사용할 covered span은 다음 조건을 만족하는 finding만 포함한다.

```python
finding.confidence >= control.confidence_threshold
and not finding.suppressed
and finding.stage in {"regex", "asset"}
```

이 기준을 쓰는 이유:

- `regex`: structured secret는 이미 처리 완료
- `asset`: 보호 자산 탐지 결과도 SLM 재확인 가치가 낮음
- `slm`: SLM 실행 전 단계에서는 존재하지 않으므로 제외
- `suppressed=True`: 실제 정책상 처리되지 않는 finding이므로 covered span으로 쓰면 안 됨

### 5-2. target 전체 skip 대신 unresolved window 생성

단순히 target 전체를 스킵하면 이름/주소 같은 문맥형 PII를 놓칠 수 있다.
따라서 target 전체 skip이 아니라 **미처리 영역(unresolved span) 중심 window**를 만든다.

기본 흐름:

```
target.text
    -> covered spans (effective regex/asset)
    -> invert spans = unresolved spans
    -> unresolved span 앞뒤로 margin 확장
    -> 가까운 window 병합
    -> 너무 짧은 window 제거
    -> 남은 window만 SLM 입력
```

권장 기본값:

| 상수 | 제안값 | 의미 |
|---|---:|---|
| `SLM_WINDOW_MARGIN` | 50 | 미처리 영역 앞뒤로 보존할 문맥 길이 |
| `SLM_MIN_WINDOW_CHARS` | 40 | 이보다 짧은 window는 SLM 가치 낮음 |
| `SLM_MERGE_GAP` | 30 | window 사이 간격이 이 값 이하면 병합 |
| `SLM_SKIP_COVERAGE_RATIO` | 0.80 | covered 비율이 높을 때 target 전체 skip 검토 |
| `SLM_SKIP_REMAINING_CHARS` | 120 | 남은 비마스킹 텍스트가 이 값 미만이면 skip |

### 5-3. 권장 skip 규칙

아래 순서로 적용한다.

1. 기존 role skip 유지
   - `system`, `assistant`, `tool_def`

2. SLM cache hit면 skip

3. unresolved span이 없으면 skip

4. `coverage_ratio >= 0.80` 이고 `remaining_chars < 120` 이면 skip

5. 남은 window가 모두 40자 미만이면 skip

이렇게 하면 "Regex가 거의 다 처리한 target"은 SLM에서 빠지고,
정말 문맥이 필요한 일부 target만 SLM에 남게 된다.

### 5-4. window offset 복원

windowed input을 쓰면 SLM 출력 offset이 원문 기준이 아니게 된다.
따라서 각 SLM 입력 target에는 최소한 다음 정보가 필요하다.

| 필드 | 의미 |
|---|---|
| `field_path` | 원래 target 식별자 |
| `role` | 원래 role |
| `text` | window 텍스트 |
| `history` | history 여부 |
| `base_offset` | 원문 target 내에서 window 시작 위치 |

SLM 결과를 원문 기준으로 복원할 때:

```python
final_start = base_offset + local_start
final_end   = base_offset + local_end
```

### 5-5. combined text 1회 추론 패턴 유지

현재 `SLMStage.scan()`의 장점은 여러 target을 합쳐 한 번에 추론하고,
그 결과를 target별로 다시 나누는 데 있다.

이 패턴은 유지한다.

변경 후 흐름:

```
원래 targets
    -> windowed slm_targets 생성
    -> combined text 1회 추론
    -> target별 + base_offset 기준으로 원문 좌표 복원
```

즉, 호출 패턴은 유지하되 입력 크기만 줄인다.

---

## 6. Qwen 어댑터 보강 설계

학습은 바꾸지 않고, `slm_adapter.py`에서 다음 기능을 제공한다.

### 6-1. rule 정규화

```python
RULE_NORMALIZE = {
    "api_key": "api_key_assignment",
    "private_key": "pem_private_key",
}
```

`parse_model_output()`에서 즉시 정규화하여 기존 `control.py`와 호환되게 한다.

### 6-2. prior overlap 필터

```python
filter_by_prior(detections, prior_ranges, ratio=0.5)
```

의미:
- Regex가 이미 잡은 범위와 50% 이상 겹치면 SLM detection 제거
- 현재 `SLMStage`의 중복 제거 규칙을 어댑터 단계로 보존

### 6-3. combined 추론 지원

```python
SLMAdapter.detect_combined(texts, prior_ranges_per_text)
```

기능:
- 여러 text를 `SEP`로 합쳐 한 번에 추론
- 결과를 text별 로컬 좌표로 분리
- 이후 `SLMStage`는 얇은 orchestration layer 역할만 수행

### 6-4. 단일 텍스트 추론도 prior filter 지원

```python
SLMAdapter.detect(text, prior_ranges=None)
```

---

## 7. 파일별 패치 범위

| 파일 | 변경 내용 |
|---|---|
| `src/engine/pipeline/__init__.py` | covered span 계산, unresolved window 생성, skip rule, SLM cache key를 reduced text 기준으로 유지 |
| `src/engine/pipeline/slm_stage.py` | `base_offset` 인식, 원문 기준 offset 복원, windowed target 처리 |
| `src/engine/pipeline/slm_adapter.py` | 신규 추가. Qwen 출력 파싱, rule 정규화, prior overlap 필터, detect/detect_combined 제공 |
| `src/engine/api/base.py` | 필요 시 internal target wrapper 또는 optional offset 필드 지원 |
| `tests/test_pipeline_slm_inputs.py` | fully-covered target skip, reduced text cache hit, role skip 회귀 테스트 |
| `tests/test_slm_adapter.py` | rule normalize, overlap filter, combined split/offset 복원 테스트 |

---

## 8. 구현 순서

### Phase A — 현재 GGUF 경로 최적화

1. `effective_findings` 기준 covered span 계산 helper 추가
2. unresolved window 생성 helper 추가
3. `base_offset` 포함 SLM target wrapper 도입
4. `SLMStage.scan()`에서 offset 복원 보강
5. SLM 입력 통계 로그 추가
6. 회귀 테스트 작성

### Phase B — 학습 완료 후 어댑터 통합

1. `slm_adapter.py` 추가
2. `parse_model_output()`에 rule normalize 반영
3. `filter_by_prior()`로 Regex 50% overlap 제거 구현
4. `detect_combined()` 구현
5. 기존 `SLMStage`를 어댑터 호출 구조로 교체
6. GGUF 경로는 fallback 또는 백업 코드로 유지

---

## 9. 검증 계획

### 9-1. 단위 테스트

1. covered span 역전(invert) 테스트
2. window margin/merge 테스트
3. fully-covered target skip 테스트
4. `base_offset` 복원 테스트
5. Qwen rule normalize 테스트
6. prior overlap 50% 필터 테스트

### 9-2. 런타임 계측

추가 권장 로그:

| 메트릭 | 의미 |
|---|---|
| `slm_input_chars_before` | window 생성 전 총 문자 수 |
| `slm_input_chars_after` | window 생성 후 총 문자 수 |
| `slm_target_count_before` | 원래 SLM 후보 target 수 |
| `slm_target_count_after` | 최종 SLM target 수 |
| `slm_skipped_targets` | skip된 target 수 |
| `slm_chunk_count` | 최종 chunk 수 |
| `slm_cache_hits` | reduced text 기준 cache hit 수 |

### 9-3. 모델 평가

학습 완료 후 다음 순서로 검증한다.

1. `eval_v2.py`로 v5 Precision / Recall / F1 확인
2. `slm_adapter.py` 단독 추론 테스트
3. pipeline 통합 후 샘플 요청 replay
4. 기존 GGUF 경로 대비 latency / chunk count / detection coverage 비교

---

## 10. 리스크 및 대응

| 리스크 | 설명 | 대응 |
|---|---|---|
| 문맥 과도 삭제 | Regex span 제거 과정에서 이름/주소 문맥이 사라질 수 있음 | span 삭제 대신 unresolved window 앞뒤 50자 유지 |
| offset drift | windowed input 도입 후 원문 좌표 복원이 어긋날 수 있음 | `base_offset` 강제, 오프셋 테스트 추가 |
| aggressive skip | coverage 기준이 너무 공격적이면 SLM recall 저하 | 초기값 보수적으로 설정, 로그 기반 튜닝 |
| adapter rule mismatch | Qwen 출력 rule과 control severity map 불일치 | `RULE_NORMALIZE` 강제 적용 |
| fallback 부재 | transformers 경로 실패 시 서비스 영향 | GGUF 경로 백업 유지 또는 feature flag 제공 |

---

## 11. 완료 기준

다음 조건을 만족하면 본 개선 작업을 완료로 본다.

1. v5 학습 결과는 유지되고 재학습이 필요하지 않다.
2. Regex/Asset이 이미 처리한 span이 SLM 입력에서 실질적으로 줄어든다.
3. SLM 입력 문자 수와 chunk 수가 기존 대비 의미 있게 감소한다.
4. 이름/주소/기관명 계열 recall이 눈에 띄게 악화되지 않는다.
5. 어댑터 교체 후에도 출력 스키마 `{rule, start, end, text, confidence}` 가 유지된다.
6. rule normalize 및 prior overlap 필터가 테스트로 보장된다.

---

## 12. 추천 구현 결론

우선순위는 다음과 같다.

1. **현재 GGUF 경로에서 SLM 입력 축소 패치 먼저 적용**
2. **입력 축소와 offset 복원 테스트 확보**
3. **v5 평가 완료 후 Qwen 어댑터 통합**

즉, 이번 작업의 본질은 **학습 변경이 아니라 런타임 최적화와 어댑터 정합성 보강**이다.