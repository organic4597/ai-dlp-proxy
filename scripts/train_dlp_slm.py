#!/usr/bin/env python3
"""
DLP SLM LoRA 파인튜닝 스크립트
================================
베이스 모델: Qwen/Qwen3.5-4B (또는 Qwen/Qwen3.5-2B, Qwen/Qwen3.5-0.8B)
방식: LoRA (표준 bf16) — VRAM 12GB+ 권장
      QLoRA (4bit nf4) — VRAM 6GB+ 가능 (--use-qlora 플래그)

참고: Qwen3.5-4B 주요 스펙 (2026년 2월 출시)
  - 아키텍처: Gated DeltaNet 하이브리드 (선형 어텐션 + 표준 어텐션 혼합)
    레이아웃: 8 × (3×DeltaNet→FFN + 1×GatedAttn→FFN)
  - 컨텍스트: 262,144 토큰 (기본), 최대 1,010,000
  - 멀티모달: 비전 인코더 포함 (DLP에서는 텍스트 전용 사용)
  - Thinking 모드: 기본 ON → Non-Thinking (enable_thinking=False) 권장
    DLP 탐지 목적으로는 Non-Thinking 모드로 결정적 JSON 출력
  - GGUF: Q4_K_M 약 3.4GB (llama.cpp / Ollama 호환 확인됨)
  - 라이선스: Apache 2.0

실행 예:
  # LoRA (기본)
  python3 scripts/train_dlp_slm.py

  # QLoRA (VRAM 절약)
  python3 scripts/train_dlp_slm.py --use-qlora

  # 소형 모델로 변경 (VRAM 제한 시)
  python3 scripts/train_dlp_slm.py \\
    --model Qwen/Qwen3.5-2B \\
    --train tests/slm_train_dataset.jsonl \\
    --eval  tests/slm_eval_dataset.jsonl \\
    --output ./dlp-slm-lora \\
    --epochs 3

출력:
  ./dlp-slm-lora/          LoRA 어댑터 체크포인트
  ./dlp-slm-merged/        병합된 전체 모델 (GGUF 변환용)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ── 의존성 체크 ───────────────────────────────────────────────────────────────

def _check_deps() -> None:
    missing = []
    for pkg in ["transformers", "peft", "trl", "datasets", "torch"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[ERROR] 누락 패키지: {', '.join(missing)}")
        print("설치: pip install transformers peft trl datasets torch accelerate")
        sys.exit(1)

_check_deps()

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainerCallback,
    TrainerState,
    TrainerControl,
)
from trl import SFTConfig, SFTTrainer

REPO_ROOT = Path(__file__).parent.parent

# ── 기본값 ────────────────────────────────────────────────────────────────────

DEFAULT_MODEL   = "Qwen/Qwen3.5-4B"
DEFAULT_TRAIN   = str(REPO_ROOT / "tests" / "slm_train_dataset.jsonl")
DEFAULT_EVAL    = str(REPO_ROOT / "tests" / "slm_eval_dataset.jsonl")
DEFAULT_OUTPUT  = str(REPO_ROOT / "dlp-slm-lora")
DEFAULT_MERGED  = str(REPO_ROOT / "dlp-slm-merged")


# ── 데이터 로드 ───────────────────────────────────────────────────────────────

def load_jsonl(path: str) -> Dataset:
    """ChatML JSONL → HuggingFace Dataset."""
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            records.append({"messages": obj["messages"]})
    return Dataset.from_list(records)


# ── 포매터 ────────────────────────────────────────────────────────────────────

def apply_chat_template(example: dict, tokenizer) -> dict:
    """messages → 모델별 chat template 적용.
    Qwen3.5: 기본이 Thinking ON이므로 enable_thinking=False 명시 필요.
             (Qwen3과 달리 /think /nothink 소프트 스위치 미지원)
    """
    # Qwen3.5 / Qwen3: enable_thinking=False → Non-Thinking 모드
    try:
        text = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False,
            enable_thinking=False,  # Non-Thinking: 결정적 JSON 출력
        )
    except TypeError:
        # enable_thinking 미지원 모델 (Qwen2.5 등) 폴백
        text = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
    return {"text": text}


# ── 학습 콜백 (진행 로그) ─────────────────────────────────────────────────────

class ProgressCallback(TrainerCallback):
    def on_log(self, args, state: TrainerState, control: TrainerControl, logs=None, **kwargs):
        if logs:
            step   = state.global_step
            total  = state.max_steps
            loss   = logs.get("loss", logs.get("eval_loss", "?"))
            lr     = logs.get("learning_rate", "?")
            print(f"  [step {step}/{total}] loss={loss}  lr={lr}")


# ── 메인 ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="DLP SLM LoRA 파인튜닝")
    parser.add_argument("--model",      default=DEFAULT_MODEL,  help="HuggingFace 모델 ID (기본: Qwen/Qwen3.5-4B)")
    parser.add_argument("--train",      default=DEFAULT_TRAIN,  help="학습 JSONL 경로")
    parser.add_argument("--eval",       default=DEFAULT_EVAL,   help="평가 JSONL 경로")
    parser.add_argument("--output",     default=DEFAULT_OUTPUT, help="LoRA 어댑터 출력 디렉터리")
    parser.add_argument("--merged",     default=DEFAULT_MERGED, help="병합 모델 출력 디렉터리")
    parser.add_argument("--epochs",     type=int,   default=3,    help="학습 에폭 수")
    parser.add_argument("--batch-size", type=int,   default=4,    help="배치 크기")
    parser.add_argument("--grad-accum", type=int,   default=4,    help="그래디언트 누적 스텝")
    parser.add_argument("--lr",         type=float, default=2e-4, help="학습률")
    parser.add_argument("--max-seq",    type=int,   default=1024, help="최대 시퀀스 길이")
    parser.add_argument("--lora-r",     type=int,   default=16,   help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int,   default=32,   help="LoRA alpha")
    parser.add_argument("--use-qlora",  action="store_true",      help="4bit QLoRA 사용 (VRAM ~6GB)")
    parser.add_argument("--use-8bit",   action="store_true",      help="8bit 양자화 사용 (VRAM ~8GB)")
    parser.add_argument("--no-merge",   action="store_true",      help="학습 후 LoRA 병합 생략")
    args = parser.parse_args()

    print("=" * 60)
    print("DLP SLM LoRA 파인튜닝")
    print("=" * 60)
    print(f"  베이스 모델: {args.model}")
    print(f"  학습 데이터: {args.train}")
    print(f"  평가 데이터: {args.eval}")
    print(f"  출력 경로  : {args.output}")
    mode_str = "QLoRA (4bit)" if args.use_qlora else ("LoRA (8bit)" if args.use_8bit else "LoRA (bf16)")
    print(f"  모드       : {mode_str} | Thinking=OFF (Non-Thinking 모드)")
    print(f"  에폭       : {args.epochs}, 배치={args.batch_size}, lr={args.lr}")
    print()

    # ── 1. 토크나이저 ──────────────────────────────────────────────────────────
    print("[1/5] 토크나이저 로드...")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # ── 2. 데이터셋 ────────────────────────────────────────────────────────────
    print("[2/5] 데이터셋 로드 및 포매팅...")
    train_ds = load_jsonl(args.train)
    eval_ds  = load_jsonl(args.eval)
    print(f"  학습: {len(train_ds)}건, 평가: {len(eval_ds)}건")

    train_ds = train_ds.map(lambda ex: apply_chat_template(ex, tokenizer), remove_columns=["messages"])
    eval_ds  = eval_ds.map(lambda ex: apply_chat_template(ex, tokenizer),  remove_columns=["messages"])

    # ── 3. 모델 로드 ───────────────────────────────────────────────────────────
    print("[3/5] 모델 로드...")
    if args.use_qlora or args.use_8bit:
        try:
            import bitsandbytes  # noqa
        except ImportError:
            print("[ERROR] 양자화 사용 시 bitsandbytes 필요: pip install bitsandbytes")
            sys.exit(1)

    if args.use_qlora:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
    elif args.use_8bit:
        bnb_config = BitsAndBytesConfig(
            load_in_8bit=True,
            llm_int8_threshold=6.0,
        )
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )

    model.config.use_cache = False  # gradient checkpointing 호환

    # ── 4. LoRA 설정 ───────────────────────────────────────────────────────────
    print("[4/5] LoRA 어댑터 설정...")

    # Qwen3.5 Gated DeltaNet 하이브리드 아키텍처 target modules
    # - GatedDeltaNet 레이어: qk_proj (QK 통합), v_proj (V), o_proj (출력)
    # - GatedAttention 레이어: q_proj, k_proj, v_proj, o_proj
    # - FFN: gate_proj, up_proj, down_proj
    # PEFT가 없는 모듈명은 자동으로 건너뜀
    target_modules = [
        # 표준 어텐션 (GatedAttention 레이어)
        "q_proj", "k_proj", "v_proj", "o_proj",
        # Gated DeltaNet 레이어 (선형 어텐션)
        "qk_proj",
        # FFN (공통)
        "gate_proj", "up_proj", "down_proj",
    ]

    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        target_modules=target_modules,
        lora_dropout=0.05,
        bias="none",
        # 어시스턴트 응답(JSON) 부분만 학습
        # SFTTrainer가 chat template 기반으로 자동 처리
    )

    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params     = sum(p.numel() for p in model.parameters())
    print(f"  학습 파라미터: {trainable_params:,} / {total_params:,} "
          f"({100 * trainable_params / total_params:.2f}%)")

    # ── 5. 학습 ────────────────────────────────────────────────────────────────
    print("[5/5] 학습 시작...")

    training_args = SFTConfig(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        max_length=args.max_seq,
        fp16=False,
        bf16=not args.use_8bit,  # 8bit 모드에서는 bf16 비활성
        save_strategy="epoch",
        eval_strategy="epoch",
        logging_steps=20,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to="none",  # wandb 끄기 (필요시 "wandb"로 변경)
        gradient_checkpointing=True,
        # assistant 응답만 학습 대상으로
        dataset_text_field="text",
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        peft_config=lora_config,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,
        callbacks=[ProgressCallback()],
    )

    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"\nLoRA 어댑터 저장 완료: {args.output}")

    # ── 6. LoRA 병합 ───────────────────────────────────────────────────────────
    if not args.no_merge:
        print("\nLoRA 병합 중 (GGUF 변환용)...")
        merged = trainer.model.merge_and_unload()
        merged.save_pretrained(args.merged, safe_serialization=True)
        tokenizer.save_pretrained(args.merged)
        print(f"병합 모델 저장 완료: {args.merged}")
        print()
        print("다음 단계: GGUF 변환")
        print(f"  python llama.cpp/convert_hf_to_gguf.py {args.merged} \\")
        print(f"    --outfile models/dlp-slm-f16.gguf --outtype f16")
        print(f"  ./llama.cpp/llama-quantize models/dlp-slm-f16.gguf \\")
        print(f"    models/dlp-slm-q4_k_m.gguf Q4_K_M")
        print()
        print("slm_stage.py 모델 경로 + 시스템 프롬프트 수정:")
        print('  DEFAULT_MODEL_PATH = "models/dlp-slm-q4_k_m.gguf"')
        print('  # 시스템 프롬프트 한국어 단문으로 교체 (파인튜닝 후 내면화됨)')
        print('  # llama_cpp 호출 시 enable_thinking 파라미터 불필요 (GGUF는 Non-Thinking 학습 완료)')


if __name__ == "__main__":
    main()
