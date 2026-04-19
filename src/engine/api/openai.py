"""
OpenAI Chat Completions 포맷 파서.
대상: OpenAI / GitHub Copilot / Azure OpenAI / Groq / Together / Mistral / OpenRouter / DeepSeek / xAI
(모두 /v1/chat/completions 또는 /chat/completions 엔드포인트 사용)

검사 대상 role:
  user        — 사용자 입력
  tool_result — 함수 실행 결과 (role=="tool" 메시지 content)
  tool_call   — LLM이 호출한 함수 인자 (assistant.tool_calls[].function.arguments)
제외 role:
  system      — 개발자 고정 시스템 프롬프트
  assistant   — LLM 응답 텍스트 (대화 history에서 매 턴 재탐지 방지)
  tool_def    — 도구 정의 description
"""
from __future__ import annotations
from .base import DLPTarget, ParsedRequest


def parse(provider: str, url: str, body: dict) -> ParsedRequest:
    model = body.get("model", "unknown")
    stream = bool(body.get("stream", False))
    targets: list[DLPTarget] = []

    # chat/completions: messages 키 / Responses API (/responses): input 키
    messages = body.get("messages") or []
    _input_items = body.get("input") or []  # Responses API

    # ── 히스토리 경계 판별 ────────────────────────────────────────────────────
    # 마지막 assistant 메시지 이후 = 새 메시지 (history=False)
    # 그 이전 = 이전 턴의 히스토리 (history=True: 마스킹은 하되 탐지 카운트 제외)
    last_assistant_idx = -1
    for i, msg in enumerate(messages):
        if msg.get("role") == "assistant":
            last_assistant_idx = i

    # ── messages ─────────────────────────────────────────────────────────────
    for i, msg in enumerate(messages):
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        is_hist = i <= last_assistant_idx

        # system/assistant 본문은 스캔 제외. tool은 아래 별도 처리.
        if role not in ("assistant", "system", "tool"):
            if isinstance(content, str):
                if content.strip():
                    targets.append(DLPTarget(
                        field_path=f"messages[{i}].content",
                        role=role,
                        text=content,
                        history=is_hist,
                    ))
            elif isinstance(content, list):
                for j, block in enumerate(content):
                    btype = block.get("type", "")
                    if btype == "text":
                        text = block.get("text", "")
                        if text.strip():
                            targets.append(DLPTarget(
                                field_path=f"messages[{i}].content[{j}].text",
                                role=role,
                                text=text,
                                history=is_hist,
                            ))

        # tool_calls: 함수 인자 (JSON 문자열)
        for k, tc in enumerate(msg.get("tool_calls", [])):
            fn = tc.get("function", {})
            args = fn.get("arguments", "")
            if isinstance(args, str) and args.strip():
                targets.append(DLPTarget(
                    field_path=f"messages[{i}].tool_calls[{k}].function.arguments",
                    role="tool_call",
                    text=args,
                    history=is_hist,
                ))

        # tool 역할 메시지의 content (함수 실행 결과) → role="tool_result"로 정규화
        if role == "tool":
            result = msg.get("content", "")
            if isinstance(result, str) and result.strip():
                targets.append(DLPTarget(
                    field_path=f"messages[{i}].content",
                    role="tool_result",
                    text=result,
                    history=is_hist,
                ))

    # ── tool 정의 description ─────────────────────────────────────────────────
    for i, tool in enumerate(body.get("tools", [])):
        fn = tool.get("function", {})
        desc = fn.get("description", "")
        if desc.strip():
            targets.append(DLPTarget(
                field_path=f"tools[{i}].function.description",
                role="tool_def",
                text=desc,
            ))

    # ── Responses API: input 배열 (/responses 엔드포인트) ────────────────────
    # 포맷: input[i].content[j].type = "input_text" | "output_text" | "text"
    for i, item in enumerate(_input_items):
        role = item.get("role", "unknown")
        content = item.get("content", "")
        # system/assistant 출력은 스캔 제외
        if role in ("assistant", "system"):
            continue
        if isinstance(content, str):
            if content.strip():
                targets.append(DLPTarget(
                    field_path=f"input[{i}].content",
                    role=role,
                    text=content,
                ))
        elif isinstance(content, list):
            for j, part in enumerate(content):
                ptype = part.get("type", "")
                if ptype in ("input_text", "text"):
                    text = part.get("text", "")
                    if text.strip():
                        targets.append(DLPTarget(
                            field_path=f"input[{i}].content[{j}].text",
                            role=role,
                            text=text,
                        ))

    # ── user 식별자 필드 ──────────────────────────────────────────────────────
    user_field = body.get("user", "")
    if isinstance(user_field, str) and user_field.strip():
        targets.append(DLPTarget(
            field_path="user",
            role="metadata",
            text=user_field,
        ))

    return ParsedRequest(
        provider=provider,
        url=url,
        model=model,
        stream=stream,
        targets=targets,
        raw_body=body,
    )
