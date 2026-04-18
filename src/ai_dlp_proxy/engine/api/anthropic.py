"""
Anthropic Messages API 파서.
대상: api.anthropic.com/v1/messages

검사 대상 role:
  user        — 사용자 입력
  tool_result — 함수 실행 결과 (tool_result 블록 내부 텍스트)
제외 role:
  system      — 시스템 프롬프트
  assistant   — LLM 응답 (tool_use 포함)
  tool_def    — 도구 정의 description
"""
from __future__ import annotations
from .base import DLPTarget, ParsedRequest


def _extract_user_content(
    content,
    base_path: str,
    targets: list[DLPTarget],
    history: bool = False,
) -> None:
    """user role의 content를 (str | list[block]) 형태로 받아 DLPTarget 추출.
    tool_result 블록이 있으면 그 내부 텍스트도 추출."""
    if isinstance(content, str):
        if content.strip():
            targets.append(DLPTarget(field_path=base_path, role="user", text=content, history=history))
    elif isinstance(content, list):
        for j, block in enumerate(content):
            btype = block.get("type", "")
            if btype == "text":
                text = block.get("text", "")
                if text.strip():
                    targets.append(DLPTarget(
                        field_path=f"{base_path}[{j}].text",
                        role="user",
                        text=text,
                        history=history,
                    ))
            elif btype == "tool_result":
                # 함수 실행 결과 — 파일 경로·DB 데이터 노출 위험
                inner = block.get("content", [])
                inner_list = inner if isinstance(inner, list) else []
                for k, rb in enumerate(inner_list):
                    text = rb.get("text", "") if isinstance(rb, dict) else str(rb)
                    if text.strip():
                        targets.append(DLPTarget(
                            field_path=f"{base_path}[{j}].content[{k}].text",
                            role="tool_result",
                            text=text,
                            history=history,
                        ))
            # tool_use (assistant의 함수 호출 입력) — 검사 제외


def parse(provider: str, url: str, body: dict) -> ParsedRequest:
    model = body.get("model", "unknown")
    stream = bool(body.get("stream", False))
    targets: list[DLPTarget] = []

    messages = body.get("messages", [])

    # ── 히스토리 경계 판별 ────────────────────────────────────────────────────
    last_assistant_idx = -1
    for i, msg in enumerate(messages):
        if msg.get("role") == "assistant":
            last_assistant_idx = i

    # ── messages: user role 처리 (히스토리 메시지에는 history=True 표시) ────────
    for i, msg in enumerate(messages):
        role = msg.get("role", "unknown")
        if role != "user":
            continue
        content = msg.get("content", "")
        is_hist = i <= last_assistant_idx
        _extract_user_content(content, f"messages[{i}].content", targets, history=is_hist)

    return ParsedRequest(
        provider=provider,
        url=url,
        model=model,
        stream=stream,
        targets=targets,
        raw_body=body,
    )
