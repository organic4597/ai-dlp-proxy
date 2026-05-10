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


# ── 공통 유틸 ───────────────────────────────────────────────────────────────

def _clip(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"…[+{len(text) - max_len}chars]"


def _new_only(raw_msgs: list) -> list:
    """last_assistant 이후 메시지만 반환. 없으면 마지막 user 1개만."""
    last_asst = -1
    for i, m in enumerate(raw_msgs):
        if m.get("role") in ("assistant", "model"):
            last_asst = i
    if last_asst >= 0:
        return raw_msgs[last_asst + 1:]
    return [m for m in raw_msgs if m.get("role") not in ("system", "developer")]


def _content_str(content, max_len: int = 500) -> str:
    if isinstance(content, str):
        return _clip(content, max_len)
    if isinstance(content, list):
        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            t = block.get("type", "")
            if t == "text":
                parts.append(block.get("text", ""))
            elif t == "image":
                parts.append("[image]")
            elif t == "tool_use":
                parts.append(f"[tool_use: {block.get('name', '?')}]")
            elif t == "tool_result":
                inner = block.get("content", "")
                if isinstance(inner, list):
                    inner = " ".join(p.get("text", "") for p in inner if isinstance(p, dict))
                parts.append(f"[tool_result: {str(inner)[:100]}]")
            else:
                parts.append(f"[{t}]")
        return _clip(" ".join(parts), max_len)
    return _clip(str(content), max_len)


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
                if isinstance(inner, str):
                    # tool_result content가 문자열 형식인 경우
                    if inner.strip():
                        targets.append(DLPTarget(
                            field_path=f"{base_path}[{j}].content",
                            role="tool_result",
                            text=inner,
                            history=history,
                        ))
                else:
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


# ── 로그용 요약 ───────────────────────────────────────────────────────────────

def summarize(obj: dict) -> dict:
    """요청 바디에서 로그/TUI 표시용 요약 dict 반환."""
    messages = obj.get("messages", [])
    return {
        "model":      obj.get("model", "N/A"),
        "stream":     bool(obj.get("stream", False)),
        "msg_count":  len(messages),
        "system":     str(obj.get("system", ""))[:200].replace("\n", "↵"),
        "messages":   messages,
    }


def extract_messages(obj: dict, msg_max: int = 500) -> list[dict]:
    """JSONL 로그용: 신규 메시지만 추출 (히스토리 제외)."""
    raw_msgs = obj.get("messages", [])
    return [
        {"role": msg.get("role", "?"), "content": _content_str(msg.get("content", ""), msg_max)}
        for msg in _new_only(raw_msgs)
    ]
