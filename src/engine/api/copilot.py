"""
GitHub Copilot 전용 파서.

VS Code Copilot은 실제 사용자 대화 외에도 제목 생성, progress 문구 생성,
도구 그룹 요약 등 내부 보조 요청을 같은 Copilot API로 보낸다. 이 어댑터는
그 wrapper prompt를 분류해 실제 사용자 입력만 DLP 대상으로 남긴다.
"""
from __future__ import annotations

import re
from typing import Any

from . import anthropic as _anthropic
from . import openai as _openai
from .base import DLPTarget, ParsedRequest

_TITLE_RE = re.compile(
    r"^\s*Please write a brief title for the following request:\s*(?P<request>.*?)\s*$",
    re.DOTALL,
)

_SIDECAR_PREFIXES = (
    "Please generate exactly 10 unique progress messages",
    "You will be given ",
)


def _clip(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"…[+{len(text) - max_len}chars]"


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "")
            if btype in ("text", "input_text"):
                parts.append(str(block.get("text", "")))
            elif btype == "tool_result":
                inner = block.get("content", "")
                if isinstance(inner, str):
                    parts.append(inner)
                elif isinstance(inner, list):
                    parts.extend(str(part.get("text", "")) for part in inner if isinstance(part, dict))
        return " ".join(part for part in parts if part)
    return str(content or "")


def _last_user_message(body: dict) -> tuple[int, str, str] | None:
    messages = body.get("messages") or []
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        text = _content_to_text(content)
        if not text.strip():
            continue
        path = f"messages[{idx}].content"
        if isinstance(content, list):
            for block_idx in range(len(content) - 1, -1, -1):
                block = content[block_idx]
                if isinstance(block, dict) and block.get("type") in ("text", "input_text"):
                    path = f"messages[{idx}].content[{block_idx}].text"
                    break
        return idx, path, text
    return None


def _title_inner(text: str) -> str | None:
    match = _TITLE_RE.match(text)
    if not match:
        return None
    inner = match.group("request").strip()
    return inner or None


def _is_sidecar_prompt(text: str) -> bool:
    stripped = text.lstrip()
    if any(stripped.startswith(prefix) for prefix in _SIDECAR_PREFIXES):
        return True
    if "groups of tools" in stripped and "provide a name and summary" in stripped:
        return True
    if "Return only a JSON array of strings" in stripped and "progress messages" in stripped:
        return True
    return False


def _data_targets_from_openai(provider: str, url: str, body: dict, exclude_path: str | None = None) -> list[DLPTarget]:
    parsed = _openai.parse(provider, url, body)
    targets: list[DLPTarget] = []
    for target in parsed.targets:
        if exclude_path and target.field_path == exclude_path:
            continue
        if target.history or target.role in ("tool_result", "tool_call", "metadata"):
            targets.append(target)
    return targets


def _openai_sidecar_target(provider: str, url: str, body: dict) -> ParsedRequest | None:
    last = _last_user_message(body)
    if last is None:
        parsed = _openai.parse(provider, url, body)
        return parsed if parsed.targets else None

    _idx, path, text = last
    data_targets = _data_targets_from_openai(provider, url, body, exclude_path=path)
    title_request = _title_inner(text)
    if title_request is not None:
        # DLP 마스킹 offset을 원본 JSON 문자열 기준으로 유지해야 하므로 target.text는
        # wrapper 전체를 사용한다. JSONL/요약에는 아래 extract_messages()에서 실제 요청만 노출한다.
        return ParsedRequest(
            provider=provider,
            url=url,
            model=body.get("model", "unknown"),
            stream=bool(body.get("stream", False)),
            targets=[DLPTarget(field_path=path, role="user", text=text, history=False), *data_targets],
            raw_body=body,
        )

    if _is_sidecar_prompt(text):
        if data_targets:
            return ParsedRequest(
                provider=provider,
                url=url,
                model=body.get("model", "unknown"),
                stream=bool(body.get("stream", False)),
                targets=data_targets,
                raw_body=body,
            )
        return None

    return _openai.parse(provider, url, body)


def parse(provider: str, url: str, body: dict) -> ParsedRequest | None:
    if "/models/session" in url:
        parsed = _openai.parse(provider, url, body)
        return parsed if parsed.targets else None
    if "/v1/messages" in url:
        return _anthropic.parse(provider, url, body)
    return _openai_sidecar_target(provider, url, body)


def summarize(obj: dict) -> dict:
    last = _last_user_message(obj)
    if last is not None:
        _idx, _path, text = last
        title_request = _title_inner(text)
        if title_request is not None:
            return {
                "model": obj.get("model", "N/A"),
                "stream": bool(obj.get("stream", False)),
                "msg_count": 1,
                "tool_count": len(obj.get("tools", [])),
                "msg_key": "copilot_user_request",
                "messages": [{"role": "user", "content": title_request}],
            }
        if _is_sidecar_prompt(text):
            return {}
    if obj.get("messages") and "/v1/messages" in str(obj.get("url", "")):
        return _anthropic.summarize(obj)
    return _openai.summarize(obj)


def extract_messages(obj: dict, msg_max: int = 500) -> list[dict]:
    last = _last_user_message(obj)
    if last is not None:
        _idx, _path, text = last
        title_request = _title_inner(text)
        if title_request is not None:
            return [{"role": "user", "content": _clip(title_request, msg_max)}]
        if _is_sidecar_prompt(text):
            return []
    return _openai.extract_messages(obj, msg_max)
