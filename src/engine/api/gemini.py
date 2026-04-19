"""
Google Gemini API 파서.
대상: generativelanguage.googleapis.com/v1.../models/{model}:generateContent

검사 대상 role:
  user            — 사용자 입력
  functionResponse — 함수 실행 결과 (tool_result에 해당)
제외 role:
  model (assistant) — LLM 응답
  systemInstruction — 시스템 프롬프트
  tool_def          — 도구 함수 선언
"""
from __future__ import annotations
import json
from .base import DLPTarget, ParsedRequest


# ── 공통 유틸 ───────────────────────────────────────────────────────────────

def _clip(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"…[+{len(text) - max_len}chars]"


def _new_only(raw_msgs: list) -> list:
    """last_model 이후 콘텐츠만 반환. 없으면 user 콘텐츠만."""
    last_model = -1
    for i, m in enumerate(raw_msgs):
        if m.get("role") == "model":
            last_model = i
    if last_model >= 0:
        return raw_msgs[last_model + 1:]
    return [m for m in raw_msgs if m.get("role") != "model"]


def _model_from_url(url: str) -> str:
    """URL에서 모델명 추출: /models/gemini-2.5-pro:generateContent → gemini-2.5-pro"""
    if "/models/" in url:
        after = url.split("/models/", 1)[1]
        return after.split(":")[0].split("/")[0]
    return "unknown"


def parse(provider: str, url: str, body: dict) -> ParsedRequest:
    model = body.get("model", _model_from_url(url))
    stream = "streamGenerateContent" in url
    targets: list[DLPTarget] = []

    # systemInstruction — 제외 (LLM Provider 관리 고정값)
    # tools functionDeclarations — 제외 (개발자 작성 고정값)

    contents = body.get("contents", [])

    # ── 히스토리 경계 판별 ──────────────────────────────────────────────────
    last_model_idx = -1
    for i, content in enumerate(contents):
        if content.get("role") == "model":
            last_model_idx = i

    # ── contents: user role 및 functionResponse 처리 (히스토리 마킹) ──────────
    for i, content in enumerate(contents):
        role = content.get("role", "user")
        if role == "model":
            continue
        is_hist = i <= last_model_idx

        for j, part in enumerate(content.get("parts", [])):
            # 일반 텍스트 (user 입력)
            text = part.get("text", "")
            if text.strip():
                targets.append(DLPTarget(
                    field_path=f"contents[{i}].parts[{j}].text",
                    role="user",
                    text=text,
                    history=is_hist,
                ))

            # functionResponse — 함수 실행 결과 (tool_result에 해당)
            fr = part.get("functionResponse", {})
            if fr:
                resp = fr.get("response", {})
                if resp:
                    targets.append(DLPTarget(
                        field_path=f"contents[{i}].parts[{j}].functionResponse.response",
                        role="tool_result",
                        text=json.dumps(resp, ensure_ascii=False),
                        history=is_hist,
                    ))
            # functionCall (model이 만든 호출 인자) — role=="model" 단계에서 이미 skip됨

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
    contents = obj.get("contents", [])
    sys_inst = obj.get("systemInstruction", {})
    sys_text = ""
    if sys_inst:
        parts = sys_inst.get("parts", [])
        sys_text = " ".join(p.get("text", "") for p in parts)[:200].replace("\n", "↵")
    return {
        "model":         obj.get("model", "N/A"),
        "stream":        False,  # Gemini는 URL로 판별 (이미 parse() 에서)
        "content_count": len(contents),
        "system":        sys_text,
        "contents":      contents,
    }


def extract_messages(obj: dict, msg_max: int = 500) -> list[dict]:
    """JSONL 로그용: 신규 콘텐츠만 추출 (히스토리 제외)."""
    raw_msgs = obj.get("contents", [])
    msgs: list[dict] = []
    for c in _new_only(raw_msgs):
        role  = c.get("role", "?")
        parts = c.get("parts", [])
        text  = " ".join(p.get("text", "") for p in parts if "text" in p)
        if text:
            msgs.append({"role": role, "content": _clip(text, msg_max)})
    return msgs
