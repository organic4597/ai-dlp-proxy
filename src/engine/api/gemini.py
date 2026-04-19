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
