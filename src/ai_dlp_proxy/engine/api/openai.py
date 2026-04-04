"""
OpenAI Chat Completions 포맷 파서.
대상: OpenAI / GitHub Copilot / Azure OpenAI / Groq / Together / Mistral / OpenRouter / DeepSeek / xAI
(모두 /v1/chat/completions 또는 /chat/completions 엔드포인트 사용)

검사 대상 role:
  user        — 사용자 입력 (직접 민감정보 유출 위험)
  tool        — 함수 실행 결과 (파일 경로·DB 레코드 등 노출 위험)
제외 role:
  system      — 시스템 프롬프트 템플릿 (LLM Provider가 관리)
  assistant   — LLM이 생성한 응답 (아웃바운드, 검사 불필요)
  tool_call   — assistant가 만든 함수 호출 인자 (LLM 생성)
  tool_def    — 도구 정의 description (개발자 작성 고정값)
"""
from __future__ import annotations
from .base import DLPTarget, ParsedRequest

# 검사할 role 집합
_SCAN_ROLES = {"user", "tool"}


def parse(provider: str, url: str, body: dict) -> ParsedRequest:
    model = body.get("model", "unknown")
    stream = bool(body.get("stream", False))
    targets: list[DLPTarget] = []

    # ── messages ─────────────────────────────────────────────────────────────
    for i, msg in enumerate(body.get("messages", [])):
        role = msg.get("role", "unknown")

        # system / assistant / tool_call 정의 등은 검사 제외
        if role not in _SCAN_ROLES:
            continue

        content = msg.get("content", "")
        # tool role은 함수 실행 결과 → tool_result로 레이블
        scan_role = "tool_result" if role == "tool" else role

        if isinstance(content, str):
            if content.strip():
                targets.append(DLPTarget(
                    field_path=f"messages[{i}].content",
                    role=scan_role,
                    text=content,
                ))
        elif isinstance(content, list):
            # 멀티모달 content 블록 배열
            for j, block in enumerate(content):
                if block.get("type") == "text":
                    text = block.get("text", "")
                    if text.strip():
                        targets.append(DLPTarget(
                            field_path=f"messages[{i}].content[{j}].text",
                            role=scan_role,
                            text=text,
                        ))
                # image_url / binary 블록은 DLP 미대상

    return ParsedRequest(
        provider=provider,
        url=url,
        model=model,
        stream=stream,
        targets=targets,
        raw_body=body,
    )
