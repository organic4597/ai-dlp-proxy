"""
HTTP flow 정보를 받아 provider를 판별하고 적합한 API 파서로 라우팅.
mitmproxy addon에서 직접 호출하는 진입점.
"""
from __future__ import annotations
import json

from .api.base import ParsedRequest
from .api import openai as _openai
from .api import anthropic as _anthropic
from .api import gemini as _gemini

# OpenAI Chat Completions 호환 API 호스트
_OPENAI_COMPAT: frozenset[str] = frozenset({
    "api.openai.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "api.groq.com",
    "api.together.ai",
    "api.mistral.ai",
    "openrouter.ai",
    "api.deepseek.com",
    "api.x.ai",
})

_AZURE_SUFFIX = ".openai.azure.com"

# 사람이 읽기 쉬운 provider 이름
_LABELS: dict[str, str] = {
    "api.openai.com":                     "OpenAI",
    "api.githubcopilot.com":              "GitHub Copilot",
    "api.individual.githubcopilot.com":   "GitHub Copilot",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot",
    "api.anthropic.com":                  "Anthropic",
    "generativelanguage.googleapis.com":  "Gemini",
    "api.groq.com":                       "Groq",
    "api.together.ai":                    "Together",
    "api.mistral.ai":                     "Mistral",
    "openrouter.ai":                      "OpenRouter",
    "api.deepseek.com":                   "DeepSeek",
    "api.x.ai":                           "xAI",
}


def extract(
    host: str,
    url: str,
    content_type: str,
    body_raw: bytes,
) -> ParsedRequest | None:
    """
    mitmproxy request/response flow에서 ParsedRequest 추출.

    Parameters
    ----------
    host         : 요청 대상 호스트 (예: "api.githubcopilot.com")
    url          : 전체 URL 문자열 (예: "https://api.githubcopilot.com/chat/completions")
    content_type : Content-Type 헤더 값 (예: "application/json")
    body_raw     : 요청 본문 bytes

    Returns
    -------
    ParsedRequest if supported, None otherwise.
    """
    if "json" not in content_type:
        return None
    if not body_raw:
        return None

    try:
        body = json.loads(body_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(body, dict):
        return None

    provider = _LABELS.get(host, "Unknown")
    if host.endswith(_AZURE_SUFFIX):
        provider = "Azure OpenAI"

    if host in _OPENAI_COMPAT or host.endswith(_AZURE_SUFFIX):
        return _openai.parse(provider, url, body)
    elif host == "api.anthropic.com":
        return _anthropic.parse(provider, url, body)
    elif host == "generativelanguage.googleapis.com":
        return _gemini.parse(provider, url, body)

    return None
