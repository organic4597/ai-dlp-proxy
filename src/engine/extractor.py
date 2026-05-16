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
from .api import copilot as _copilot

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


def _infer_provider_from_url_and_model(url: str, body: dict) -> str:
    """호스트를 알 수 없을 때 URL 경로 + model명으로 provider 추정.
    IP 대역 기반 추정은 사용하지 않는다.
    """
    model = str(body.get("model", "")).lower()
    path = url.lower()

    if "claude" in model:
        return "Anthropic"
    if any(k in model for k in ("gpt-", "o1-", "o3-", "o4-", "text-davinci")):
        return "OpenAI"
    if any(k in model for k in ("gemini", "palm", "bison")):
        return "Gemini"
    if "deepseek" in model:
        return "DeepSeek"
    if "grok" in model:
        return "xAI"
    if "mistral" in model or "mixtral" in model:
        return "Mistral"

    if "/v1/messages" in path:
        return "Anthropic"
    if "/v1/chat/completions" in path:
        return "OpenAI"
    return "Unknown"


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

    # 호스트 미식별 시 URL/모델 기반 fallback (IP 대역 기반 추정 금지)
    if provider == "Unknown":
        provider = _infer_provider_from_url_and_model(url, body)

    if provider == "GitHub Copilot":
        return _copilot.parse(provider, url, body)

    # /v1/messages 경로는 Anthropic Messages API 포맷
    is_anthropic_format = "/v1/messages" in url

    if host == "api.anthropic.com" or is_anthropic_format:
        return _anthropic.parse(provider, url, body)
    elif host in _OPENAI_COMPAT or host.endswith(_AZURE_SUFFIX):
        return _openai.parse(provider, url, body)
    elif host == "generativelanguage.googleapis.com":
        return _gemini.parse(provider, url, body)

    return None


# ── 공급자별 로그용 함수 라우팅 ─────────────────────────────────────────────

_OPENAI_COMPAT_PROVIDERS = frozenset({
    "OpenAI", "Azure OpenAI", "GitHub Copilot", "Groq",
    "Together", "Mistral", "OpenRouter", "DeepSeek", "xAI",
})


def summarize_request(provider: str, body: dict) -> dict:
    """
    공급자별 파서의 summarize()를 호출해 로그/TUI 표시용 요약 dict 반환.
    """
    if provider == "GitHub Copilot":
        return _copilot.summarize(body)
    if provider in _OPENAI_COMPAT_PROVIDERS:
        return _openai.summarize(body)
    elif provider == "Anthropic":
        return _anthropic.summarize(body)
    elif provider == "Gemini":
        return _gemini.summarize(body)
    return {}


def extract_messages(provider: str, body: dict, msg_max: int = 500) -> list[dict]:
    """
    공급자별 파서의 extract_messages()를 호출해 JSONL 로그용 메시지 목록 반환.
    히스토리 제외, 신규 메시지만 포함.
    """
    if provider == "GitHub Copilot":
        return _copilot.extract_messages(body, msg_max)
    if provider in _OPENAI_COMPAT_PROVIDERS:
        return _openai.extract_messages(body, msg_max)
    elif provider == "Anthropic":
        return _anthropic.extract_messages(body, msg_max)
    elif provider == "Gemini":
        return _gemini.extract_messages(body, msg_max)
    return []
