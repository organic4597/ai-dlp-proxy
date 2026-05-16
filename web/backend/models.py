"""Pydantic 스키마 모델."""
from __future__ import annotations
from pydantic import BaseModel
from typing import Any


class FindingOut(BaseModel):
    id: int | None = None
    request_id: str
    ts: str
    stage: str | None = None
    rule: str | None = None
    severity: str | None = None
    confidence: float = 0.0
    suppressed: bool = False
    suppressed_reason: str | None = None
    match_text: str | None = None
    field_path: str | None = None
    role: str | None = None
    metadata: dict[str, Any] | None = None
    prompt_excerpt: str | None = None
    dlp_applied: str | None = None
    policy_effective: bool = False
    policy_reason: str | None = None
    confidence_threshold: float | None = None


class RequestOut(BaseModel):
    id: int | None = None
    ts: str
    request_id: str
    prompt_excerpt: str | None = None
    provider: str | None = None
    model: str | None = None
    pipeline_action: str | None = "pass"
    raw_finding_count: int = 0
    effective_finding_count: int = 0
    total_text_len: int = 0
    target_count: int = 0
    elapsed_ms: float | None = None
    cache_hit: bool = False
    dlp_applied: str | None = "pass"
    findings: list[FindingOut] | None = None


class CustomRuleIn(BaseModel):
    name: str
    pattern: str
    severity: str = "high"  # critical/high/medium/low
    description: str = ""


class AllowlistEntryIn(BaseModel):
    rule: str = "*"
    value: str
    expires_at: str | None = None  # ISO8601


class AssetIn(BaseModel):
    id: str | None = None
    name: str
    severity: str = "high"
    keywords: list[str] = []
    examples: list[str] = []
    embedding_threshold: float = 0.83


class ControlIn(BaseModel):
    regex_enabled: bool | None = None
    asset_enabled: bool | None = None
    slm_enabled: bool | None = None
    ml_filter_enabled: bool | None = None
    ml_filter_threshold: float | None = None
    mask_on_detect: bool | None = None
    block_on_alert: bool | None = None
    block_on_mask: bool | None = None
    confidence_threshold: float | None = None
    context_penalty_enabled: bool | None = None
    disabled_rules: list[str] | None = None
    allowlist: list[dict] | None = None
    mask_templates: dict[str, str] | None = None
    skip_roles: list[str] | None = None
    custom_rules: list[dict] | None = None
    slm_backend: str | None = None   # "auto" | "gguf" | "adapter" | "api"
    slm_api_url: str | None = None   # SLM API 서버 URL (api 모드)


class ControlOut(BaseModel):
    regex_enabled: bool = True
    asset_enabled: bool = True
    slm_enabled: bool = False
    ml_filter_enabled: bool = False
    ml_filter_threshold: float = 0.4
    mask_on_detect: bool = False
    block_on_alert: bool = False
    block_on_mask: bool = False
    confidence_threshold: float = 0.5
    context_penalty_enabled: bool = True
    disabled_rules: list[str] = []
    allowlist: list[dict] = []
    mask_templates: dict[str, str] = {}
    skip_roles: list[str] = ["system", "tool_def"]
    custom_rules: list[dict] = []
    slm_backend: str = "auto"
    slm_api_url: str = "http://localhost:8766"


class ProcessStatus(BaseModel):
    name: str
    running: bool
    pid: int | None = None
    uptime_sec: float | None = None
    extra: dict[str, Any] = {}


class AuditOut(BaseModel):
    id: int | None = None
    ts: str
    request_id: str
    provider: str | None = None
    model: str | None = None
    pipeline_action: str = "pass"
    finding_count: int = 0
    effective_finding_count: int = 0
    total_text_len: int = 0
    target_count: int = 0
    elapsed_ms: float | None = None
    findings: list[FindingOut] | None = None
