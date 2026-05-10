"""
DLP pipeline 제어 파일 로더.

RegexStage가 매 스캔마다 제어 파일을 다시 읽어,
TUI/inspect_traffic에서 바꾼 정책을 즉시 반영한다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .masking import DEFAULT_MASK_TEMPLATES, merge_mask_templates


_SEVERITY_MAP: dict[str, object] = {}  # lazy-filled by _parse_severity


DEFAULT_CONTROL_PATH = "/tmp/dlp-control.json"
ALLOWLIST_LIMIT = 100


def _normalize_for_allowlist(value: str) -> str:
    return re.sub(r"[\W_]+", "", value).casefold()


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class AllowlistEntry:
    rule: str
    value: str
    normalized: str
    added_at: str | None = None
    expires_at: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        expires = _parse_ts(self.expires_at)
        if expires is None:
            return False
        current = now or datetime.now(timezone.utc)
        return current >= expires


# role 필터: 기본적으로 아래 두 role은 스캔에서 제외
# - "system": AI 도구(opencode 등)의 고정 시스템 프롬프트 — PII 없음
# - "tool_def": 함수 스키마 정의 — PII 없음
DEFAULT_SKIP_ROLES: frozenset[str] = frozenset({"system", "tool_def"})


@dataclass
class PipelineControl:
    regex_enabled: bool = True
    confidence_threshold: float = 0.5
    context_penalty_enabled: bool = True
    asset_enabled: bool = True
    ml_filter_enabled: bool = False      # 기본 OFF (옵트인) — 모델 없으면 no-op
    ml_filter_threshold: float = 0.4    # TP 확률 임계값 (보수적, Recall 우선)
    disabled_rules: list[str] = field(default_factory=list)
    allowlist: list[AllowlistEntry] = field(default_factory=list)
    mask_templates: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_MASK_TEMPLATES))
    skip_roles: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_SKIP_ROLES))
    custom_rules: list = field(default_factory=list)  # list[RegexRule] 타입을 임포트 순환 방지로 list로 선언


def _parse_custom_rules(raw_items: list) -> list:
    """
    control.json의 custom_rules 배열을 RegexRule 객체 리스트로 변환.
    가져오기 순환을 피하기 위해 실제 RegexRule 생성은 런타임에 동적으로 수행.
    각 항목 형식:
      { "name": str, "pattern": str, "severity": str, "description": str }
    """
    from .regex_stage import RegexRule  # 런타임 import (순환 방지)
    from .base import Severity

    _SEV = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }

    rules = []
    seen_names: set[str] = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        pattern_str = str(item.get("pattern", "")).strip()
        if not name or not pattern_str:
            continue
        if name in seen_names:
            continue
        seen_names.add(name)
        try:
            compiled = re.compile(pattern_str)
        except re.error:
            continue
        sev_str = str(item.get("severity", "high")).lower()
        sev = _SEV.get(sev_str, Severity.HIGH)
        desc = str(item.get("description", name)).strip()
        rules.append(RegexRule(
            name=name,
            pattern=compiled,
            severity=sev,
            description=desc,
        ))
    return rules


def _parse_allowlist(raw_items: list) -> list[AllowlistEntry]:
    entries: list[AllowlistEntry] = []
    for item in raw_items[-ALLOWLIST_LIMIT:]:
        if isinstance(item, str):
            entries.append(AllowlistEntry(
                rule="*",
                value=item,
                normalized=_normalize_for_allowlist(item),
            ))
            continue

        if not isinstance(item, dict):
            continue

        value = str(item.get("value", "")).strip()
        if not value:
            continue

        normalized = str(item.get("normalized", "")).strip() or _normalize_for_allowlist(value)
        entries.append(AllowlistEntry(
            rule=str(item.get("rule", "*")).strip() or "*",
            value=value,
            normalized=normalized,
            added_at=item.get("added_at"),
            expires_at=item.get("expires_at"),
        ))
    return entries


def load_control(path: str = DEFAULT_CONTROL_PATH) -> PipelineControl:
    control_path = Path(path)
    if not control_path.exists():
        return PipelineControl()

    try:
        data = json.loads(control_path.read_text(encoding="utf-8"))
    except Exception:
        return PipelineControl()

    threshold = data.get("confidence_threshold", 0.5)
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        threshold = 0.5
    threshold = min(max(threshold, 0.0), 1.0)

    allowlist = [
        entry
        for entry in _parse_allowlist(data.get("allowlist", []))
        if not entry.is_expired()
    ]
    disabled_rules = [str(name) for name in data.get("disabled_rules", []) if str(name).strip()]

    raw_skip = data.get("skip_roles")
    if isinstance(raw_skip, list):
        skip_roles: frozenset[str] = frozenset(str(r).strip() for r in raw_skip if str(r).strip())
    else:
        skip_roles = frozenset(DEFAULT_SKIP_ROLES)

    custom_rules = _parse_custom_rules(data.get("custom_rules", []))

    return PipelineControl(
        regex_enabled=bool(data.get("regex_enabled", True)),
        confidence_threshold=threshold,
        context_penalty_enabled=bool(data.get("context_penalty_enabled", True)),
        asset_enabled=bool(data.get("asset_enabled", True)),
        ml_filter_enabled=bool(data.get("ml_filter_enabled", False)),
        ml_filter_threshold=float(data.get("ml_filter_threshold", 0.4)),
        disabled_rules=disabled_rules,
        allowlist=allowlist,
        mask_templates=merge_mask_templates(data.get("mask_templates", {}), allow_custom=True),
        skip_roles=skip_roles,
        custom_rules=custom_rules,
    )


def is_allowlisted(rule_name: str, value: str, allowlist: list[AllowlistEntry]) -> bool:
    normalized = _normalize_for_allowlist(value)
    for entry in allowlist:
        if entry.rule not in ("*", rule_name):
            continue
        if entry.normalized == normalized:
            return True
    return False