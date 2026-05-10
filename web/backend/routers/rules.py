"""커스텀 정규식 룰 CRUD API.

control.json 의 custom_rules 배열을 직접 편집한다.
엔진은 매 스캔마다 control.json 을 re-read 하므로 즉시 반영된다.
"""
from __future__ import annotations
import json
import re
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from settings import CONTROL_FILE

router = APIRouter()

# 엔진과 동일한 내장 룰 목록 (참고용)
BUILTIN_RULES: list[dict] = [
    {"name": "kr_rrn",              "severity": "critical", "builtin": True, "description": "주민등록번호"},
    {"name": "credit_card",         "severity": "critical", "builtin": True, "description": "신용카드 번호"},
    {"name": "us_ssn",              "severity": "critical", "builtin": True, "description": "미국 사회보장번호"},
    {"name": "aws_access_key",      "severity": "critical", "builtin": True, "description": "AWS 액세스 키"},
    {"name": "pem_private_key",     "severity": "critical", "builtin": True, "description": "PEM 개인키"},
    {"name": "github_pat",          "severity": "critical", "builtin": True, "description": "GitHub Personal Access Token"},
    {"name": "kr_passport",         "severity": "high",     "builtin": True, "description": "한국 여권번호"},
    {"name": "kr_driver_license",   "severity": "high",     "builtin": True, "description": "운전면허번호"},
    {"name": "jwt_token",           "severity": "high",     "builtin": True, "description": "JWT 토큰"},
    {"name": "api_key_assignment",  "severity": "high",     "builtin": True, "description": "API 키 할당 패턴"},
    {"name": "kr_phone",            "severity": "medium",   "builtin": True, "description": "한국 전화번호"},
    {"name": "email",               "severity": "low",      "builtin": True, "description": "이메일 주소"},
]


class RuleIn(BaseModel):
    name: str
    pattern: str
    severity: str = "high"
    description: str = ""


def _read_control() -> dict:
    try:
        return json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_control(data: dict) -> None:
    CONTROL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _validate_pattern(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as e:
        raise HTTPException(422, f"정규식 오류: {e}")
    return pattern


def _validate_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(422, "name 은 비어있을 수 없습니다")
    if not re.match(r"^[a-z0-9_]{1,64}$", name):
        raise HTTPException(422, "name 은 소문자·숫자·언더스코어만 허용 (최대 64자)")
    if name in {r["name"] for r in BUILTIN_RULES}:
        raise HTTPException(409, f"'{name}' 은 내장 룰 이름입니다 — 다른 이름을 사용하세요")
    return name


@router.get("/rules")
async def list_rules():
    """내장 룰 목록 + 커스텀 룰 목록을 합쳐서 반환."""
    ctrl = _read_control()
    disabled = set(ctrl.get("disabled_rules", []))
    custom = ctrl.get("custom_rules", [])
    builtins = [
        {**r, "enabled": r["name"] not in disabled}
        for r in BUILTIN_RULES
    ]
    customs = [
        {**r, "builtin": False, "enabled": r.get("name", "") not in disabled}
        for r in custom
    ]
    return {"builtin": builtins, "custom": customs}


@router.post("/rules", status_code=201)
async def create_rule(body: RuleIn):
    """커스텀 룰 추가."""
    name = _validate_name(body.name)
    _validate_pattern(body.pattern)
    severity = body.severity if body.severity in ("critical", "high", "medium", "low") else "high"

    ctrl = _read_control()
    custom = ctrl.get("custom_rules", [])
    if any(r.get("name") == name for r in custom):
        raise HTTPException(409, f"커스텀 룰 '{name}' 이미 존재")

    entry = {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "pattern": body.pattern,
        "severity": severity,
        "description": body.description.strip(),
    }
    custom.append(entry)
    ctrl["custom_rules"] = custom
    _write_control(ctrl)
    return entry


@router.put("/rules/{name}")
async def update_rule(name: str, body: RuleIn):
    """커스텀 룰 수정."""
    _validate_pattern(body.pattern)
    ctrl = _read_control()
    custom = ctrl.get("custom_rules", [])
    idx = next((i for i, r in enumerate(custom) if r.get("name") == name), None)
    if idx is None:
        raise HTTPException(404, f"커스텀 룰 '{name}' 없음 (내장 룰은 수정 불가)")
    severity = body.severity if body.severity in ("critical", "high", "medium", "low") else "high"
    custom[idx] = {
        **custom[idx],
        "pattern": body.pattern,
        "severity": severity,
        "description": body.description.strip(),
    }
    ctrl["custom_rules"] = custom
    _write_control(ctrl)
    return custom[idx]


@router.delete("/rules/{name}", status_code=204)
async def delete_rule(name: str):
    """커스텀 룰 삭제."""
    ctrl = _read_control()
    custom = ctrl.get("custom_rules", [])
    new_custom = [r for r in custom if r.get("name") != name]
    if len(new_custom) == len(custom):
        raise HTTPException(404, f"커스텀 룰 '{name}' 없음")
    ctrl["custom_rules"] = new_custom
    _write_control(ctrl)


@router.patch("/rules/{name}/toggle")
async def toggle_rule(name: str):
    """내장 룰 또는 커스텀 룰을 enabled/disabled 전환."""
    ctrl = _read_control()
    disabled: list[str] = ctrl.get("disabled_rules", [])
    if name in disabled:
        disabled.remove(name)
        enabled = True
    else:
        disabled.append(name)
        enabled = False
    ctrl["disabled_rules"] = disabled
    _write_control(ctrl)
    return {"name": name, "enabled": enabled}
