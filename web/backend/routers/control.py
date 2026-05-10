"""제어 파일 API."""
from __future__ import annotations
import json

from fastapi import APIRouter, HTTPException

from models import ControlIn, ControlOut
from settings import CONTROL_FILE

router = APIRouter()

_DEFAULTS: dict = {
    "regex_enabled": True,
    "asset_enabled": True,
    "slm_enabled": False,
    "ml_filter_enabled": False,
    "ml_filter_threshold": 0.4,
    "mask_on_detect": False,
    "block_on_alert": False,
    "block_on_mask": False,
    "confidence_threshold": 0.5,
    "context_penalty_enabled": True,
    "disabled_rules": [],
    "allowlist": [],
    "mask_templates": {},
    "skip_roles": ["system", "tool_def"],
    "custom_rules": [],
}


def _read() -> dict:
    try:
        return {**_DEFAULTS, **json.loads(CONTROL_FILE.read_text(encoding="utf-8"))}
    except Exception:
        return dict(_DEFAULTS)


def _write(data: dict) -> None:
    CONTROL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@router.get("/control", response_model=ControlOut)
async def get_control():
    return ControlOut(**_read())


@router.put("/control", response_model=ControlOut)
async def put_control(body: ControlIn):
    current = _read()
    patch = body.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "변경할 항목이 없습니다")
    merged = {**current, **patch}
    # 값 범위 검증
    if "confidence_threshold" in patch:
        merged["confidence_threshold"] = max(0.0, min(1.0, merged["confidence_threshold"]))
    if "ml_filter_threshold" in patch:
        merged["ml_filter_threshold"] = max(0.0, min(1.0, merged["ml_filter_threshold"]))
    _write(merged)
    return ControlOut(**merged)
