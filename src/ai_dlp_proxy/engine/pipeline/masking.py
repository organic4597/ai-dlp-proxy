from __future__ import annotations

import json
from pathlib import Path


DEFAULT_CONTROL_PATH = "/tmp/dlp-control.json"

EDITABLE_MASK_RULES: list[tuple[str, str]] = [
    ("kr_rrn", "critical"),
    ("credit_card", "critical"),
    ("us_ssn", "critical"),
    ("aws_access_key", "critical"),
    ("pem_private_key", "critical"),
    ("github_pat", "critical"),
    ("kr_passport", "high"),
    ("kr_driver_license", "high"),
    ("jwt_token", "high"),
    ("api_key_assignment", "high"),
    ("kr_phone", "medium"),
    ("email", "low"),
]

DEFAULT_MASK_TEMPLATES: dict[str, str] = {
    "kr_rrn": "[주민등록번호]",
    "kr_phone": "[전화번호]",
    "credit_card": "[카드번호]",
    "us_ssn": "[SSN]",
    "email": "[이메일]",
    "kr_passport": "[여권번호]",
    "kr_driver_license": "[운전면허]",
    "aws_access_key": "[AWS_KEY]",
    "api_key_assignment": "[API_KEY]",
    "pem_private_key": "[PRIVATE_KEY]",
    "jwt_token": "[JWT]",
    "github_pat": "[GH_TOKEN]",
    "person_name": "[이름]",
    "address": "[주소]",
    "organization": "[기관]",
    "date_of_birth": "[생년월일]",
    "account_number": "[계좌번호]",
    "ip_address": "[IP주소]",
    "device_id": "[기기ID]",
    "medical_info": "[의료정보]",
    "biometric": "[생체정보]",
    "slm_pii": "[개인정보]",
}


def merge_mask_templates(raw_overrides: object, allow_custom: bool = False) -> dict[str, str]:
    templates = dict(DEFAULT_MASK_TEMPLATES)
    if not isinstance(raw_overrides, dict):
        return templates
    for raw_rule, raw_value in raw_overrides.items():
        rule = str(raw_rule).strip()
        value = str(raw_value).strip()
        if not rule or not value:
            continue
        # 빌트인 규칙: 기존 값 덮어쓰기만 허용
        # 커스텀 규칙 (allow_custom=True): 새 키도 허용
        if rule in templates or allow_custom:
            templates[rule] = value
    return templates


def load_mask_templates(control_path: str = DEFAULT_CONTROL_PATH) -> dict[str, str]:
    try:
        data = json.loads(Path(control_path).read_text(encoding="utf-8"))
    except Exception:
        data = {}
    return merge_mask_templates(data.get("mask_templates", {}), allow_custom=True)