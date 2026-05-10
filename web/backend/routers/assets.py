"""보호 자산(Protected Assets) CRUD API.

~/.config/ai-dlp-proxy/assets.json 을 직접 편집한다.
엔진의 AssetStage 는 매 스캔마다 파일을 다시 읽어 즉시 반영.
"""
from __future__ import annotations
import json
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

ASSETS_FILE = Path.home() / ".config/ai-dlp-proxy/assets.json"

# 기본 자산 (엔진의 default_assets.py 와 동기화)
_DEFAULT_ASSETS: list[dict] = [
    {
        "id": "seed-ssh-key", "name": "SSH 키", "severity": "critical",
        "keywords": [".ssh", "id_rsa", "id_ed25519", "authorized_keys"],
        "examples": ["id_rsa 파일을 첨부합니다", "SSH 개인키를 전달드립니다"],
        "embedding_threshold": 0.85,
    },
    {
        "id": "seed-kubeconfig", "name": "Kubernetes kubeconfig", "severity": "high",
        "keywords": ["kubeconfig", ".kube/config", "admin.conf"],
        "examples": ["운영 클러스터 kubeconfig 공유합니다", "admin.conf 백업본 전달드립니다"],
        "embedding_threshold": 0.84,
    },
    {
        "id": "seed-service-account", "name": "서비스 계정 키 파일", "severity": "high",
        "keywords": ["service-account.json", "sa-key.json", "gcp-sa.json"],
        "examples": ["service-account.json 첨부합니다", "배포용 sa-key.json 전달드립니다"],
        "embedding_threshold": 0.83,
    },
    {
        "id": "seed-prod-env", "name": "운영 환경 변수 파일", "severity": "medium",
        "keywords": [".env.production", "prod.env", "docker-prod.env"],
        "examples": ["운영 .env.production 파일 공유합니다"],
        "embedding_threshold": 0.82,
    },
]


class AssetIn(BaseModel):
    name: str
    severity: str = "high"
    keywords: list[str] = []
    examples: list[str] = []
    embedding_threshold: float = 0.83


def _read() -> list[dict]:
    if not ASSETS_FILE.exists():
        ASSETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write(_DEFAULT_ASSETS)
        return list(_DEFAULT_ASSETS)
    try:
        raw = json.loads(ASSETS_FILE.read_text(encoding="utf-8"))
        return raw.get("assets", raw) if isinstance(raw, dict) else raw
    except Exception:
        return list(_DEFAULT_ASSETS)


def _write(assets: list[dict]) -> None:
    ASSETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ASSETS_FILE.write_text(
        json.dumps({"assets": assets}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


@router.get("/assets")
async def list_assets():
    return _read()


@router.post("/assets", status_code=201)
async def create_asset(body: AssetIn):
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "name 은 비어있을 수 없습니다")
    severity = body.severity if body.severity in ("critical", "high", "medium", "low") else "high"
    threshold = max(0.5, min(1.0, body.embedding_threshold))

    assets = _read()
    if any(a.get("name") == name for a in assets):
        raise HTTPException(409, f"자산 '{name}' 이미 존재")

    entry = {
        "id": str(uuid.uuid4())[:12],
        "name": name,
        "severity": severity,
        "keywords": [k.strip() for k in body.keywords if k.strip()],
        "examples": [e.strip() for e in body.examples if e.strip()],
        "embedding_threshold": threshold,
    }
    assets.append(entry)
    _write(assets)
    return entry


@router.put("/assets/{asset_id}")
async def update_asset(asset_id: str, body: AssetIn):
    assets = _read()
    idx = next((i for i, a in enumerate(assets) if a.get("id") == asset_id), None)
    if idx is None:
        raise HTTPException(404, f"자산 '{asset_id}' 없음")

    name = body.name.strip() or assets[idx]["name"]
    severity = body.severity if body.severity in ("critical", "high", "medium", "low") else "high"
    threshold = max(0.5, min(1.0, body.embedding_threshold))

    assets[idx] = {
        **assets[idx],
        "name": name,
        "severity": severity,
        "keywords": [k.strip() for k in body.keywords if k.strip()],
        "examples": [e.strip() for e in body.examples if e.strip()],
        "embedding_threshold": threshold,
    }
    _write(assets)
    return assets[idx]


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(asset_id: str):
    assets = _read()
    new_assets = [a for a in assets if a.get("id") != asset_id]
    if len(new_assets) == len(assets):
        raise HTTPException(404, f"자산 '{asset_id}' 없음")
    _write(new_assets)


@router.post("/assets/reset-defaults", status_code=200)
async def reset_defaults():
    """기본 자산으로 초기화 (사용자 추가 자산 보존)."""
    assets = _read()
    existing_ids = {a["id"] for a in assets}
    added = 0
    for d in _DEFAULT_ASSETS:
        if d["id"] not in existing_ids:
            assets.append(dict(d))
            added += 1
    _write(assets)
    return {"added": added, "total": len(assets)}
