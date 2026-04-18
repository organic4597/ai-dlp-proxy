from __future__ import annotations

import copy
import json
from pathlib import Path


DEFAULT_ASSETS: list[dict] = [
    {
        "id": "seed-ssh-key",
        "name": "SSH 키",
        "severity": "critical",
        "keywords": [".ssh", "id_rsa", "id_ed25519", "authorized_keys"],
        "examples": [
            "id_rsa 파일을 첨부합니다",
            "SSH 개인키를 전달드립니다",
            ".ssh/authorized_keys 점검 부탁드립니다",
        ],
        "embedding_threshold": 0.85,
    },
    {
        "id": "seed-kubeconfig",
        "name": "Kubernetes kubeconfig",
        "severity": "high",
        "keywords": ["kubeconfig", ".kube/config", "admin.conf"],
        "examples": [
            "운영 클러스터 kubeconfig 공유합니다",
            ".kube/config 파일 확인 부탁드립니다",
            "admin.conf 백업본 전달드립니다",
        ],
        "embedding_threshold": 0.84,
    },
    {
        "id": "seed-service-account",
        "name": "서비스 계정 키 파일",
        "severity": "high",
        "keywords": ["service-account.json", "sa-key.json", "gcp-sa.json"],
        "examples": [
            "service-account.json 첨부합니다",
            "배포용 sa-key.json 전달드립니다",
            "gcp-sa.json 키 파일입니다",
        ],
        "embedding_threshold": 0.83,
    },
    {
        "id": "seed-prod-env",
        "name": "운영 환경 변수 파일",
        "severity": "medium",
        "keywords": [".env.production", "prod.env", "docker-prod.env"],
        "examples": [
            "운영 .env.production 파일 공유합니다",
            "prod.env 값을 확인해주세요",
            "docker-prod.env 전달드립니다",
        ],
        "embedding_threshold": 0.82,
    },
]


def get_default_assets() -> list[dict]:
    return copy.deepcopy(DEFAULT_ASSETS)


def ensure_default_assets_file(path: Path) -> list[dict]:
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        assets = raw.get("assets", [])
        return assets if isinstance(assets, list) else []

    assets = get_default_assets()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"assets": assets}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return assets