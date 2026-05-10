#!/usr/bin/env bash
# ai-dlp-proxy 웹 대시보드 시작 스크립트
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Python venv 활성화
source ../venv/bin/activate

# Python 의존성 설치 (없으면 설치)
echo "==> Python 의존성 확인..."
pip install -q fastapi "uvicorn[standard]" aiosqlite python-multipart

# 프론트엔드 의존성 설치
echo "==> Node.js 의존성 확인..."
cd frontend
if [ ! -d "node_modules" ]; then
  npm install
fi
cd ..

# 인자에 따라 dev / prod 모드 분기
MODE="${1:-dev}"

if [ "$MODE" = "dev" ]; then
  echo ""
  echo "==> 개발 모드: 백엔드(8765) + 프론트엔드(5173) 동시 실행"
  echo "     대시보드: http://localhost:5173"
  echo ""

  # 백엔드 백그라운드 (backend/ 디렉토리에서 실행)
  cd backend
  uvicorn main:app --host 127.0.0.1 --port 8765 --reload &
  BACKEND_PID=$!
  cd ..
  echo "    백엔드 PID: $BACKEND_PID"

  # 프론트엔드 포그라운드
  cd frontend
  npm run dev -- --port 5173 --open
  cd ..

  # 프론트엔드 종료 시 백엔드도 종료
  kill $BACKEND_PID 2>/dev/null || true

elif [ "$MODE" = "prod" ]; then
  echo ""
  echo "==> 프로덕션 모드: 프론트엔드 빌드 후 FastAPI 통합 서빙"

  cd frontend
  npm run build
  cd ..

  echo ""
  echo "    대시보드: http://127.0.0.1:8765"
  echo ""
  cd backend
  uvicorn main:app --host 127.0.0.1 --port 8765

else
  echo "사용법: $0 [dev|prod]"
  exit 1
fi
