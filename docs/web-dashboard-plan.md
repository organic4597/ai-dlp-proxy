# AI-DLP-Proxy 웹 대시보드 구현 문서

> 최초 계획: 2026-05-10 · **구현 완료: 2026-05-10 · 최종 수정: 2026-05-10**  
> 상태: ✅ 전체 구현 완료 (10개 페이지, `/control`과 `/settings` 통합, 데이터 초기화 추가)  
> 목표: TUI의 모든 기능을 웹 브라우저에서 동일하게 사용 가능한 실시간 대시보드 구현

---

## 1. 목표 및 범위

### 기능 목표 (TUI 탭 ↔ 웹 페이지 1:1 대응, + 확장 페이지)

| TUI 탭 | 웹 페이지 | 핵심 기능 | 상태 |
|--------|----------|----------|------|
| 트래픽 | `/traffic` | 실시간 요청 스트림, 액션 배지, 상세 펼침 | ✅ |
| 탐지 목록 | `/findings` | PII 탐지 리스트, 룰/신뢰도 필터 | ✅ |
| 파이프라인 | `/pipeline` | 파이프라인 플로우 시각화, 캐시·SLM·Suppress 통계 | ✅ |
| 제어 + 설정 | `/settings` **(통합)** | 파이프라인 스테이지·액션 토글, 임계값, Skip Roles, 허용목록 CRUD, 데이터 초기화 | ✅ |
| 프로세스 | `/process` | mitmproxy·엔진 프로세스 상태/시작/중지 | ✅ |
| 엔진 로그 | `/logs` | 실시간 로그 스트림, 레벨 필터, 일시정지 | ✅ |
| 감사 로그 | `/audit` | audit.jsonl 뷰어, 필터·페이징, CSV 내보내기 | ✅ |
| *(신규)* | `/rules` | 커스텀 룰 CRUD, 빌트인 룰 ON/OFF 토글 | ✅ |
| *(신규)* | `/assets` | 보호 자산 CRUD, 임베딩 임계값, 기본값 복원 | ✅ |
| *(신규)* | `/allowlist` | 허용목록 CRUD, 만료일 관리, 마스킹 템플릿 편집 | ✅ |

### 비기능 목표
- 단일 서버 (로컬 또는 홈 서버) 배포 ✅
- 엔진 재시작 없이 대시보드 독립 운영 ✅
- 새 탭/새로고침 후 직전 상태 즉시 복원 ✅
- 모바일 화면에서도 기본 조회 가능 ✅

---

## 2. DB 선정

### 데이터 규모 추정

| 종류 | 발생 빈도 | 보존 기간 | 예상 1일 건수 |
|------|----------|---------|-------------|
| 트래픽 요청 | LLM API 호출마다 | 30일 | ~1,000건 |
| Finding | 요청당 0~20개 | 30일 | ~5,000건 |
| Audit | 요청당 1개 | 90일 | ~1,000건 |
| 엔진 로그 | 초당 1~10줄 | 7일 | ~200,000줄 |

30일 기준 최대 트래픽 30만건, Finding 150만건 — **SQLite로 충분히 처리 가능**.

### 결론: SQLite (WAL 모드) + 인메모리 캐시(dict)

**선정 근거:**

```
장점
  - 추가 서버 프로세스 없음 → 배포 단순
  - WAL(Write-Ahead Logging) 모드: 다수 동시 Reader + 1 Writer 지원
  - Python 내장 (sqlite3 / aiosqlite)
  - VACUUM·자동 파티션 없이 수 GB 데이터도 정상 동작
  - 인덱스로 시계열 쿼리 충분히 빠름

단점 / 보완책
  - 멀티 프로세스 쓰기 병목 → 엔진→DB 쓰기를 단일 asyncio task로 직렬화
  - 복잡한 시계열 집계 → DuckDB로 분석 쿼리만 오프로드 (선택)
```

**비교 탈락 이유:**

| 후보 | 탈락 이유 |
|------|---------|
| PostgreSQL / TimescaleDB | 별도 서버 필요, 단일 로컬 환경에서 과잉 |
| InfluxDB | 시계열 특화지만 Python 에코시스템 통합 복잡, 관리 오버헤드 |
| Redis | 영속성 미흡, 대용량 audit 저장 부적합 (실시간 버퍼로만 사용 가능) |
| MongoDB | 의존성 대비 효용 없음 |

### DB 파일 위치

```
~/.config/ai-dlp-proxy/
  db/
    dlp.db          ← 메인 SQLite (트래픽·Finding·Audit·통계)
    dlp.db-wal      ← WAL 파일 (자동)
    dlp.db-shm      ← 공유 메모리 (자동)
  audit.jsonl       ← 기존 파일 (DB로 마이그레이션 후 백업)
```

---

## 3. DB 스키마

```sql
-- ─────────────────────────────────────────────────────────────
-- 트래픽 요청
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,          -- ISO8601
    request_id   TEXT    UNIQUE,            -- 엔진 내부 ID
    provider     TEXT,
    model        TEXT,
    pipeline_action TEXT DEFAULT 'pass',   -- pass/alert/mask/block
    raw_finding_count   INTEGER DEFAULT 0,
    effective_finding_count INTEGER DEFAULT 0,
    total_text_len INTEGER DEFAULT 0,
    target_count   INTEGER DEFAULT 0,
    elapsed_ms     REAL,
    cache_hit      INTEGER DEFAULT 0       -- bool
);
CREATE INDEX IF NOT EXISTS idx_req_ts  ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_req_act ON requests(pipeline_action);

-- ─────────────────────────────────────────────────────────────
-- PII 탐지 결과
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT    NOT NULL REFERENCES requests(request_id),
    ts           TEXT    NOT NULL,
    stage        TEXT,
    rule         TEXT,
    severity     TEXT,
    confidence   REAL,
    suppressed   INTEGER DEFAULT 0,        -- bool
    suppressed_reason TEXT,
    match_text   TEXT,
    field_path   TEXT,
    role         TEXT,
    metadata     TEXT                      -- JSON blob
);
CREATE INDEX IF NOT EXISTS idx_find_req  ON findings(request_id);
CREATE INDEX IF NOT EXISTS idx_find_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS idx_find_ts   ON findings(ts);

-- ─────────────────────────────────────────────────────────────
-- 파이프라인 누적 통계 스냅샷 (1분 단위 집계)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pipeline_snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    cache_hits   INTEGER DEFAULT 0,
    cache_misses INTEGER DEFAULT 0,
    nms_suppressed    INTEGER DEFAULT 0,
    ml_suppressed     INTEGER DEFAULT 0,
    al_suppressed     INTEGER DEFAULT 0,
    slm_calls         INTEGER DEFAULT 0,
    slm_avg_ms        REAL DEFAULT 0,
    action_pass       INTEGER DEFAULT 0,
    action_alert      INTEGER DEFAULT 0,
    action_mask       INTEGER DEFAULT 0,
    action_block      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snap_ts ON pipeline_snapshots(ts);

-- ─────────────────────────────────────────────────────────────
-- 엔진 로그 (최근 7일만 보존)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS engine_logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    level    TEXT DEFAULT 'INFO',
    message  TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_ts ON engine_logs(ts);
```

### 데이터 보존 정책 (자동 정리)

```python
# 서버 시작 시 + 1시간 주기 실행
DELETE FROM requests        WHERE ts < datetime('now', '-30 days');
DELETE FROM findings        WHERE ts < datetime('now', '-30 days');
DELETE FROM pipeline_snapshots WHERE ts < datetime('now', '-90 days');
DELETE FROM engine_logs     WHERE ts < datetime('now', '-7 days');
PRAGMA incremental_vacuum;
```

---

## 4. 기술 스택

### 백엔드

```
FastAPI (Python 3.12)  ←  이미 venv에 설치 가능
  ├─ uvicorn (ASGI 서버)
  ├─ aiosqlite  (비동기 SQLite)
  └─ python-multipart (파일 업로드용, 선택)
```

- **선정 이유**: 이미 Python 환경 존재, 엔진과 동일 언어, async 네이티브, 자동 OpenAPI 문서

### 프론트엔드

```
SvelteKit (Svelte 5)
  ├─ Tailwind CSS v4 (유틸리티 CSS)
  ├─ shadcn-svelte (컴포넌트 라이브러리)
  ├─ Chart.js / uplot (그래프)
  └─ EventSource API (SSE 실시간)
```

**Svelte 선정 이유 (React·Vue 대비):**
- 번들 크기 가장 작음 → 로컬 서버 부담 최소
- 컴파일 타임 반응성 → 런타임 Virtual DOM 없음
- `$state` / `$derived` 로 실시간 상태 관리 직관적
- SvelteKit = 라우팅 + SSR + 파일 기반 레이아웃 내장

### 실시간 통신: SSE (Server-Sent Events)

```
엔진 이벤트 흐름:
  mitmproxy addon
      → engine_server.py (Unix Socket, action=subscribe)
      → FastAPI /api/events (SSE endpoint)
      → Browser EventSource
      → Svelte $state 업데이트 → DOM 반영
```

**SSE vs WebSocket 비교:**

| 기준 | SSE | WebSocket |
|------|-----|----------|
| 방향 | 서버→클라이언트 단방향 | 양방향 |
| 복잡도 | 낮음 (HTTP 기반) | 높음 |
| 재연결 | 브라우저 자동 처리 | 수동 구현 필요 |
| 프록시/방화벽 | 호환성 높음 | 일부 제한 |
| 제어 명령 | REST API로 분리 | 단일 소켓으로 통합 가능 |

→ **SSE + REST API 조합** 선택:  
실시간 스트림은 SSE, 제어 명령(임계값 변경·ON-OFF)은 REST API

---

## 5. 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (SvelteKit SPA)                                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ /traffic │ │/findings │ │/pipeline │ │ /control │   ...     │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘          │
│       │  EventSource (SSE)       │  REST (fetch)               │
└───────┼──────────────────────────┼─────────────────────────────┘
        │                          │
┌───────▼──────────────────────────▼─────────────────────────────┐
│  FastAPI Web Server  (port 8765)                                │
│                                                                  │
│  GET  /api/events          ← SSE 스트림 (scan·log 이벤트)       │
│  GET  /api/traffic         ← 최근 요청 목록 (DB 조회)            │
│  GET  /api/findings        ← 탐지 목록 (필터·페이징)             │
│  GET  /api/pipeline/stats  ← 파이프라인 현재 통계               │
│  GET  /api/audit           ← 감사 로그 (필터·페이징)             │
│  GET  /api/control         ← 제어 파일 현재 값 조회              │
│  PUT  /api/control         ← 제어 파일 변경 (임계값 등)          │
│  POST /api/process/start   ← 프로세스 시작                       │
│  POST /api/process/stop    ← 프로세스 중지                       │
│  GET  /api/logs            ← 엔진 로그 최근 N줄                  │
│                                                                  │
│  내부:                                                           │
│  ├─ EngineClient      Unix Socket /tmp/dlp-engine.sock          │
│  ├─ EventBroadcaster  Subscribe → SSE fan-out                   │
│  ├─ DBWriter          scan 이벤트 → SQLite INSERT               │
│  └─ SnapshotWorker    1분 주기 stats → pipeline_snapshots        │
└───────────────────────┬────────────────────────────────────────┘
                        │ Unix Socket NDJSON
┌───────────────────────▼────────────────────────────────────────┐
│  engine_server.py  (기존, 무수정)                               │
│  action: scan / ping / stats / subscribe / control / ...       │
└───────────────────────┬────────────────────────────────────────┘
                        │
              mitmproxy addon  ←→  LLM API 트래픽
```

---

## 6. 디렉터리 구조

```
ai-dlp-proxy/
  web/                          ← 새로 추가
    backend/
      main.py                   ← FastAPI 앱 진입점
      db.py                     ← aiosqlite 연결·마이그레이션
      engine_client.py          ← engine_server.py와 소켓 통신
      event_bus.py              ← SSE fan-out 브로드캐스터
      routers/
        traffic.py
        findings.py
        pipeline.py
        control.py
        process.py
        audit.py
        logs.py
        events.py               ← SSE endpoint
      models.py                 ← Pydantic 스키마
      settings.py               ← 환경변수 (포트, DB 경로 등)
    frontend/                   ← SvelteKit 프로젝트
      src/
        routes/
          +layout.svelte        ← 사이드바 + 상단바 공통 레이아웃
          traffic/+page.svelte
          findings/+page.svelte
          pipeline/+page.svelte
          control/+page.svelte
          process/+page.svelte
          settings/+page.svelte
          logs/+page.svelte
          audit/+page.svelte
        lib/
          stores/
            events.svelte.ts    ← SSE EventSource 관리 (전역 store)
            traffic.svelte.ts
            pipeline.svelte.ts
          components/
            PipelineFlow.svelte ← 파이프라인 노드 시각화
            FindingCard.svelte
            StatsCard.svelte
            RuleTable.svelte
            ConfHistogram.svelte
            ActionBadge.svelte
        app.css                 ← Tailwind 진입점
      package.json
      svelte.config.js
      vite.config.ts
    start_web.sh                ← 백엔드 + 프론트 동시 실행
```

---

## 7. 실시간 데이터 흐름 상세

### 7-1. scan 이벤트 → 브라우저까지

```
1. mitmproxy addon → engine_server.py  action=scan
2. engine_server.py  _broadcast_event({type:"scan_result", ...})
3. FastAPI EngineClient (subscribe 모드 상시 연결)
       수신 → asyncio.Queue → EventBroadcaster
4. EventBroadcaster → 모든 SSE 연결에 fan-out
5. Browser EventSource("GET /api/events")
       onmessage → Svelte store update → DOM reactive 반영
```

### 7-2. 엔진 로그 스트림

```
engine_server.py log.info()
  → Python logging.StreamHandler (stderr)
  → FastAPI 서버가 subprocess로 엔진 실행 시 stderr pipe 캡처
  → SSE type="log" 이벤트로 브라우저 전달
```

> 또는: engine_server.py에 `action=log_subscribe` 추가하여 로그 이벤트도 UDS로 전달

### 7-3. 제어 명령 흐름

```
브라우저 PUT /api/control {"ml_filter_enabled": true}
  → FastAPI control router
  → _patch_control() (기존 함수 재사용, 파일 직접 수정)
  → engine_server.py는 scan 시마다 load_control() 호출 → 자동 반영
  → SSE type="control_changed" 이벤트로 다른 탭에도 동기화
```

### 7-4. 통계 스냅샷 (히스토리 그래프용)

```
FastAPI SnapshotWorker (1분 주기)
  → GET /api/stats → engine_server.py action=stats
  → pipeline_snapshots INSERT
  → /pipeline 페이지: 최근 1시간 스냅샷 → Chart.js 시계열 그래프
```

---

## 8. 페이지별 상세 기능

### 8-1. 트래픽 (`/traffic`)

```
┌─ 상단 통계 카드 ──────────────────────────────────────┐
│  총 스캔  PASS  ALERT  MASK  BLOCK  평균 응답시간      │
└───────────────────────────────────────────────────────┘
┌─ 실시간 요청 테이블 (SSE로 행 prepend) ───────────────┐
│  시각 │ 제공자 │ 모델 │ 액션 │ 탐지 │ 응답시간        │
│  ...  │ ...   │ ...  │[MASK]│  3건 │  142ms          │
│       ← 클릭 시 하단 상세 패널 슬라이드 인            │
└───────────────────────────────────────────────────────┘
┌─ 상세 패널 ───────────────────────────────────────────┐
│  Request ID / Provider / Model / Action               │
│  Finding 목록 (룰·신뢰도·매치 원문·컨텍스트)          │
│  억제된 Finding (dim 표시, 이유 포함)                  │
└───────────────────────────────────────────────────────┘
```

### 8-2. 파이프라인 (`/pipeline`)

```
좌측: 파이프라인 노드 다이어그램 (SVG or HTML+CSS)
  요청 텍스트
      ↓
  [RegexStage]  total/suppressed/avgConf
      ↓
  [ML FP Filter] ON/OFF, 억제건수
      ──── NMS 중첩제거 ────
      ↓
  [AssetStage]
      ↓
  [SLM Stage]
      ↓
  [decide_action]  threshold

우측 상단: 캐시 히트율 도넛 차트 + 수치
우측 중단: SLM 평균/p95 응답시간 게이지
우측 하단: Suppress 분류 (NMS/ML/허용목록) 막대 차트

하단: 1시간 시계열 그래프 (액션별 요청 수)
```

### 8-3. 제어 (`/control`)

- 신뢰도 임계값: 슬라이더 + 숫자 입력, Save 버튼
- 스테이지 ON-OFF: 토글 카드 (Regex·Asset·SLM·ML필터)
- ML FP 임계값: 슬라이더
- 문맥 페널티: 토글
- 비활성 룰: 멀티 셀렉트 체크박스
- 허용목록: 테이블 + 추가/삭제 버튼
- 마스킹 템플릿: 룰별 템플릿 편집 인풋

### 8-4. 감사 로그 (`/audit`)

- 날짜 범위 피커 + 액션 필터 + 규칙 키워드 검색
- 무한 스크롤 or 페이지네이션 (DB 쿼리)
- 행 클릭 → 우측 상세 패널 (Finding 전체 목록)
- CSV 내보내기 버튼

### 8-5. 프로세스 (`/process`)

- mitmproxy 상태 (PID·업타임·포트)
- 엔진 상태 (PID·업타임·소켓 경로)
- 시작/중지 버튼 → POST /api/process/start|stop
- 인증서 정보·경로 표시

---

## 9. 구현 단계 계획

### Phase 0 — 기반 (1~2일)

```
[ ] SQLite 스키마 생성 (db.py)
[ ] aiosqlite 연결 풀 설정
[ ] engine_client.py — UDS 연결, ping/stats/subscribe/control 래핑
[ ] event_bus.py — asyncio.Queue fan-out (SSE 브로드캐스터)
[ ] FastAPI 앱 뼈대 + uvicorn 실행
[ ] SvelteKit + Tailwind + shadcn 초기화
[ ] EventSource 전역 스토어 (events.svelte.ts)
[ ] 공통 레이아웃 (사이드바 네비게이션)
```

### Phase 1 — 실시간 트래픽 (1일)

```
[ ] SSE /api/events endpoint
[ ] DBWriter: scan_result 이벤트 → requests·findings INSERT
[ ] GET /api/traffic (페이징·필터)
[ ] /traffic 페이지: 테이블 + SSE prepend + 상세 패널
```

### Phase 2 — 파이프라인 & 통계 (1~2일)

```
[ ] GET /api/pipeline/stats → engine action=stats 중계
[ ] SnapshotWorker 1분 주기 INSERT
[ ] GET /api/pipeline/snapshots?range=1h
[ ] /pipeline 페이지: 노드 다이어그램 + 차트
```

### Phase 3 — 제어 & 설정 (1일)

```
[ ] GET/PUT /api/control
[ ] /control 페이지: 슬라이더·토글 + SSE 동기화
[ ] /settings 페이지
```

### Phase 4 — 감사 로그 (1일)

```
[ ] audit.jsonl → DB 마이그레이션 스크립트
[ ] GET /api/audit (필터·페이징)
[ ] /audit 페이지: 테이블 + 필터 + 상세 + CSV 내보내기
```

### Phase 5 — 나머지 (1일)

```
[ ] /findings 페이지
[ ] /process 페이지
[ ] /logs 페이지 (SSE tail)
[ ] 엔진 로그 → DB 저장 or 직접 SSE 전달
[ ] 반응형 레이아웃 (모바일)
[ ] start_web.sh 실행 스크립트
```

---

## 10. 환경 설정 및 의존성

### 백엔드 추가 패키지

```bash
# 기존 venv에 추가
pip install fastapi uvicorn[standard] aiosqlite python-multipart
```

### 프론트엔드 초기화

```bash
cd web/frontend
npm create svelte@latest .   # SvelteKit
npm install
npx svelte-add@latest tailwindcss
npm install -D shadcn-svelte
npx shadcn-svelte@latest init
npm install chart.js
```

### 실행 스크립트 (`web/start_web.sh`)

```bash
#!/bin/bash
cd "$(dirname "$0")"
source ../venv/bin/activate

# 백엔드 (포트 8765)
uvicorn backend.main:app --host 0.0.0.0 --port 8765 --reload &
BACKEND_PID=$!

# 프론트엔드 개발 서버 (포트 5173) — 프로덕션은 빌드 후 static 서빙
cd frontend && npm run dev &
FRONT_PID=$!

trap "kill $BACKEND_PID $FRONT_PID" EXIT
wait
```

> 프로덕션: `npm run build` 후 FastAPI에서 `StaticFiles` 마운트 → 단일 포트(8765)로 통합

### 포트 정책

| 서비스 | 포트 | 비고 |
|--------|------|------|
| mitmproxy | 8080 | 기존 |
| engine_server | /tmp/dlp-engine.sock | 기존 UDS |
| FastAPI 웹 서버 | 8765 | 신규 |
| SvelteKit dev | 5173 | 개발 시만 |

---

## 11. 보안 고려사항

- **로컬 전용 기본값**: uvicorn `--host 127.0.0.1` (외부 노출 시 명시적 변경) ✅
- **CORS**: 개발 시 `http://localhost:5173` 허용, 프로덕션 시 동일 Origin ✅
- **제어 API 인증**: 로컬 환경이므로 초기에는 생략. 외부 노출 시 Bearer 토큰 또는 Basic Auth 추가
- **XSS**: 프론트엔드에서 매치 원문 표시 시 `{@html}` 미사용, 텍스트 노드로만 출력 ✅
- **SQLite 경로 traversal**: DB 경로를 환경변수로만 받고 사용자 입력으로 동적 변경 불가 ✅
- **커스텀 룰 정규식**: 서버 측에서 `re.compile()` + 패턴 검증 후 저장 ✅

---

## 12. ~~미결 결정 사항~~ → 결정 완료 (2026-05-10)

| 항목 | 결정 | 비고 |
|------|------|------|
| 엔진 로그 SSE 방식 | **B: `action=log_subscribe`** | engine_server 기존 지원 활용 |
| 프론트 빌드 방식 | **A (개발 dev) / B (프로덕션 빌드)** | `start_web.sh`로 통합 |
| 감사 로그 소스 | **DB 단독** | jsonl → DB 마이그레이션 API 제공 |
| 차트 라이브러리 | **Chart.js** | 파이프라인 시계열에 사용 |
| 인증 | **없음** (로컬 전용) | 필요 시 Bearer 토큰 추가 가능 |

---

## 13. 실제 구현 현황 (2026-05-10)

### 빌드 결과

```
npm run build
  ✓ 160 modules transformed → ✓ built in 7.13s  — 에러 없음
```

### 운영 프로세스 (정상 상태)

```
PID=mitmdump   --listen-host 0.0.0.0 -p 4001
PID=engine_server.py --sock /tmp/dlp-engine.sock
PID=uvicorn main:app --host 127.0.0.1 --port 8765
```

### 데몬 관리

```bash
./dlp-supervisor start          # 전체 시작
./dlp-supervisor stop engine    # 개별 중지
./dlp-supervisor status         # PID + 메모리 현황
./dlp-supervisor logs web       # 실시간 로그

# 환경변수 커스터마이징
DLP_MITM_PORT=4001 DLP_WEB_PORT=8765 DLP_WEBDEV=true ./dlp-supervisor start
```

---

## 참고: 기존 코드 재사용 포인트

- `scripts/engine_server.py` — `action=subscribe` 이미 구현됨 → EngineClient에서 그대로 활용 ✅
- `scripts/engine_server.py` — `action=stats` → `/api/pipeline/stats` 중계 ✅
- `src/engine/pipeline/control.py` — `load_control()`, `_patch_control()` → 제어 API에서 직접 import ✅
- `src/engine/pipeline/__init__.py` — `get_cache_stats()`, `get_slm_stats()` → stats endpoint ✅
- `~/.config/ai-dlp-proxy/audit.jsonl` — `POST /api/audit/migrate-jsonl` API로 DB 마이그레이션 가능 ✅
