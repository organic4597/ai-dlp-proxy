# GUI Control Validation

기준일: 2026-04-18

검증 스크립트:

- [tests/run_gui_control_checks.py](tests/run_gui_control_checks.py)
- [tests/fixtures/dummy_service.py](tests/fixtures/dummy_service.py)

최신 실행 결과:

| 항목 | 값 |
|---|---|
| GUI 검증 결과 | 66 passed, 0 failed |
| 기존 회귀 테스트 | 61 passed, 0 failed |
| 프로세스 버튼 검증 방식 | 실제 subprocess e2e + dummy long-running service |
| 정책 적용 검증 방식 | 제어 파일 반영 + engine/inspect runtime path 검증 |

## 런타임 정책 검증

| GUI 항목 | 저장 키 | 실제 소비 위치 | 검증 방식 | 상태 |
|---|---|---|---|---|
| Regex Stage 스위치 | `regex_enabled` | `run_pipeline()` | ON/OFF 시 finding 생성 여부 비교 | PASS |
| Asset Stage 스위치 | `asset_enabled` | `run_pipeline()` | ON/OFF 시 asset finding 생성 여부 비교 | PASS |
| SLM Stage 스위치 | `slm_enabled` | `engine_server._handle_scan()` → `run_pipeline(..., slm_enabled=...)` | 전달 인자 캡처 | PASS |
| 내부 stats 요청 제외 | 엔진 `_stats.total` | `engine_server.handle_client()` | `stats`는 total 미증가, `scan`만 증가 확인 | PASS |
| 신뢰도 임계값 | `confidence_threshold` | `engine_server._handle_scan()` / `inspect_traffic.py` | effective finding count 변화 확인 | PASS |
| 마스킹 룰 토글 | `disabled_rules` | `RegexStage.scan()` | 룰 비활성 시 탐지 제거 확인 | PASS |
| 기본 보호 자산 시드 | `assets.json` | `default_assets.py` / `AssetStage` / TUI | 파일 미존재 시 기본 자산 자동 생성 확인 | PASS |
| Allowlist | `allowlist` | `RegexStage.scan()` | finding suppressed 여부 확인 | PASS |
| 탐지 시 본문 마스킹 | `mask_on_detect` | `InspectAddon.request()` | 요청 body 실제 치환 확인 | PASS |
| ALERT 차단 | `block_on_alert` | `InspectAddon.request()` | 403 응답 생성 확인 | PASS |
| 정책 off 시 pass-through | `mask_on_detect=false`, `block_on_mask=false` | `InspectAddon.request()` | 엔진 `MASK` 추천이어도 원문 전달 확인 | PASS |
| MASK 차단 | `block_on_mask` | `InspectAddon.request()` | 403 응답 생성 확인 | PASS |

## TUI 위젯/핸들러 검증

| GUI 항목 | 기대 동작 | 검증 방식 | 상태 |
|---|---|---|---|
| `sw-cap` | 캡처 플래그 파일 생성/삭제 | `/tmp/dlp-capture-next` 존재 여부 확인 | PASS |
| `sw-auto` | 내부 자동 스크롤 상태 변경 | `DLPApp._auto` 확인 | PASS |
| `sw-pass` | PASS 이벤트 숨김 | `ttable` 행 수 변화 없음 확인 | PASS |
| `sw-tg` | `gpt-5-mini` 제목 요청 숨김 | `ttable` 행 수 변화 없음 확인 | PASS |
| `Ctrl+Q` 종료 | 앱 종료 요청 처리 | `pilot.press("ctrl+q")` 후 `is_running=False` 확인 | PASS |
| `sw-regex` | 제어 파일 반영 | `regex_enabled` 저장 값 확인 | PASS |
| `sw-asset` | 제어 파일 반영 | `asset_enabled` 저장 값 확인 | PASS |
| `sw-slm` | 제어 파일 반영 | `slm_enabled` 저장 값 확인 | PASS |
| 실시간 worker 유지 | subscribe/poll 동시 실행 | `engine-subscribe`, `engine-poll` worker 동시 RUNNING 확인 | PASS |
| 임계값 입력 + 저장 버튼 | 제어 파일 반영 | `confidence_threshold` 저장 값 확인 | PASS |
| 임계값 입력 + Enter | 제어 파일 반영 | `confidence_threshold` 저장 값 확인 | PASS |
| `ctrl-sw-mask-on-detect` | 제어 파일 반영 | `mask_on_detect` 저장 값 확인 | PASS |
| `ctrl-sw-block-alert` | 제어 파일 반영 | `block_on_alert` 저장 값 확인 | PASS |
| `ctrl-sw-block-mask` | 제어 파일 반영 | `block_on_mask` 저장 값 확인 | PASS |
| 시작 경고 팝업 | 실행 직후 warning toast 표시 | `notify()` 생성 알림 + 내부 warning 상태 확인 | PASS |
| 시작 경고 자동 숨김 | 일정 시간 후 자동 소멸 | notification collection 만료 확인 | PASS |
| 마스킹 룰 행 클릭/Enter | 즉시 ON/OFF 토글 | `disabled_rules` 반영 확인 | PASS |
| 마스킹 룰 저장 | 치환 텍스트 저장 | `mask_templates` 저장 값 확인 | PASS |
| 마스킹 룰 ON/OFF 버튼 | 룰 ON/OFF 토글 | `disabled_rules` 반영 확인 | PASS |
| 마스킹 룰 기본값 복원 | 사용자 치환 제거 | `mask_templates` override 제거 확인 | PASS |
| 자산 추가 모달 취소 | 변경 없음 | `assets.json` 동일성 확인 | PASS |
| 자산 추가 모달 확인 | 자산 추가 | `assets.json` row 추가 확인 | PASS |
| 자산 테이블 행 선택 | 선택 상태 반영 | `_selected_asset_id` 갱신 확인 | PASS |
| 자산 편집 버튼 | 기존 자산 수정 | `assets.json` row 변경 확인 | PASS |
| 자산 삭제 버튼 | 선택 자산 삭제 | `assets.json` row 제거 확인 | PASS |
| Allowlist 모달 취소 | 변경 없음 | `allowlist` 동일성 확인 | PASS |
| Allowlist 직접 추가 | 항목 추가 | `allowlist` row 추가 확인 | PASS |
| Allowlist 테이블 행 선택 | 선택 상태 반영 | `_selected_allowlist_index` 갱신 확인 | PASS |
| Allowlist 편집 버튼 | 기존 항목 수정 | `allowlist` row 변경 확인 | PASS |
| 선택 탐지 Allowlist 추가 | 후보값 기반 추가 | `allowlist` row 증가 확인 | PASS |
| Allowlist 삭제 버튼 | 선택 항목 삭제 | `allowlist` row 제거 확인 | PASS |
| 트래픽 상단 집계 | 표시 중인 트래픽 기준 합산 | `StatsBar.total/scanned/findings/masked` 확인 | PASS |
| 트래픽 테이블 행 선택 | 턴 상세 렌더 | `dlog` 출력 존재 확인 | PASS |
| 전송 내용 복사 버튼 | 상세 전송 텍스트 복사 | `copy_to_clipboard()` 전달 값 확인 | PASS |
| 정책 off + 엔진 MASK 추천 | 최종 상태는 `ALERT`, 전송 내용은 원문 유지 | `pipeline_action=mask`, `dlp_applied=pass` 이벤트 주입 후 `sent_text` 확인 | PASS |
| 전송 내용 실제 적용 반영 | `scan_applied` 후 마스킹 결과 갱신 | `dlp_applied=masked` 반영 + 치환 텍스트 확인 | PASS |
| NMS 억제 요청 최종 PASS | 유효 탐지 0건으로 집계되고 전송은 PASS | `effective_finding_count=0`, `suppressed_finding_count=1` 이벤트 주입 후 `StatsBar`/상세 확인 | PASS |
| 트래픽 탐지 정보 전체 표시 | 긴 finding 컨텍스트와 대상 원문 전체 렌더 | 긴 이벤트 주입 후 `dlog`에 시작/끝 마커 확인 | PASS |
| 탐지 테이블 행 선택 | 선택 상태 갱신 | `_selected_finding` 설정 확인 | PASS |
| 억제 탐지 상세 일관성 | suppressed finding도 최종 상태/억제 사유와 함께 유지 | 선택된 finding의 `suppressed_reason=nms`, 최종 상태 `pass` 확인 | PASS |
| 탐지 목록 상세 전체 표시 | 긴 finding의 매치/원문/앞뒤 컨텍스트 전체 렌더 | 탐지 목록 탭 활성화 후 `fdetail`에 시작/끝 마커 확인 | PASS |
| 로그 클리어 버튼 | 엔진 로그 비움 | `elog.lines == 0` 확인 | PASS |
| 트래픽 클리어 버튼 | 테이블/히스토리 비움 | `ttable`, `ftable`, JSONL 파일 초기화 확인 | PASS |
| 탐지 클리어 버튼 | 탐지 목록 비움 | `ftable.row_count == 0` 확인 | PASS |

## 프로세스 버튼 e2e 검증

| GUI 항목 | 검증 대상 | 검증 방식 | 상태 |
|---|---|---|---|
| 엔진 시작 버튼 | 실제 subprocess 시작 | PID 할당 + dummy service start 로그 확인 | PASS |
| mitm 시작 버튼 | 실제 subprocess 시작 | PID 할당 + dummy service start 로그 확인 | PASS |
| 엔진 재시작 버튼 | 실제 subprocess 재기동 | PID 변경 + stop/start 로그 확인 | PASS |
| mitm 재시작 버튼 | 실제 subprocess 재기동 | PID 변경 + stop/start 로그 확인 | PASS |
| 엔진 중지 버튼 | 실제 subprocess 종료 | `running=False`, `enabled=False`, stop 로그 확인 | PASS |
| mitm 중지 버튼 | 실제 subprocess 종료 | `running=False`, `enabled=False`, stop 로그 확인 | PASS |

## GUI 미노출 제어 키

| 제어 키 | 현재 상태 | 비고 |
|---|---|---|
| `context_penalty_enabled` | GUI 미노출 | 제어 파일 수동 편집 또는 별도 UI 추가 필요 |

## 실행 방법

```bash
cd /home1/ai-dlp-proxy
source venv/bin/activate
PYTHONPATH=src python tests/run_gui_control_checks.py
python tests/run_tests.py
```