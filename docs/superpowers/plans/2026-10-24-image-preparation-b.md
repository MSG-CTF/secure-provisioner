# B안 이미지 준비 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 생성 가용성과 보안 검증을 보존하면서 Backend 사전 다운로드와 Scheduler의 준비 target 우선순위를 연결한다.

**Architecture:** Runtime이 이미지 작업과 실제 노드 캐시 관측의 원본을 소유한다. Scheduler는 Broker 후보를 조회한 뒤 Runtime 관측 저장소를 일괄 조회하는 B안을 사용한다. Broker 예약 계약은 유지한다.

**Tech Stack:** Go Runtime/HTTP/PostgreSQL/K3s CRI, Kotlin Scheduler, OpenAPI 3.1.

**Spec:** [B 계약](../../api/image-preparation-b-contract.md), [OpenAPI](../../api/image-preparation.openapi.yaml).

## Global Constraints

- 계약 PR만으로 HTTP handler/agent/worker 지원을 선언하거나 feature flag를 켜지 않는다.
- 같은 노드에 전체 플랫폼 이미지가 있어야 ready다. 서로 다른 노드의 캐시 합집합 금지.
- 관측 시각과 원래 만료 시각은 조회/캐시/재전송으로 갱신하지 않는다.
- 이미지 준비는 선호이며 인증·정책·플랫폼·격리·자원 검증은 필수다.
- unknown query target 생략과 unknown preparation target의 422를 구분한다.
- 60s/300ms/10s/30s는 실측 전 제안값이며 신규 설정은 기본 비활성이다.

## Review Focus

- stale/future/부분 관측 또는 node UID/boot 변경이 positive 힌트를 되살리지 않는다.
- 등록되지 않은 보조 digest와 정책 차단을 캐시가 우회하지 않는다.
- 정확한 request replay와 변경된 요청 충돌을 이미지 집합 동일성과 혼동하지 않는다.
- 조회 장애가 Broker 실패나 생성 실패로 전파되지 않는다.
- 구버전 payload 재시도/reconcile에 새 trace 필드를 끼워 넣지 않는다.

## Task 1: 계약과 팀 연동 이슈

Files: `docs/api/image-preparation-b-contract.md`, `docs/api/image-preparation.openapi.yaml`,
`docs/api/examples/image-preparation/*`, `scripts/validate-image-preparation-contract.py`.

- [x] 사용자 조건을 반영한 B 역할·오류·관측·같은 노드·보안·배포 순서 명세를 작성한다.
- [x] 요청·응답과 retry child 작업의 OpenAPI/가상 예시를 작성한다.
- [x] schema validator와 오류 예시 검증을 실행하고 독립 리뷰의 중요 항목을 해결한다.
- [x] [Runtime #69](https://github.com/MSG-CTF/secure-provisioner/issues/69), [Scheduler #75](https://github.com/MSG-CTF/instance-scheduler/issues/75), [Broker #8](https://github.com/MSG-CTF/resource-broker/issues/8), [Backend #139](https://github.com/MSG-CTF/msg-backend/issues/139)를 연결한다.
- [x] [계약 PR #70](https://github.com/MSG-CTF/secure-provisioner/pull/70)을 draft로 제출했다. 실제 기능 완료로 처리하지 않는다.

## Task 2: Runtime 관측 모델과 batch query (별도 구현 PR)

Files to add: `internal/imageprep/model.go`, `identity.go`, `readiness.go`,
`internal/httpapi/image_readiness.go`, 관측용 `internal/runtimepg` migration.
Modify: `internal/httpapi/http.go`, `cmd/provisioner/main.go`의 명시적 서비스 주입.

Consumes: approved digest catalog, target Registry, persisted node image observations.
Produces: `POST /v1/image-readiness/query` and canonical image_set_id.

- [ ] RED: 같은 노드 전체 보유/노드 간 분산/architecture 불일치/승인 차단/정책 없음/unknown 생략/최초 미관측을 검사한다.
- [ ] RED: stale/future/캐시 재조회/node UID·boot 교체와 count·시각 불변식을 검사한다.
- [ ] GREEN: 실제 CRI 관측만 저장하고 query는 저장소와 현재 정책만 읽도록 구현한다.
- [ ] 권한 경계와 feature-disabled/구버전 동작을 검사하고 관련 Go suite를 실행한다.

## Task 3: 노드 pull 경로와 영속 준비 작업 (별도 구현 PR)

Files to add: `internal/imageprep/worker.go`, `store.go`, CRI collector/agent,
`internal/httpapi/image_preparations.go`, 작업용 `internal/runtimepg` migration.
Modify: worker lifecycle/config wiring only; 기존 create/delete concurrency를 잠식하지 않는다.

Consumes: immutable full containers and target scope.
Produces: prep create/status/retry APIs, durable node/image state, refreshed observations.

- [ ] RED: duplicate request/reordered canonical input/conflicting release·body/retry replay를 검사한다.
- [ ] RED: unknown/disabled/unauthorized target, no eligible nodes, 부분 실패, 재시작 복구, 시도 소진을 검사한다.
- [ ] GREEN: 원래 node UID 집합을 고정하고 실제 실행 CRI에 pull/inspect한다. 앱은 실행하지 않는다.
- [ ] RED/GREEN: 인증/승인/platform/missing manifest와 transient registry 오류의 재시도 차이를 검사한다.
- [ ] 전용 개발 노드에서 실제 cache 부재→pull→같은 노드 검증 및 토큰 비노출을 확인한다.

## Task 4: create 추적·platform·soft placement (별도 구현 PR)

Modify: `internal/httpapi/create.go`, `internal/provisioner` command/serialization,
`internal/k3s/resources.go`, durable operation payload와 request replay 경로.

- [ ] RED: 선택적 release_id/architecture 생략 호환성, null 거절, replay/conflict/reconcile/reset 보존을 검사한다.
- [ ] GREEN: 고정 metadata는 fingerprint에 보존하고 변동 ready 목록은 payload에서 제외한다.
- [ ] RED/GREEN: OS/architecture는 필수, 이미지 준비는 preferred affinity, 없으면 lazy pull이 되도록 검사한다.
- [ ] 새 Runtime을 먼저 배포하고 실제 Node/manifest platform 대조와 보안 거절을 확인한다.

## Task 5: Scheduler B 연동 (Scheduler 저장소 이슈)

Modify: RuntimeClient/HTTP adapter, 전용 readiness config/cache,
ResourceCandidateSelector, InstanceOperationService, 원본 스펙 보존 경로.

- [ ] RED/GREEN: eligible 후보의 target을 dedup해서 일괄 조회하고 같은 위험도 내 준비 우선 후 분산 순서를 유지한다.
- [ ] RED/GREEN: unknown/누락/timeout/401/403/404/5xx/만료는 기존 순서로 진행한다.
- [ ] RED/GREEN: cache hit로 observed_at/valid_until을 연장하지 않고 예약 전 candidate expiry를 재확인한다.
- [ ] RED/GREEN: 미확정 예약은 재생하지 않고 복구하며 release/architecture 원래 값을 replay/reset에 보존한다.
- [ ] Broker 예약·실제 생성 E2E, cold/warm 생성 지연, 조회 p95/p99, cache hit, pull 부하를 확인한 뒤 flag를 켠다.

## Task 6: Broker 역할 확인 (Broker 저장소 이슈)

- [ ] B안에서 후보/예약 API를 바꾸지 않는지 확인한다.
- [ ] runtime_ready·자원 observation freshness와 image_readiness를 결합하지 않는다.
- [ ] 후보 target_id와 Runtime Registry 매핑, 예약 응답이 target을 변경하는 경우를 검증한다.
- [ ] 이미지 준비 정보를 reservation의 필수 조건으로 추가하지 않는다.

## Task 7: Backend 준비 요청 및 작업 추적 ([Backend #139](https://github.com/MSG-CTF/msg-backend/issues/139))

- [ ] 승인 release 확정 후 비동기 준비 전달 기록과 안정적인 request_id를 보존한다.
- [ ] 전체 containers·architecture·release_id와 신뢰된 허용 target 범위를 Runtime에 직접 전달한다.
- [ ] operation_id/image_set_id와 부분 실패·child 재시도를 추적하며 준비 실패를 생성 gate로 쓰지 않는다.
- [ ] 기존 Scheduler 전달과 release 일관성, 중복 이벤트·응답 유실·재시작 복구·비밀값 비노출을 시험한다.
- [ ] Runtime 지원 후 비활성 flag로 배포하고 시범 대상에서 Backend→Scheduler→Runtime E2E를 확인한다.
