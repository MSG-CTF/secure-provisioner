# 비동기 런타임 Operation 및 상태 조회 설계

## 문서 정보

- 작성일: 2026-07-28
- 저장소: `MSG-CTF/secure-provisioner`
- 관련 이슈: #16, #25, #26
- 기반 작업: #17, #18, #24
- API 계약: `docs/api/runtime-operations.md`
- OpenAPI: `docs/api/secure-provisioner.openapi.yaml`

## 목표

Secure Provisioner의 생성과 삭제를 공통 비동기 Operation으로 처리한다.
호출자는 생성·삭제 요청을 접수한 뒤 `operation_id`로 처리 상태와 최종
결과를 조회한다.

별도의 런타임 상태 조회에서는 인스턴스 컨테이너의 실제 상태와
`target_id`가 가리키는 단일 노드 K3s의 건강 상태·배치 가능 자원을
제공한다.

이번 구현은 Secure Provisioner로 한정한다. Instance Scheduler
저장소는 현재 DTO를 확인하는 용도로만 사용하며 수정하지 않는다.

## 설계 원칙

1. 생성과 삭제는 같은 Operation 상태 모델을 사용한다.
2. 접수 성공은 처리 완료가 아니라 작업 저장 성공을 의미한다.
3. 같은 `request_id`와 같은 요청은 같은 Operation을 반환한다.
4. 같은 `request_id`를 다른 요청에 사용하면 거부한다.
5. Operation이 성공하기 전까지 최종 생성·삭제 결과를 반환하지 않는다.
6. 모든 K3s 접근은 저장된 `target_id`에 해당하는 Client 하나만 사용한다.
7. 삭제 전에는 Binding과 Namespace 소유권을 모두 검증한다.
8. 추가 배치 가능 공간은 순간 사용량이 아니라
   `allocatable - requested`를 기준으로 계산한다.
9. Metrics 조회 실패는 Core 상태 조회 실패로 확대하지 않는다.
10. 자격 증명과 내부 K3s 접속 정보는 응답과 로그에 노출하지 않는다.

## 범위

### 포함

- 비동기 생성·삭제 접수
- Operation 상태 조회
- `request_id` 기반 멱등 처리
- 제한된 동시성 Worker와 오류 재시도
- K3s 생성 Adapter 연결
- 실제 K3s Namespace 삭제
- Instance Runtime Binding 저장과 상태 전이
- 컨테이너 상태·자원 사용량 조회
- 단일 노드 K3s 건강 상태·자원 조회
- Markdown API 명세와 OpenAPI 3.1 문서
- Fake Kubernetes·Metrics Client 테스트
- Loopback 로컬 통합 테스트

### 제외

- `MSG-CTF/instance-scheduler` 코드 변경
- Scheduler 폴링 Worker와 DB 상태 전이
- Operation·Binding의 운영 DB 영속화
- AWS EC2·CloudWatch API 조회
- GCP Compute·Monitoring API 조회
- VM 전원 상태, 네트워크, 디스크 I/O
- 멀티노드 K3s target
- target 선택과 스케줄링 정책
- 로컬 대시보드 배포와 GitHub 업로드

## 구성요소

### HTTP API

HTTP 계층은 다음 책임만 가진다.

- 요청 JSON과 경로 변수 검증
- 생성·삭제 Operation 접수
- Operation 상태 조회
- 런타임 상태 조회
- 안정적인 HTTP 상태와 오류 Envelope 변환
- `Location`, `Retry-After` Header 제공

구체적인 경로와 요청·응답 Schema는 별도 API 명세서에서 관리한다.

### Runtime Service

Runtime Service는 HTTP와 K3s Adapter 사이의 조정자다.

- 생성·삭제 명령과 Binding 비교
- Operation Store 접수
- Binding 상태 전이
- Worker와 Adapter 조립
- K3s 오류를 안정 오류 코드로 분류
- Operation 최종 결과 생성

### Operation Store

Operation Store는 작업과 멱등 키를 관리한다.

```text
QUEUED -> RUNNING -> SUCCEEDED
                  -> RETRYING -> QUEUED
                  -> FAILED
```

동일한 `request_id`와 동일한 명령은 기존 Operation을 반환한다. 동일한
`request_id`와 다른 명령은 `REQUEST_ID_CONFLICT`로 거부한다.

현재 구현은 인메모리 Store다. 프로세스가 재시작되면 Operation이
복구된다고 보장하지 않는다. 운영 영속화는 별도 작업으로 남긴다.

### Runtime Binding Store

Binding은 인스턴스 실행 위치의 기준 정보다.

```text
instance_id
  -> team_id
  -> target_id
  -> namespace
  -> runtime_workload_id
  -> lifecycle state
```

생성 성공 후 Binding을 저장하며 상태 조회와 삭제는 Binding을 기준으로
실행 위치와 소유권을 검증한다.

현재 구현은 인메모리 Store다. Operation Store와 같은 영속성 제한을
갖는다.

### Cluster Registry

Cluster Registry는 전역 고유 `target_id`를 하나의 K3s Client에
매핑한다.

- AWS와 GCP에 VM이 여러 대여도 각 단일 노드 K3s는 다른 `target_id`를
  사용한다.
- 조회·생성·삭제는 target 목록을 순회하지 않는다.
- 등록되지 않은 target과 사용할 수 없는 target은 workload 처리 전에
  거부한다.

### K3s 생성 Adapter

생성 Adapter는 다음 순서로 작업한다.

1. `(target_id, instance_id)` workload lock을 획득한다.
2. Namespace, Deployment, Service와 Ingress를 생성·재조정한다.
3. 현재 Deployment revision의 Pod Ready를 확인한다.
4. 해당 Pod가 Endpoint에 연결됐는지 확인한다.
5. `runtime_workload_id`와 `service_url`을 반환한다.
6. 부분 실패 시 요청이 소유한 리소스를 rollback한다.

Worker는 Adapter 결과와 Binding 저장이 모두 끝난 뒤 CREATE Operation을
`SUCCEEDED`로 변경한다. Binding 저장이 실패하면 요청 소유 리소스를
정리하고 Operation을 실패 처리한다.

### K3s 삭제 Adapter

삭제 Adapter는 다음 순서로 작업한다.

1. 생성 Adapter와 같은 workload lock을 획득한다.
2. Binding의 `target_id`로 K3s Client 하나를 선택한다.
3. Namespace의 instance·team·managed-by Label을 검증한다.
4. Foreground 방식으로 Namespace 삭제를 요청한다.
5. 제한 시간 안에서 Namespace가 없어졌는지 확인한다.
6. 이미 없는 Namespace는 성공으로 처리한다.

삭제 성공 결과를 Operation에 저장한 뒤 Binding을 `DELETED`로
변경한다.

### Runtime Status Reader

상태 Reader는 Binding으로 target과 Namespace를 결정하고 다음 정보를
조회한다.

- Pod와 컨테이너 생명주기
- 컨테이너 requests·limits
- Pod Metrics의 컨테이너 CPU·메모리 사용량
- Node Ready·MemoryPressure·DiskPressure·PIDPressure
- Node capacity·allocatable
- Node에 배치된 미종료 Pod의 requested
- Node Metrics의 CPU·메모리 사용량

target에는 Node가 정확히 하나 있어야 한다. Node가 없거나 둘 이상이면
`TARGET_TOPOLOGY_INVALID`로 처리한다.

Pod 요청량은 Kubernetes 스케줄링 규칙에 따라 일반 컨테이너 requests,
init container 최댓값과 Pod overhead를 반영한다. 종료된 Pod는
제외한다.

```text
schedulable = max(allocatable - requested, 0)
```

CPU는 millicore, 메모리와 ephemeral storage는 MiB로 반환한다.

Metrics API를 사용할 수 없으면 사용량만 `null`로 처리한다. Core API의
상태, Condition, capacity, allocatable과 requested는 계속 반환한다.

## 처리 흐름

### 생성

```text
생성 요청
  -> CREATE Operation 저장
  -> 202 + operation_id
  -> Worker가 K3s 생성
  -> Pod Ready와 Endpoint 확인
  -> Binding 저장
  -> SUCCEEDED + workload_id + service_url
```

### 삭제

```text
삭제 요청
  -> Binding·요청 일치 확인
  -> DELETE Operation 저장
  -> 202 + operation_id
  -> Worker가 소유권 확인 후 Namespace 삭제
  -> Namespace 삭제 완료 확인
  -> Binding DELETED
  -> SUCCEEDED + SUCCESS
```

### 상태 조회

```text
instance_id
  -> Binding 조회
  -> target_id로 Client 하나 선택
  -> Namespace 소유권 확인
  -> 컨테이너·Node·Metrics 조회
  -> 런타임 상태 응답
```

## 동시성과 실패 처리

- 생성과 삭제는 같은 workload lock을 공유한다.
- 같은 workload를 동시에 생성·삭제하지 않는다.
- 재시도 가능한 일시 오류만 `RETRYING`으로 전환한다.
- 소유권 불일치와 요청 충돌은 재시도하지 않는다.
- 생성 부분 실패는 요청 소유 리소스를 rollback한다.
- 삭제 대상이 이미 없으면 성공으로 수렴한다.
- Client 연결이 끊겨도 같은 `request_id`는 새 Operation을 만들지 않는다.
- Metrics 오류는 Operation이나 Binding 상태를 변경하지 않는다.
- kubeconfig, API 주소와 내부 Client 오류는 외부에 노출하지 않는다.

## 테스트 전략

### Operation API

- 생성·삭제 접수가 202와 `QUEUED`를 반환한다.
- 같은 요청은 같은 Operation을 반환한다.
- 같은 멱등 키의 다른 요청은 거부한다.
- Worker 상태 전이와 재시도를 검증한다.
- 성공과 최종 실패 결과를 검증한다.

### 생성

- Pod와 Endpoint 준비 전에는 성공 처리하지 않는다.
- 생성 성공 결과와 Binding 저장을 검증한다.
- 부분 실패와 Binding 저장 실패 rollback을 검증한다.

### 삭제

- Binding과 요청 식별자 불일치를 거부한다.
- Namespace 소유권 불일치를 거부한다.
- 이미 없는 Namespace를 성공 처리한다.
- Foreground 삭제 완료 후에만 성공 처리한다.

### 상태 조회

- Binding의 target Client 하나만 사용한다.
- 컨테이너 상태와 사용량을 검증한다.
- 단일 Node의 Condition과 자원을 검증한다.
- requested와 schedulable 계산을 검증한다.
- Metrics를 사용할 수 없는 경우의 부분 응답을 검증한다.
- 단일 노드 조건 위반을 거부한다.

## 검증 명령

```text
go test -count=1 ./...
go vet ./...
go build ./...
git diff --check
```

로컬 HTTP 통합 테스트는 loopback에서 실행하며 실제 자격 증명을
사용하지 않는다. 생성·삭제를 접수하고 Operation을 최종 상태까지
폴링한다. 로컬 대시보드는 검증 편의를 위해 사용할 수 있지만 배포
산출물에는 포함하지 않는다.
