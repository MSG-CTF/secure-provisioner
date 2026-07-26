# 멀티 클라우드 런타임 조회·삭제 및 테스트 대시보드 설계

## 배경

현재 `feat/18-k3s-create-adapter`는 Scheduler가 전달한 `target_id`를 Cluster Registry에서 해석하고, 해당 K3s에 Namespace, Deployment, Service, Ingress를 생성한 뒤 Ready Pod와 Endpoint를 확인한다. 그러나 다음 기능은 아직 없다.

- 인스턴스가 어느 `target_id`와 Namespace에 생성됐는지 조회하는 위치 저장소
- 실행 중인 Pod와 컨테이너의 현재 상태 및 CPU·메모리 사용량 조회
- 저장된 위치를 이용하는 실제 K3s 삭제 Adapter
- 내부 서비스와 로컬 테스트에서 사용할 상태 API
- AWS 개발용 K3s에서 조회와 삭제를 확인할 테스트 대시보드

현재 `DeleteWorkloadCommand`에는 `TargetID`와 `RuntimeWorkloadID`가 있지만, 요청값과 생성 결과를 대조할 영속 위치 정보가 없다. K3s Operation Executor도 CREATE만 지원한다.

## 목표

1. 정상 조회와 삭제 경로에서 모든 클라우드나 클러스터를 순회하지 않는다.
2. `instance_id`로 위치를 한 번 조회하고 저장된 `target_id`로 정확한 K3s Client를 선택한다.
3. 내부 서비스가 컨테이너 상태, requests/limits 및 현재 CPU·메모리 사용량을 조회할 수 있다.
4. 동일한 상태 API를 로컬 테스트 대시보드가 사용한다.
5. 삭제는 멱등하며 다른 인스턴스나 다른 팀의 리소스를 삭제하지 않는다.
6. AWS CLI로 확인한 서울 리전의 개발용 `k3s-lab` EC2를 이용해 생성→조회→삭제를 재현한다.

## 제외 범위

- 과거 사용량 그래프와 장기 보관. 이는 Prometheus 관측성 범위다.
- 운영용 관리자 UI와 사용자용 공개 UI.
- 전체 클러스터를 상시 스캔하는 Reconciler.
- PostgreSQL Adapter 자체 구현. 이번 기능은 `BindingStore` 인터페이스와 동시성 안전 인메모리 구현을 제공하며, 운영 배포 전에 기존 PostgreSQL Store 이슈에서 영속 Adapter를 구현한다.
- Scheduler가 선택한 target을 Provisioner가 재선정하는 기능.
- 브라우저나 외부 요청에서 kubeconfig, Kubernetes API URL, AWS credential을 입력받는 기능.

## 접근 방식

### 채택: 중앙 위치 인덱스와 target 기반 라우팅

생성 성공 결과를 `InstanceRuntimeBinding`으로 기록한다. 조회와 삭제는 `instance_id`로 Binding을 읽고 `target_id`에 해당하는 Cluster Client 하나만 사용한다.

이 구조는 인스턴스 수가 증가해도 정상 요청당 DB 조회 한 번과 K3s 한 곳의 API 호출만 필요하다. Kubernetes Client와 Metrics Client는 인스턴스별이 아니라 target별로 생성해 공유한다.

### 기각: `runtime_workload_id` 문자열만 파싱

프로세스가 단순해 보이지만 식별자 형식 변경에 취약하고, team 소유권과 생성 세대를 안정적으로 검증하기 어렵다. `runtime_workload_id`는 검증값으로 보존하되 위치의 유일한 진실로 사용하지 않는다.

### 기각: 요청마다 모든 클러스터 검색

클러스터 수에 비례해 지연과 실패 가능성이 커진다. 정상 경로에는 사용하지 않고, 향후 별도 Reconcile 또는 운영 복구 도구에서만 제한적으로 사용한다.

## 컴포넌트

### `InstanceRuntimeBinding`

```go
type InstanceRuntimeBinding struct {
    InstanceID        string
    TeamID            int64
    TargetID          string
    Namespace         string
    RuntimeWorkloadID string
    State             BindingState
    CreatedAt         time.Time
    UpdatedAt         time.Time
    DeletedAt         *time.Time
}
```

`InstanceID`가 기본 키다. 운영 PostgreSQL Adapter에는 `(target_id, state)`와 `(state, updated_at)` 인덱스를 둔다.

### `BindingStore`

```go
type BindingStore interface {
    SaveCreated(InstanceRuntimeBinding) error
    Get(instanceID string) (InstanceRuntimeBinding, error)
    MarkDeleting(instanceID string) (InstanceRuntimeBinding, error)
    MarkDeleted(instanceID string, deletedAt time.Time) error
}
```

동일 `instance_id`에 다른 target, team 또는 runtime workload가 기록되면 충돌로 거부한다. 로컬 서버와 단위 테스트는 mutex 기반 인메모리 구현을 사용한다. 프로세스 재시작 시 매핑이 사라지는 한계는 대시보드와 문서에 명시하며, 운영 사용은 PostgreSQL Adapter를 전제로 한다.

### Cluster Registry

한 target은 다음 두 Client를 공유한다.

```go
type Cluster struct {
    Config        ClusterConfig
    KubeClient    kubernetes.Interface
    MetricsClient metricsclient.Interface
}
```

생성 조회와 유지보수 조회를 분리한다.

- `LookupForCreate`: placement가 비활성인 target을 거부한다.
- `LookupForMaintenance`: 신규 placement가 비활성이어도 기존 인스턴스 조회와 삭제를 허용한다.

target 설정이나 credential이 완전히 제거된 경우에는 조회·삭제를 성공 처리하지 않고 안정 오류로 보류한다.

### `RuntimeStatusReader`

Binding의 target과 Namespace를 사용해 다음 정보를 읽는다.

- Deployment generation과 available replica
- 소유권 label이 일치하는 Pod 목록
- Pod phase와 conditions
- 일반, init 및 필요 시 ephemeral container status
- 컨테이너별 state, ready, restart count, reason, exit code, 시작·종료 시각
- Pod Spec의 requests와 limits
- Metrics API의 컨테이너별 CPU와 메모리 working set
- EndpointSlice readiness

Metrics API가 없거나 아직 표본이 없으면 전체 조회를 실패시키지 않는다. 상태와 requests/limits는 반환하고 `usage`를 `null`, `metrics_available`을 `false`로 표시한다.

### `DeleteAdapter`

삭제는 Binding의 target과 Namespace를 사용한다.

1. CREATE와 같은 `(target_id, instance_id)` workload lock을 획득한다.
2. Namespace를 조회한다.
3. Namespace가 없으면 멱등 성공을 반환한다.
4. Namespace의 managed-by, instance-id 및 team-id 소유권을 Binding과 대조한다.
5. 일치할 때만 Namespace 삭제를 요청한다.
6. 제한 시간 안에 Namespace가 `NotFound`가 되는지 확인한다.
7. 성공 후 Binding을 `DELETED`로 전환한다.

API timeout과 일시 연결 실패는 재시도 가능한 오류다. 소유권 불일치와 target 불일치는 안정 오류이며 어떤 리소스도 삭제하지 않는다.

### 내부 상태 API

```http
GET /internal/v1/instances/{instance_id}/runtime-status
```

응답 예:

```json
{
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "target_id": "aws-k3s-lab",
  "runtime_workload_id": "aws-k3s-lab/ctf-018f.../challenge",
  "phase": "READY",
  "endpoint_ready": true,
  "metrics_available": true,
  "observed_at": "2026-07-26T12:34:56Z",
  "containers": [
    {
      "pod_name": "challenge-7c9f...",
      "name": "challenge",
      "state": "RUNNING",
      "ready": true,
      "restart_count": 0,
      "reason": "",
      "requests": {
        "cpu_millicores": 100,
        "memory_mib": 128,
        "ephemeral_storage_mib": 256
      },
      "limits": {
        "cpu_millicores": 100,
        "memory_mib": 128,
        "ephemeral_storage_mib": 256
      },
      "usage": {
        "cpu_millicores": 12,
        "memory_mib": 34
      }
    }
  ]
}
```

`target_id`는 응답에 표시할 수 있지만 조회 요청의 라우팅 입력으로 받지 않는다.

### 삭제 API

```http
DELETE /internal/v1/instances/{instance_id}
Content-Type: application/json
```

기존 Scheduler 삭제 DTO의 request ID, team ID, runtime type, target ID, runtime workload ID 및 reason을 유지한다. 서버는 Binding을 진실의 원천으로 사용하고 요청의 target/team/runtime workload를 일치 검증한다. 삭제는 Operation으로 등록하고 `202 Accepted`를 반환한다. Worker가 `DeleteAdapter`를 실행하고 Operation 조회로 완료 상태를 확인한다.

동일 request ID와 동일 payload는 같은 Operation을 반환한다. Namespace가 이미 없거나 이전 삭제가 완료된 인스턴스는 최종적으로 성공에 수렴한다.

### 테스트 대시보드

대시보드는 Provisioner 프로세스가 정적 HTML로 제공하며 테스트 환경에서만 활성화한다.

- 환경변수: `PROVISIONER_ENABLE_TEST_DASHBOARD=true`
- 기본 bind: loopback
- 입력: instance ID
- 표시: target, workload ID, phase, endpoint readiness, 관측 시각
- 컨테이너 표: Pod, 이름, 상태, Ready, 재시작, reason, requests/limits, 현재 사용량
- 동작: 새로고침, 선택적 자동 새로고침, 삭제
- 삭제: 현재 binding을 다시 표시하고 사용자 확인 후 내부 삭제 API 호출
- 삭제 진행: Operation 상태를 polling해 완료 또는 오류 표시
- Metrics가 없으면 사용량 영역만 “수집 불가” 표시

대시보드는 K3s API에 직접 접근하지 않으며 kubeconfig, Kubernetes API 주소, AWS 정보와 credential을 브라우저에 전달하지 않는다. 운영 기본값은 비활성이다.

## 오류 계약

| 상황 | HTTP/안정 코드 | 처리 |
| --- | --- | --- |
| Binding 없음 | `404 INSTANCE_NOT_FOUND` | 클러스터 조회 안 함 |
| 요청 target/team/workload 불일치 | `409 INSTANCE_BINDING_MISMATCH` | fail-closed |
| Registry target 없음 | `503 TARGET_NOT_FOUND` | 조회·삭제 보류 |
| K3s 연결 timeout | `503 TARGET_TEMPORARILY_UNAVAILABLE` | Operation 재시도 |
| Namespace 소유권 불일치 | `409 RUNTIME_OWNERSHIP_MISMATCH` | 삭제 금지 |
| Namespace 이미 없음 | 성공 | 멱등 삭제 |
| Metrics API 없음 | `200` + usage `null` | 상태는 반환 |
| Pod가 아직 없음 | `200` + 빈 containers | phase는 `PROVISIONING` 또는 `TERMINATING` |

오류와 로그에는 kubeconfig 내용, API URL userinfo, credential, Pod 환경변수와 Secret 값을 넣지 않는다.

## 많은 인스턴스 처리

- Binding 조회는 `instance_id` 기본 키를 사용한다.
- Client는 target별로 캐시해 공유한다.
- CREATE와 DELETE는 instance별 lock으로 경쟁을 막는다.
- target별 semaphore로 동시 Kubernetes 변경 요청 수를 제한한다.
- 대시보드 목록에서 모든 K3s를 fan-out 조회하지 않는다.
- 목록/요약은 Binding Store의 마지막 상태를 사용하고, 상세 화면만 target 한 곳에 실시간 조회한다.
- 향후 Reconciler는 target별 watcher 또는 제한된 batch로 상태를 갱신한다.

## 테스트 전략

### 단위 테스트

- 서로 다른 target의 KubeClient와 MetricsClient가 섞이지 않는다.
- Binding 충돌, 멱등 저장 및 상태 전이가 안전하다.
- Pod ContainerStatus와 PodMetrics가 컨테이너 이름으로 정확히 합쳐진다.
- Waiting, Running, Terminated, CrashLoopBackOff, OOMKilled를 안정 응답으로 변환한다.
- Metrics 없음은 부분 성공이다.
- 삭제는 저장된 target만 호출한다.
- Namespace NotFound는 성공이다.
- 소유권 불일치는 삭제 요청을 보내지 않는다.
- CREATE/DELETE 경쟁은 동일 workload lock으로 직렬화된다.
- HTTP unknown field, 크기 제한, 오류 정보 비노출을 유지한다.

### 로컬 Fake Client 통합 테스트

1. AWS/GCP/NCP 세 target을 각각 다른 fake client로 등록한다.
2. AWS target에 생성 Binding과 Pod/PodMetrics를 준비한다.
3. 상태 API가 AWS client만 조회하는지 확인한다.
4. 삭제 Operation을 실행하고 AWS Namespace만 삭제되는지 확인한다.
5. 같은 삭제를 다시 실행해 멱등 성공을 확인한다.
6. 대시보드가 상태 API와 Operation API를 통해 결과를 표시하는지 확인한다.

### AWS 개발용 K3s 통합 테스트

AWS CLI는 `ap-northeast-2`에서 `Name=k3s-lab`인 실행 중인 EC2를 식별하고 상태를 확인하는 데만 사용한다. 실제 K3s 조작은 해당 target의 임시 kubeconfig 또는 보호된 SSH tunnel을 통한 Kubernetes Client로 수행한다.

환경변수 기반 opt-in 테스트 순서:

1. AWS 호출 계정과 `k3s-lab` EC2가 running인지 읽기 전용으로 확인한다.
2. 무작위 UUID로 고유 Namespace를 생성한다.
3. 기존 생성 Adapter로 테스트 workload를 생성하고 Ready를 확인한다.
4. Binding을 기록하고 runtime status를 조회한다.
5. 컨테이너 state, ready, requests/limits를 검증한다.
6. Metrics API가 있으면 CPU·메모리 값을 검증하고, 없으면 부분 성공을 검증한다.
7. 삭제 Adapter를 실행한다.
8. Namespace가 `NotFound`가 되는지 확인한다.
9. 동일 삭제를 반복해 멱등 성공을 확인한다.
10. 테스트 실패 시에도 `t.Cleanup`이 테스트 Namespace만 제거한다.

통합 테스트는 기존 workload나 Namespace를 수정하지 않는다. 임시 kubeconfig, SSH tunnel, AWS credential과 공개 주소를 저장소나 로그에 남기지 않는다.

### 검증 명령

```text
go test -count=1 ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./...
git diff --check
```

AWS 실환경 테스트는 명시적인 환경변수가 모두 있을 때만 실행하고 일반 CI에서는 건너뛴다.

## 이슈 구성

- 기존 #16을 확장해 Binding 기반 멱등 K3s 삭제, target 라우팅, 소유권 검증 및 실환경 삭제 테스트를 포함한다.
- 별도 신규 이슈로 컨테이너 runtime status, Metrics API, 내부 상태 API 및 테스트 대시보드를 추적한다.
- 두 이슈는 #18 K3s 생성 Adapter에 의존하고, 운영 배포는 #5 PostgreSQL Store에 의존한다.

## 완료 기준

- 조회와 삭제가 전체 클러스터를 검색하지 않고 저장된 target 하나만 사용한다.
- 내부 상태 API가 컨테이너 상태와 설정 리소스를 반환한다.
- Metrics Server 유무에 따라 사용량 전체 또는 부분 응답을 안정적으로 반환한다.
- 삭제가 멱등하며 소유권 불일치 리소스를 보호한다.
- 테스트 대시보드에서 조회와 삭제 진행 상태를 확인할 수 있다.
- fake multi-target 테스트와 AWS `k3s-lab` 생성→조회→삭제 통합 테스트가 통과한다.
- 테스트 종료 후 생성한 Namespace와 임시 접근 자원이 남지 않는다.
