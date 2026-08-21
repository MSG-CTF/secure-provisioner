# 단순화된 Web/Pwn 격리 API 설계

## 배경

현재 기능 브랜치의 생성 API는 `challenge_ref`, `isolation_ref`,
`workload_profile_ref`, `resource_profile_ref`, `outbound_mode`를 호출자가 각각
지정한다. 이 구조는 정책 합성을 명시적으로 보여 주지만, MVP의 Scheduler가 알아야
할 내부 정책 버전까지 외부 계약으로 노출한다.

MVP에서는 Scheduler가 문제 정의를 소유하고 이미지, 포트, 자원값을 전달한다.
Provisioner는 전달받은 실행 명세를 특정 K3s Target에 배치하면서 Web 또는 Pwn에
맞는 격리를 강제한다. 따라서 외부 API에는 문제 유형을 나타내는 단일 필드만 두고,
공통 정책과 세부 정책 버전은 Provisioner 내부에서 결정한다.

## 목표

- 외부 정책 선택을 필수 `isolation_profile` 하나로 단순화한다.
- `WEB`은 내부적으로 `STANDARD@v1 + WEB@v1`로 합성한다.
- `PWN`은 내부적으로 `STANDARD@v1 + PWN@v1`로 합성한다.
- 기존 다중 컨테이너, 다중 포트, 컨테이너 간 연결, Target 선택 구조를 유지한다.
- Scheduler가 보낸 수치형 자원 제한을 Provisioner가 그대로 검증하고 강제한다.
- 모든 워크로드 Pod의 public internet outbound를 차단한다.
- 기존 비동기 Operation, 재시도, 멱등성 계약은 유지한다.

## 범위 밖

- Challenge Catalog와 이미지 등록 API
- `challenge_id`를 이용한 서버 측 정책 조회 및 교차 검증
- 문제 참가자에게 Provisioner API를 직접 공개하는 인증 구조
- 인터넷 outbound 허용 모드
- 커널 문제 또는 완화된 보안 설정이 필요한 Pwn 문제
- 자동 image pre-pull 배포기
- 여러 K3s Target을 선택하는 Scheduler의 배치 알고리즘

## 외부 생성 계약

정식 MVP 계약은 `workload.containers[]`를 사용한다. JSON 필드명은 모두
snake_case다.

```json
{
  "request_id": "runtime-create-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": 18,
  "isolation_profile": "WEB",
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "containers": [
      {
        "name": "web",
        "image": "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ports": [8080],
        "expose": true,
        "run_as_user": 10001
      },
      {
        "name": "api",
        "image": "ghcr.io/msg-ctf/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ports": [9000],
        "expose": false,
        "run_as_user": 10001,
        "writable_paths": [
          {
            "path": "/tmp/api",
            "size_limit_mib": 64
          }
        ]
      }
    ],
    "internal_connections": [
      {
        "source_container": "web",
        "destination_container": "api",
        "protocol": "TCP",
        "port": 9000
      }
    ],
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

Pwn 요청은 같은 구조에서 `isolation_profile`만 `PWN`으로 바꾼다. Pwn 프로필의
추가 제약은 아래 검증 규칙에 따라 적용한다.

### 제거하는 외부 필드

다음 필드는 새 계약에서 제거한다.

- `challenge_ref`
- `isolation_ref`
- `workload_profile_ref`
- `resource_profile_ref`
- `workload.outbound_mode`

현재 API는 unknown field를 거부하므로 이 필드를 계속 보내는 호출은
`400 INVALID_REQUEST`가 된다. Scheduler와 Provisioner는 이 계약으로 함께
전환한다. 보안 정책을 묵시적으로 낮추지 않기 위해 이전 요청을 Web으로 자동
추정하는 호환 모드는 두지 않는다.

### 기존 단일 컨테이너 필드

기존 `workload.image`와 `workload.container_port`는 한 번의 마이그레이션 기간에는
호환 입력으로 유지한다. 이 입력도 `isolation_profile`은 반드시 보내야 한다.
Provisioner는 이를 이름이 `main`이고 외부 노출되는 컨테이너 하나로 정규화한다.
OpenAPI와 Scheduler의 정식 예시는 `containers[]`만 사용하며, 단일 필드는 deprecated로
표시한다. 후속 API 버전에서 제거한다.

## 필드 책임

### Scheduler 책임

- `request_id`, `instance_id`, `team_id` 생성
- Broker 또는 배치 결과에 따른 `target_id` 지정
- 문제 정의에 따른 `WEB` 또는 `PWN` 분류
- 실행할 각 컨테이너의 정확한 image reference와 digest 전달
- 컨테이너 포트와 외부 노출 여부 전달
- 필요한 컨테이너 간 연결 선언
- 워크로드 전체의 CPU, memory, ephemeral storage 합산 제한 전달

### Provisioner 책임

- 모든 입력의 구조와 기본 안전 조건 검증
- `isolation_profile`을 내부 정책 조합으로 해석
- Target capability와 정책의 호환성 검증
- Kubernetes 보안 리소스와 워크로드 리소스 생성
- 전달받은 자원값을 Pod requests/limits, ResourceQuota, LimitRange에 강제
- 생성 결과와 endpoint를 비동기 Operation으로 반환

## 검증 규칙

### 공통

- `isolation_profile`은 필수이며 정확히 `WEB` 또는 `PWN`이어야 한다.
- 누락되거나 알 수 없는 값은 `400 INVALID_REQUEST`다.
- `runtime_type`은 MVP에서 `KUBERNETES`만 허용한다.
- `target_id`는 등록되고 enabled이며 필요한 capability를 만족해야 한다.
- 컨테이너 이름은 중복될 수 없다.
- image는 비어 있을 수 없다. 운영 계약은 immutable digest reference를 권장한다.
- 포트는 유효 범위여야 하고 한 컨테이너 안에서 중복될 수 없다.
- `run_as_user`는 non-root 양수 UID여야 한다.
- 자원 제한 세 값은 모두 양수여야 한다.
- `internal_connections`는 선택 사항이다. 없으면 컨테이너 사이 통신을 자동으로
  허용하지 않는다.
- 선언된 연결의 source와 destination은 존재하는 컨테이너여야 하며, port는
  destination 컨테이너의 선언된 포트여야 한다.

### WEB

- `STANDARD@v1 + WEB@v1`로 합성한다.
- Target의 기본 runtime을 사용한다.
- 외부에 노출되는 컨테이너가 하나 이상 있어야 한다.
- Target이 지원하면 Ingress 또는 NodePort로 노출할 수 있다.
- endpoint protocol은 `HTTP`다.

### PWN

- `STANDARD@v1 + PWN@v1`로 합성한다.
- 모든 문제 Pod에 `runtimeClassName: gvisor`를 강제한다.
- Target의 exposure mode는 `NODE_PORT`여야 한다.
- 외부에 노출되는 컨테이너는 정확히 하나여야 한다.
- 노출 컨테이너가 공개하는 포트는 정확히 하나여야 한다.
- endpoint protocol은 `TCP`다.
- writable path는 `/tmp` 또는 `/tmp` 하위 경로만 허용한다.
- gVisor, NetworkPolicy, strict supplemental groups, Pod PID 제한 capability가
  검증되지 않은 Target에는 생성하지 않는다.

커널 기능, root 실행, 추가 capability 또는 writable root filesystem이 필요한 문제는
Pwn 프로필을 완화하지 않고 후속 전용 Target 범위로 분리한다.

## 내부 정책 해석

HTTP handler는 외부 값을 다음 정책 요청으로 정규화한다.

```text
WEB -> baseline STANDARD@v1 + workload WEB@v1 + outbound NONE
PWN -> baseline STANDARD@v1 + workload PWN@v1 + outbound NONE
```

`challenge_ref`와 `resource_profile_ref`는 내부 명세에서도 제거한다. 문제 식별은
Scheduler의 영역이고, 자원 제한은 요청의 수치값 자체가 실행 명세이기 때문이다.
내부 `ResolvedPolicy`에는 감사, spec hash, Kubernetes 렌더링에 필요한 다음 결정만
보존한다.

- baseline version
- workload profile version
- runtime class
- endpoint protocol과 exposure 제약
- 컨테이너 보안 요구 사항과 writable path
- internal connections
- 고정 outbound `NONE`
- 수치형 resource limits

Runtime binding에도 동일한 정규화 결과를 저장한다. 삭제는 `instance_id`로 binding을
조회하므로 Challenge Catalog 의존성이 생기지 않는다.

## 네트워크 정책

모든 Namespace는 ingress/egress default-deny로 시작한다.

- cluster DNS만 공통 egress로 허용한다.
- `internal_connections`에 선언된 source-to-destination TCP port만 허용한다.
- 외부 서비스가 노출 컨테이너의 선언된 port에 도달하는 ingress만 허용한다.
- public internet egress를 여는 API 필드는 제공하지 않는다.

`outbound_mode`를 API에서 없애도 정책이 빠지는 것이 아니다. Provisioner가
`NONE`을 항상 선택하기 때문에 caller가 완화할 수 없게 된다.

## 이미지와 pre-pull

pre-pull 여부와 관계없이 Kubernetes PodSpec에는 실행할 image identifier가 필요하다.
따라서 각 컨테이너의 `image`는 API에 남긴다. Provisioner는
`imagePullPolicy: IfNotPresent`를 명시한다.

- Target node에 같은 digest가 캐시돼 있으면 즉시 사용한다.
- 캐시가 없으면 kubelet/containerd가 lazy pull한다.
- 자동 pre-pull은 별도 운영 기능이며, 이 API 변경의 범위가 아니다.

Pod의 internet egress 차단은 node의 image pull을 막지 않는다. image pull은 워크로드
Pod가 아니라 node의 container runtime이 수행한다.

## 비동기 처리와 멱등성

기존 동작은 유지한다.

- 생성 요청은 `202 Accepted`, `Location`, `Retry-After`를 반환한다.
- Scheduler는 Operation을 polling한다.
- 성공하면 endpoint를 포함한 결과를 받고, 실패하면 `last_error_code`를 받는다.
- 같은 `request_id`와 같은 정규화 명세는 같은 Operation으로 취급한다.
- 같은 `request_id`에서 `isolation_profile`, 컨테이너, 포트, 연결, 자원값 또는
  Target이 다르면 멱등성 충돌로 거부한다.
- spec hash에는 외부 label뿐 아니라 해석된 baseline/profile/runtime/endpoint 결정도
  포함해 정책 변경을 감지한다.

## 신뢰 경계

MVP에서는 Scheduler가 신뢰된 내부 호출자이며 문제의 `WEB`/`PWN` 분류를 책임진다.
참가자가 Provisioner API를 직접 호출할 수 없어야 한다. Provisioner만으로는 Pwn
문제가 잘못 `WEB`으로 표시됐는지 판별할 수 없다.

이 제한은 의도적으로 남긴 MVP 위험이다. Challenge Catalog 계약이 정해지면
Scheduler가 전달한 문제 ID를 기준으로 서버 측 profile과 image digest를 조회하거나
교차 검증하는 단계를 추가한다. 그 전까지는 Scheduler와 Provisioner 사이의 인증 및
네트워크 접근 제한을 운영 전제 조건으로 둔다.

## 오류 분류

- JSON 형식, 필수 필드, enum, 포트, 연결, writable path, Pwn 노출 제약 위반:
  `400 INVALID_REQUEST`
- 존재하지 않거나 disabled인 Target, 필요한 capability 부족, Pwn의 gVisor/NodePort
  미지원: 기존 Target/capability 오류 코드
- 같은 `request_id`에 다른 정규화 명세: 기존 멱등성 충돌 코드
- Kubernetes 일시 장애: 기존 재시도 가능 오류 분류와 worker backoff 적용

오류 응답에는 kubeconfig, 인증 정보, registry credential 또는 내부 endpoint를
노출하지 않는다.

## 테스트 전략

### API 계약

- WEB/PWN 요청의 snake_case decode와 command 변환
- `isolation_profile` 누락, unknown value, 잘못된 대소문자 거부
- 제거된 ref와 `outbound_mode`를 unknown field로 거부
- `containers[]` 정식 경로와 단일 컨테이너 deprecated 경로 검증
- `internal_connections` 생략 시 deny-by-default 유지
- 기존 비동기 Operation 응답 형태 유지

### Resolver

- WEB이 `STANDARD@v1 + WEB@v1 + NONE`으로 해석됨
- PWN이 `STANDARD@v1 + PWN@v1 + NONE`으로 해석됨
- Scheduler가 보낸 양수 자원값을 별도 named profile 비교 없이 보존함
- WEB/PWN별 노출, runtime, writable path 제약 검증

### Kubernetes adapter

- 두 프로필 모두 공통 SecurityContext, quota, limits, NetworkPolicy를 적용함
- PWN의 모든 Pod에 gVisor를 적용함
- WEB은 Target 기본 runtime을 사용함
- `imagePullPolicy: IfNotPresent`가 모든 컨테이너에 적용됨
- DNS와 명시적 internal connection 외의 egress가 허용되지 않음
- fake client 전체 생성 및 중간 실패 rollback 검증

### 회귀

- Operation 멱등성, copy, retry, checkpoint 테스트
- runtime binding 저장/조회/삭제 테스트
- `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`

## 전환 순서

1. Provisioner 코드, OpenAPI, 운영 문서를 이 계약으로 함께 수정한다.
2. Scheduler 생성 DTO와 호출 코드를 `isolation_profile` 및 `containers[]` 계약으로
   수정한다.
3. 두 컴포넌트를 같은 운영 전환 구간에 배포한다. 새 Provisioner는 profile 없는
   요청을 fail-closed로 거부한다.
4. 기존 단일 컨테이너 필드 사용량이 없음을 확인한 뒤 후속 API 버전에서 제거한다.
5. 실제 K3s Target에서 WEB/PWN smoke test와 gVisor runtime test를 수행한다.

## 완료 기준

- 외부 생성 계약에서 정책 선택 필드는 `isolation_profile` 하나뿐이다.
- 모든 요청은 명시적으로 WEB 또는 PWN을 선택하며 누락 시 거부된다.
- WEB/PWN은 각각 정해진 내부 정책 조합으로만 해석된다.
- caller는 outbound나 공통 보안 기준을 완화할 수 없다.
- 다중 컨테이너, 다중 포트, 명시적 내부 연결, Scheduler 지정 자원값이 유지된다.
- 기존 비동기 Operation과 멱등성 동작이 회귀하지 않는다.
- 문서와 OpenAPI가 실제 handler 동작과 일치한다.
