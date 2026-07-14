# Secure Provisioner Local MVP

`mvp/`는 운영 코드와 분리한 로컬 실습용 Go 모듈이다. Provisioner의 HTTP API, 비동기 Worker, TTL 정리, 멱등 처리와 간단한 `ctf-mock`을 한 컴퓨터에서 검증한다.

## 구성

```text
Fake Broker (:18080)
  -> MVP Provisioner (:8080)
       -> Fake Scheduler (:18080)
       -> Fake Challenge Catalog (:18080)
       -> In-memory Fake K3s Adapter
       -> Fake challenge endpoint (:18080)
       -> Fake Broker / SLA callbacks (:18080)
```

`ctf-mock`은 K3s API를 흉내 내지 않는다. Kubernetes 호출은 Provisioner 내부의 Fake K3s Adapter가 담당하고, 이후 같은 경계를 `client-go` Adapter로 교체한다.

## 현재 구현 범위

- `POST /internal/v1/instances`: 비동기 생성 접수
- `GET /internal/v1/instances/{instanceId}`: 참가자에게 노출 가능한 상태 조회
- `DELETE /internal/v1/instances/{instanceId}`: 멱등 삭제 접수
- `GET /internal/v1/operations/{operationId}`: 작업 상태 조회
- `teamId + challengeId` 활성 인스턴스 유일성
- 최대 3회 제한 재시도와 간단한 backoff
- 기본 최대 TTL 6시간 및 만료 인스턴스 자동 삭제
- Fake Scheduler 예약 검증과 해제
- Fake Challenge Catalog의 digest·port·profile 조회
- Fake endpoint 확인 후에만 `READY` 전환
- 생성 실패 시 Fake K3s 리소스 롤백
- ResourceQuota, LimitRange, default-deny NetworkPolicy 및 restricted securityContext 표현

## 로컬 실행

새 PowerShell 두 개를 연다.

첫 번째 PowerShell:

```powershell
cd C:\Users\RYZEN1\Desktop\msg_ctf\secure-provisioner\mvp
go run ./cmd/ctf-mock
```

두 번째 PowerShell:

```powershell
cd C:\Users\RYZEN1\Desktop\msg_ctf\secure-provisioner\mvp
go run ./cmd/provisioner
```

두 서버 모두 로컬 주소에만 바인딩된다.

## 생성 실습

세 번째 PowerShell에서 Fake Broker로 요청한다.

```powershell
$createBody = @{
  requestId     = "req-demo-001"
  instanceId    = "inst-demo-001"
  teamId        = "team-demo"
  challengeId   = "pwn-101"
  clusterId     = "k3s-local"
  reservationId = "rsv-local"
  createdBy     = "local-user"
  expiresAt     = (Get-Date).ToUniversalTime().AddHours(2).ToString("o")
} | ConvertTo-Json

$accepted = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:18080/mock/v1/broker/instances `
  -ContentType "application/json" `
  -Body $createBody

$accepted
```

잠시 후 상태와 Fake K3s에 적용된 보안 설정을 조회한다.

```powershell
Invoke-RestMethod http://127.0.0.1:18080/mock/v1/broker/instances/inst-demo-001
Invoke-RestMethod http://127.0.0.1:18080/mock/v1/broker/debug/resources/inst-demo-001
Invoke-RestMethod http://127.0.0.1:18080/mock/v1/events
```

사용 가능한 샘플 문제는 `pwn-101`, `web-101`, `kernel-101`이다. `kernel-101`은 MVP Fake K3s에 없는 `kata-qemu`를 요구하므로 의도적으로 생성에 실패한다.

## 삭제 실습

```powershell
$deleteBody = @{ requestId = "req-delete-001" } | ConvertTo-Json

Invoke-RestMethod `
  -Method Delete `
  -Uri http://127.0.0.1:18080/mock/v1/broker/instances/inst-demo-001 `
  -ContentType "application/json" `
  -Body $deleteBody
```

다른 `requestId`로 같은 삭제를 반복해도 `TERMINATED`가 반환된다.

## 장애 시나리오

다음 요청은 문제 endpoint를 강제로 비정상으로 만든다.

```powershell
$scenario = @{ endpointUnhealthy = $true } | ConvertTo-Json
Invoke-RestMethod `
  -Method Put `
  -Uri http://127.0.0.1:18080/mock/v1/scenario `
  -ContentType "application/json" `
  -Body $scenario
```

지원 필드는 다음과 같다.

- `schedulerUnavailable`
- `catalogUnavailable`
- `endpointUnhealthy`
- `brokerCallbackUnavailable`
- `slaUnavailable`
- `releaseUnavailable`

정상 상태로 되돌리려면 빈 객체를 전달한다.

```powershell
Invoke-RestMethod `
  -Method Put `
  -Uri http://127.0.0.1:18080/mock/v1/scenario `
  -ContentType "application/json" `
  -Body "{}"
```

## 테스트

```powershell
.\scripts\test.ps1
```

테스트는 동시 중복 생성, 같은 팀의 다른 문제 생성, 보안 베이스라인, 반복 삭제, endpoint 실패 롤백과 TTL 자동 삭제를 검증한다.

## MVP 한계

- Operation Store는 PostgreSQL이 아니라 인메모리이므로 프로세스 재시작 시 상태가 사라진다.
- Fake K3s Adapter는 Kubernetes 오브젝트를 표현할 뿐 실제 격리를 강제하지 않는다.
- endpoint와 callback은 로컬 mock이다.
- 내부 서비스 인증, Prometheus, 실제 Route, `client-go`, Admission 정책은 아직 없다.
- 실제 NetworkPolicy, seccomp, Pod Security 및 RuntimeClass 효과는 개발용 K3s에서 별도로 검증해야 한다.

다음 구현 단계는 인메모리 Store를 PostgreSQL로 교체한 뒤 `client-go` 기반 개발 K3s Adapter를 추가하는 것이다.
