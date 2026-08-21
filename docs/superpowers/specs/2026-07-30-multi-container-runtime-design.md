# 팀별 다중 컨테이너 런타임 설계

## 문서 정보

- 작성일: 2026-07-30
- 저장소: `MSG-CTF/secure-provisioner`
- 기준 브랜치: `dev`
- 관련 이슈: #29
- 연관 이슈: #19, #24, #27, #30

## 목표

Scheduler가 선택한 `target_id`의 단일 노드 K3s에 팀별 런타임 인스턴스를
생성한다. 런타임 인스턴스 하나는 Namespace 하나를 소유하며, 문제 정의에 따라
컨테이너 하나 이상을 포함할 수 있다.

```text
VM / 단일 노드 K3s
├─ 문제 A / Team 1 Namespace
│  └─ web
├─ 문제 A / Team 2 Namespace
│  └─ web
└─ 문제 B / Team 1 Namespace
   ├─ web
   └─ db
```

같은 문제와 이미지를 여러 팀이 사용하더라도 `instance_id`마다 Namespace와
Kubernetes 리소스를 따로 만든다. 생성과 삭제는 기존 비동기 Operation 흐름을
그대로 사용한다.

## 범위

### 포함

- 생성 요청의 `workload.containers[]`
- 단일 컨테이너 기존 요청 호환
- 컨테이너별 Deployment와 ClusterIP Service
- 공개 컨테이너와 포트의 외부 Ingress 경로
- 다중 Endpoint 생성 결과
- 문제 전체 합산 리소스의 자동 분배
- 모든 컨테이너의 준비 상태 확인
- 생성 실패 시 Namespace 전체 롤백
- Namespace 단위 다중 컨테이너 삭제
- 다중 컨테이너 Command 멱등 비교와 방어적 복사
- Markdown, OpenAPI와 회귀 테스트 갱신
- 테스트 요청에서
  `ghcr.io/msg-ctf/challenges/oob-test/web:latest` 사용

### 제외

- Dockerfile 빌드와 GHCR Push
- `info.yaml` 파싱과 Challenge Catalog 구현
- Scheduler와 Broker 코드 변경
- VM 생성, 삭제와 target 선택
- GHCR 자격 증명 발급 및 배포
- NetworkPolicy, ResourceQuota, LimitRange와 RuntimeClass
- 컨테이너별 리소스 값을 출제자가 직접 지정하는 계약
- 운영 이미지의 digest 강제

## 생성 API

새 요청은 문제 전체 리소스 한도와 컨테이너 목록을 전달한다.

```json
{
  "request_id": "req-multi-01",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": "00000000-0000-4000-8000-000000000001",
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-dev"
  },
  "workload": {
    "containers": [
      {
        "name": "web",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
        "ports": [8080],
        "expose": true
      },
      {
        "name": "internal",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
        "ports": [8080],
        "expose": false
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

`containers[]`에는 최소 하나의 항목이 있어야 한다. 각 항목은 다음 규칙을
따른다.

- `name`: Namespace 안에서 고유한 Kubernetes DNS label
- `image`: 공백이 아닌 OCI 이미지 참조
- `ports`: 중복되지 않은 `1..65535` 포트가 하나 이상
- `expose`: `true`인 컨테이너만 외부 Endpoint 생성
- 문제 전체에서 `expose: true`인 컨테이너가 최소 하나 존재

이번 테스트에서는 `latest` tag를 허용한다. 운영 환경에서 digest를 강제하는
규칙은 이미지 공급 계약 이슈 #30에서 결정한다.

## 기존 단일 컨테이너 요청 호환

기존 `workload.image`와 `workload.container_port` 요청은 계속 허용한다.
Provisioner는 이를 다음 컨테이너 정의로 정규화한다.

```json
{
  "name": "challenge",
  "image": "기존 workload.image 값",
  "ports": [8080],
  "expose": true
}
```

위 예시의 `8080` 자리에는 기존 `workload.container_port` 값이 들어간다.

`containers[]`와 기존 `image` 또는 `container_port`를 동시에 보내면 의미가
모호하므로 `INVALID_REQUEST`로 거절한다. 정규화 이후 HTTP, Operation과 K3s
계층은 같은 다중 컨테이너 모델만 사용한다.

## 합산 리소스 분배

`resource_limits`는 VM 사양이 아니라 팀의 문제 런타임 인스턴스 전체에
허용되는 합산값이다. Scheduler는 이 합산값으로 target의 배치 가능 여부를
판단하고, Provisioner는 이를 컨테이너 수에 맞춰 자동 분배한다.

CPU millicore, 메모리 MiB와 임시 저장공간 MiB를 각각 다음처럼 계산한다.

```text
기본값 = 합산값 / 컨테이너 수
나머지 = 합산값 % 컨테이너 수
```

요청 순서 앞쪽의 `나머지`개 컨테이너에 1단위를 더 준다. 따라서 모든
컨테이너 값의 합은 요청받은 합산값과 정확히 같다.

예를 들어 CPU `501m`을 컨테이너 두 개에 분배하면 `251m`, `250m`이 된다.
각 리소스 합산값은 컨테이너 수 이상이어야 하므로 모든 컨테이너가 최소
`1m`, `1MiB`, `1MiB`를 받는다.

이 자동 분배는 1차 계약이다. 실제 문제 특성에 따른 컨테이너별 리소스 입력은
팀 회의 후 별도 이슈로 확장한다.

## Kubernetes 리소스 구조

런타임 인스턴스 하나에 다음 리소스를 만든다.

```text
Namespace: ctf-<instance-id>
├─ Deployment: web
├─ Service: web
├─ Deployment: internal
├─ Service: internal
└─ Ingress: challenge
```

- 모든 리소스에 `instance_id`, `team_id`, managed-by 소유권 label을 적용한다.
- 각 Deployment는 replica 하나와 컨테이너 하나를 가진다.
- 컨테이너별 label과 selector에는 컨테이너 이름을 포함한다.
- 각 Service는 같은 이름의 Deployment만 선택한다.
- 같은 Namespace에서는 `web`, `internal` 같은 Service 이름으로 통신한다.
- 외부 Ingress는 `expose: true`인 포트만 backend로 연결한다.
- `expose: false` Service는 ClusterIP 내부 통신에만 사용한다.

첫 번째 공개 Endpoint는 기존 주소를 유지한다.

```text
/instances/{instance_id}
```

두 번째 이후 공개 Endpoint는 충돌을 피하기 위해 다음 경로를 사용한다.

```text
/instances/{instance_id}/{container_name}/{port}
```

## 생성 결과

기존 Scheduler 호환을 위해 `service_url`을 유지하고, 모든 공개 주소는
`endpoints[]`로 함께 반환한다.

```json
{
  "runtime_workload_id": "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
  "service_url": "https://gateway.example/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "endpoints": [
    {
      "container_name": "web",
      "port": 8080,
      "service_url": "https://gateway.example/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001"
    }
  ]
}
```

`service_url`은 첫 번째 `endpoints[]` 항목과 같다. Operation이 `QUEUED`,
`RUNNING`, `RETRYING`인 동안에는 최종 결과를 반환하지 않는다.

## 준비 상태와 성공 조건

CREATE Operation은 다음 조건을 모두 만족한 뒤에만 `SUCCEEDED`가 된다.

1. 요청한 모든 Deployment의 현재 revision이 observed 상태다.
2. 각 Deployment에 Ready Pod가 하나 이상 있다.
3. 각 Service의 EndpointSlice가 해당 Ready Pod를 가리킨다.
4. 공개 Endpoint 정보가 모두 만들어졌다.
5. Runtime Binding 저장이 성공했다.

하나라도 준비되지 않으면 timeout 동안 기다린다. 적용 또는 준비 실패 시
해당 요청이 소유한 Namespace 전체를 롤백한다. 다른 팀 Namespace는 건드리지
않는다.

## 멱등성과 삭제

`containers[]`의 이름, 이미지, 포트 순서, 공개 여부와 합산 리소스를 모두
생성 명령 비교에 포함한다. Operation Store에 저장할 때 slice와 내부 slice를
방어적으로 복사해 호출자의 이후 변경이 멱등 비교를 바꾸지 못하게 한다.

삭제는 기존 Binding의 `target_id`, `instance_id`, `team_id`와
`runtime_workload_id`를 검증한 다음 Namespace 전체를 삭제한다. Namespace
안의 Deployment, Service와 Ingress는 함께 제거된다. 같은 문제를 실행하는
다른 팀 Namespace에는 영향을 주지 않는다.

## GHCR 이미지 사용

제공된 테스트 이미지는 현재 익명 Manifest 조회가 `401 Unauthorized`를
반환한다. 실제 K3s pull 검증 전 다음 중 하나가 준비돼야 한다.

- K3s 노드의 containerd에 GHCR `read:packages` 인증 설정
- 팀 Namespace 생성 시 사용할 `imagePullSecret` 공급 방식

자격 증명을 생성 API, Operation 결과 또는 로그에 넣지 않는다. Registry 인증
공급 방식은 #30에서 결정하며, 이 기능은 K3s 노드에 인증이 이미 준비됐다고
가정한다.

## 오류 처리

- 잘못된 컨테이너 이름, 중복 이름·포트, 빈 이미지, 잘못된 합산값:
  HTTP `INVALID_REQUEST`
- Worker가 유효하지 않은 정규화 Command를 받은 경우:
  `INVALID_CREATE_COMMAND`
- 일부 리소스 적용 실패: `RESOURCE_APPLY_FAILED` 후 Namespace rollback
- 준비 시간 초과: `WORKLOAD_NOT_READY` 후 Namespace rollback
- rollback 실패: `ROLLBACK_FAILED`
- 기존 리소스 소유권 불일치: `RESOURCE_OWNERSHIP_CONFLICT`
- Registry 인증 또는 image pull의 세부 오류 분류는 #27, #30에서 확정

## 테스트

### 단위 및 회귀 테스트

- 기존 단일 컨테이너 DTO 정규화
- 다중 컨테이너 DTO 변환과 검증
- 이름·포트·공개 컨테이너 검증
- 합산 리소스의 정확한 분배와 최소값 검증
- Command 방어적 복사와 멱등 비교
- 컨테이너별 Deployment와 Service selector
- 내부 컨테이너에 외부 Route가 없는지 검증
- 여러 공개 Endpoint 경로와 기존 `service_url` 호환
- 모든 Deployment와 Endpoint가 준비되기 전 성공하지 않는지 검증
- 일부 적용·준비 실패 시 Namespace 전체 rollback
- 다중 컨테이너 Namespace 삭제
- Team 1 삭제 후 Team 2 리소스 유지
- Markdown과 OpenAPI 예제 회귀 검사

### 로컬 또는 개발 K3s 검증

1. GHCR 인증이 설정된 target을 Registry에 등록한다.
2. 제공된 `web` 이미지를 공개 `web`과 비공개 `internal` 정의에 각각 사용해
   다중 컨테이너 생성 요청을 보낸다.
3. Operation을 `SUCCEEDED`까지 폴링한다.
4. Namespace 안에 Deployment와 Service가 각각 두 개 있는지 확인한다.
5. 외부 Endpoint가 `web`에만 생성됐는지 확인한다.
6. 삭제 Operation을 접수하고 Namespace 제거를 확인한다.

### 전체 검증 명령

```text
go test -count=1 ./...
go vet ./...
go build ./...
git diff --check
```

## 완료 기준

- 기존 단일 컨테이너 요청이 이전과 같은 결과로 성공한다.
- 다중 컨테이너 요청이 하나의 팀 Namespace로 생성된다.
- 합산 리소스가 컨테이너에 나뉘고 합계가 변하지 않는다.
- 공개 컨테이너만 외부 Endpoint를 가진다.
- 모든 컨테이너와 Service가 준비된 뒤 CREATE가 성공한다.
- 실패 시 요청 Namespace에 부분 리소스가 남지 않는다.
- 삭제 시 해당 팀 Namespace의 모든 리소스가 제거된다.
- 같은 문제의 다른 팀 Namespace는 유지된다.
- Scheduler와 Broker 저장소는 변경하지 않는다.
