# 문제 인스턴스 공통 런타임 격리 설계

## 1. 문서 목적

이 문서는 Secure Provisioner가 CTF 문제 인스턴스를 생성할 때 공통으로 강제할 런타임 격리 정책, 문제별 허용사항의 전달 계약, K3s 적용 순서와 실제 차단 효과를 검증하는 방법을 정의한다.

이 설계는 다음 GitHub 이슈의 책임 경계를 연결한다.

- `#19`: 생성 API 격리 프로필 계약과 Provisioner의 Kubernetes 리소스 생성
- `#11`: 실제 K3s에서 공격 시나리오로 격리 효과 검증
- `#13`: Admission 단계의 최종 강제와 고위험 RuntimeClass
- `#24`: target capability와 K3s 운영 부트스트랩
- `#29`: 팀별 다중 컨테이너 인스턴스 생성·삭제
- `#31`: 문제별 자원 배분과 부하 테스트

`#19` 구현은 다중 컨테이너별 Deployment와 Service가 존재해야 하므로 `#29`를 선행 구현으로 사용한다. 현재 `feat/19-runtime-isolation` 브랜치는 `feat/29-multi-container-runtime`을 기준으로 분기한다. `#29`가 `dev`에 병합되면 `#19`를 최신 `dev` 위로 재배치한다.

## 2. 현재 상태

현재 코드는 다음 기능을 제공한다.

- `instance_id`마다 `ctf-<instance-id>` Namespace 생성
- `team_id`와 `instance_id` 소유권 label 적용
- 컨테이너별 Deployment와 ClusterIP Service 생성
- 공개 컨테이너에 대한 Ingress 생성
- CPU, 메모리와 ephemeral storage requests/limits 적용
- 생성 실패 시 소유권을 검증한 Namespace 롤백
- 삭제 시 Binding과 Namespace 소유권을 검증한 후 해당 Namespace만 삭제

현재 다음 보호 계층은 구현되어 있지 않다.

- NetworkPolicy
- ResourceQuota와 LimitRange
- 전용 ServiceAccount와 token 자동 마운트 차단
- Pod/Container SecurityContext
- seccomp, capabilities 제거와 read-only root filesystem
- 문제별 isolation/resource profile 참조와 검증
- target security capability 검증
- 실제 K3s 공격 시나리오 테스트

Namespace는 리소스 이름과 삭제 범위를 분리하지만, Namespace만으로 Pod 네트워크를 차단하지 않는다. 따라서 현재 상태를 팀·인스턴스 간 보안 격리가 완료된 상태로 간주하지 않는다.

## 3. 보안 목표

### 3.1 보호 대상

문제 인스턴스가 침해되더라도 다음 대상에 영향을 주지 못해야 한다.

- 다른 팀의 모든 인스턴스
- 같은 팀의 다른 인스턴스
- 같은 인스턴스 안에서 허용되지 않은 다른 컨테이너
- Kubernetes API와 ServiceAccount credential
- 클라우드 metadata endpoint
- K3s 노드의 관리 포트, 프로세스, IPC와 파일시스템
- target의 다른 문제 인스턴스가 사용할 CPU, 메모리, PID와 저장공간

### 3.2 신뢰 경계

- 문제 제작자의 `info.yaml`은 기능 요구사항을 표현하는 요청이다.
- CI와 Challenge Catalog가 승인한 resolved challenge config가 배포 권한의 근거다.
- Scheduler는 승인된 참조를 전달하고 target을 선택하지만 정책을 임의로 완화하지 못한다.
- Secure Provisioner는 신뢰된 profile을 Kubernetes 리소스로 변환하고 강제한다.
- Admission과 target 방화벽은 Provisioner 오류가 있어도 우회를 막는 최종 계층이다.
- 문제 컨테이너, 이미지 안의 프로세스와 사용자 입력은 신뢰하지 않는다.

### 3.3 비목표

- Provisioner에서 Dockerfile을 빌드하거나 이미지를 Registry에 Push하지 않는다.
- Scheduler가 선택한 target을 Provisioner가 다른 target으로 변경하지 않는다.
- 표준 NetworkPolicy만으로 노드 로컬 트래픽 차단을 보장한다고 주장하지 않는다.
- shared K3s에서 privileged 또는 host namespace가 필요한 문제를 실행하지 않는다.
- 팀당 활성 인스턴스 2개 제한은 Scheduler slot 정책으로 처리하며 이 설계에서 구현하지 않는다.

## 4. 핵심 결정

### 4.1 인스턴스가 물리적 격리 단위다

한 팀이 동시에 두 인스턴스를 실행하더라도 Namespace를 공유하지 않는다.

```text
Team 1
├─ Instance A → Namespace ctf-aaa
└─ Instance B → Namespace ctf-bbb

Team 2
└─ Instance C → Namespace ctf-ccc
```

소유권은 `team_id`, 실행 격리 경계는 `instance_id`, 적용 정책은 `challenge_ref`와 profile digest로 구분한다.

### 4.2 공통 baseline은 해제할 수 없다

모든 shared K3s 문제에 다음 정책을 적용한다.

- 인스턴스별 Namespace
- ingress와 egress default-deny
- DNS, 외부 진입점과 승인된 내부 연결만 allow
- Kubernetes API와 metadata 접근 차단
- 전용 ServiceAccount와 token 자동 마운트 차단
- `privileged: false`
- `allowPrivilegeEscalation: false`
- `hostNetwork: false`, `hostPID: false`, `hostIPC: false`
- `hostPath` 사용 금지
- 모든 Linux capability 제거
- seccomp `RuntimeDefault`
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- CPU, 메모리와 ephemeral storage requests/limits
- ResourceQuota와 LimitRange
- target이 지원하는 경우 PID 제한

문제별 profile은 baseline을 끄는 기능이 아니다. profile은 내부 연결, 외부 egress, non-root UID와 쓰기 가능한 임시 경로처럼 필요한 허용 범위를 좁게 추가한다.

### 4.3 호환성은 baseline 완화가 아니라 실행 요구사항 정규화로 해결한다

기존 이미지가 파일 쓰기를 요구하면 root filesystem을 writable로 바꾸지 않는다. 승인된 경로에 크기 제한이 있는 `emptyDir`를 마운트한다.

```yaml
writable_paths:
  - path: /tmp
    size_mib: 64
  - path: /app/data
    size_mib: 128
```

이미지가 root로만 실행되면 Dockerfile을 non-root로 수정하거나 승인된 `run_as_user`를 지정한다. `run_as_user`는 `1` 이상이어야 하며 `runAsNonRoot`를 해제하지 않는다.

setuid, 추가 capability, privileged 또는 host namespace가 필요한 Pwn 문제는 shared K3s baseline을 완화하지 않는다. 해당 문제는 `DEDICATED_TARGET` 또는 검증된 sandbox RuntimeClass 대상으로 분류하고 `#13`에서 처리한다.

## 5. 생성 계약

### 5.1 불변 참조

생성 요청에 다음 참조를 추가한다.

```json
{
  "challenge_ref": {
    "challenge_id": "web-chall1",
    "version": "2026.08.1",
    "digest": "sha256:5c58b4fefc6f1c586209e4a1f77f52f9dd72597d45e80768730c042f1b9c6751"
  },
  "isolation_ref": {
    "name": "STANDARD",
    "version": "v1",
    "digest": "sha256:a0b353b244cb1ed120a802cca6b668909efe9841e3bf26f30fc534569fbeec65"
  },
  "resource_profile_ref": {
    "name": "SMALL",
    "version": "v1",
    "digest": "sha256:00ce378dbf4598e244eb356d6d79a6d2b98b9a1770196878c538a40dd5590b45"
  }
}
```

- `challenge_ref`는 승인된 resolved challenge config를 식별한다.
- `isolation_ref`는 적용할 isolation profile의 정확한 내용을 식별한다.
- `resource_profile_ref`는 숫자 자원값과 Namespace object quota의 출처를 식별한다.
- digest는 `sha256:<64 lowercase hex>` 형식만 허용한다.
- name/version은 운영자가 읽기 위한 식별자이고 digest가 최종 동일성 기준이다.

### 5.2 컨테이너 실행 요구사항

문제 제작자가 Kubernetes SecurityContext를 직접 전달하지 않도록 허용 입력을 기능 요구사항으로 제한한다.

```json
{
  "name": "web",
  "image": "registry.example/msg-ctf/web-chall1@sha256:7e115e6f20f80998377fd5bb92fd0f72d5303a939e2e9646b0c6acc22db440f1",
  "ports": [8080],
  "expose": true,
  "run_as_user": 10001,
  "writable_paths": [
    {"path": "/tmp", "size_mib": 64}
  ]
}
```

검증 규칙은 다음과 같다.

- 운영 profile에서는 `image@sha256:...`만 허용한다.
- `run_as_user`는 `1` 이상이고 Linux UID 범위 안이어야 한다.
- writable path는 절대 경로여야 하며 `/`, `/proc`, `/sys`, `/dev`, `/var/run/secrets`, ServiceAccount 경로를 허용하지 않는다.
- writable path끼리 중복되거나 상위·하위 경로가 겹치면 거부한다.
- 각 writable path는 `emptyDir.sizeLimit`이 필수다.
- `hostPath`, raw volume, raw SecurityContext, RBAC, RuntimeClass와 ServiceAccount 이름은 요청 필드로 제공하지 않는다.

### 5.3 내부 연결

다중 컨테이너 문제는 필요한 연결을 명시한다.

```json
{
  "internal_connections": [
    {
      "source_container": "web",
      "destination_container": "db",
      "protocol": "TCP",
      "port": 5432
    }
  ]
}
```

- source와 destination은 같은 요청의 `containers[].name`이어야 한다.
- destination port는 해당 컨테이너의 `ports[]`에 선언돼 있어야 한다.
- protocol은 초기 구현에서 `TCP` 또는 `UDP`만 허용한다.
- 빈 목록은 컨테이너 간 연결을 모두 차단한다.
- 동일 Namespace라는 이유만으로 전체 통신을 허용하지 않는다.

### 5.4 외부 egress

기본값은 `NONE`이다. 외부 연결이 필요한 문제만 승인된 profile에서 `PUBLIC_INTERNET`을 사용한다.

- `NONE`: DNS와 승인된 내부 연결 외의 egress를 허용하지 않는다.
- `PUBLIC_INTERNET`: 공인 IP 대역만 허용하고 private, loopback, link-local, CGNAT, metadata, cluster, service, pod와 node CIDR을 제외한다.
- 임의 CIDR이나 FQDN을 문제 제작자가 raw NetworkPolicy로 전달하지 않는다.
- 특정 목적지만 필요한 경우 플랫폼·보안 팀이 profile assignment에 승인된 CIDR/port allowlist를 기록한다.

NetworkPolicy는 L3/L4 정책이므로 DNS 질의 이름이나 HTTP 경로를 제한하지 못한다. DNS 터널링과 L7 egress 제어가 필요한 고위험 문제는 shared K3s의 `STANDARD` 대상이 아니라 전용 egress proxy 또는 `DEDICATED_TARGET` 대상으로 분류한다.

### 5.5 마이그레이션

현재 Scheduler가 보내는 숫자형 `resource_limits`는 profile 전환 기간 동안 유지한다.

1. Provisioner에 trusted static profile registry와 `STANDARD@v1`, resource profile을 추가한다.
2. 생성 요청에 profile ref를 추가하고 resolved 숫자값과 digest 일치를 검증한다.
3. 개발 환경에서만 명시적인 legacy 호환 설정으로 profile ref 누락을 허용한다.
4. 운영 환경에서는 profile ref가 없으면 fail-closed로 거부한다.
5. Scheduler와 Catalog 매핑이 완료되면 임의 숫자만 전달하는 계약을 제거한다.

legacy 호환 설정은 공통 baseline을 끄지 않는다. 누락된 참조를 기본 profile로 보완할 뿐이다.

## 6. Profile Resolver와 target capability

### 6.1 Profile Resolver

`PolicyResolver`는 다음 책임만 가진다.

```go
type PolicyResolver interface {
    ResolveIsolation(context.Context, ChallengeRef, PolicyRef) (IsolationPolicy, error)
    ResolveResources(context.Context, ChallengeRef, PolicyRef) (ResourcePolicy, error)
}
```

- name/version/digest로 신뢰된 profile을 조회한다.
- challenge와 profile assignment가 승인된 조합인지 확인한다.
- digest가 canonical profile 내용과 일치하는지 확인한다.
- API DTO나 Kubernetes 타입을 직접 반환하지 않는다.

초기 구현은 Provisioner 배포에 read-only로 주입되는 versioned YAML registry를 사용한다. profile YAML을 canonical JSON으로 변환해 SHA-256을 계산한다. 이후 Catalog 연동으로 교체하더라도 `PolicyResolver` 인터페이스와 Domain 모델은 유지한다.

### 6.2 target capability

`ClusterConfig`는 최소한 다음 capability를 표현한다.

- NetworkPolicy controller 종류와 검증 상태
- DNS Namespace와 Pod selector
- Ingress controller Namespace와 Pod selector
- Pod, Service와 node CIDR
- IPv4/IPv6 사용 여부
- Pod Security Admission 지원과 정책 버전
- PID 제한 지원 여부
- 사용 가능한 RuntimeClass 목록
- Pod에서 노드·metadata로 향하는 트래픽을 차단하는 host boundary 지원 여부
- capability를 마지막으로 검증한 시각

Scheduler가 profile과 호환되는 target을 선택하고, Provisioner가 생성 직전에 다시 검증한다. capability가 누락됐거나 검증 유효기간이 지난 target에서는 workload를 실행하지 않는다.

NetworkPolicy 리소스가 API에 등록되어 있다는 사실만으로 실제 enforcement를 증명할 수 없다. target capability는 `#11`의 probe와 target 부트스트랩 검증이 성공한 경우에만 활성화한다.

## 7. Kubernetes 리소스 설계

### 7.1 ResourceSet 확장

`ResourceSet`에 다음 필드를 추가한다.

```go
type ResourceSet struct {
    Namespace       *corev1.Namespace
    ServiceAccount  *corev1.ServiceAccount
    ResourceQuota   *corev1.ResourceQuota
    LimitRange      *corev1.LimitRange
    NetworkPolicies []*networkingv1.NetworkPolicy
    Deployments     []*appsv1.Deployment
    Services        []*corev1.Service
    Ingress         *networkingv1.Ingress
}
```

모든 보호 리소스에는 기존 소유권 label과 policy digest annotation을 적용한다. 이름과 생성 순서는 결정적이어야 하며 같은 요청의 재시도에서 동일한 manifest가 생성돼야 한다.

### 7.2 Namespace

Namespace 이름은 기존 `ctf-<instance-id without hyphen>` 형식을 유지한다.

필수 label과 annotation은 다음 정보를 포함한다.

- managed-by
- `instance_id`
- `team_id`
- `challenge_id`
- isolation profile digest
- resource profile digest

Pod Security Admission을 사용할 target에서는 `#13`이 정한 고정 버전의 `restricted` enforce/audit/warn label을 추가한다. target이 해당 Admission capability를 제공하지 않으면 profile 요구사항 불일치로 생성 요청을 거부한다.

### 7.3 ServiceAccount

인스턴스마다 `challenge-runtime` ServiceAccount를 생성한다.

```yaml
automountServiceAccountToken: false
```

Pod에도 `serviceAccountName: challenge-runtime`과 `automountServiceAccountToken: false`를 함께 지정한다. ServiceAccount와 Pod 양쪽에 적용해 mutation이나 향후 기본값 변경에 대한 방어 계층을 둔다. RoleBinding과 Kubernetes API 권한은 생성하지 않는다.

### 7.4 SecurityContext

Pod에 다음 값을 적용한다.

```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
```

각 컨테이너에 다음 값을 적용한다.

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop: ["ALL"]
```

`runAsUser`는 승인된 resolved requirement에서 가져온다. init container와 sidecar를 도입할 경우 동일한 baseline을 적용한다. 요청 모델에 volume과 host namespace 설정이 없으므로 `hostPath`는 생성 경로 자체가 존재하지 않는다. `#13`의 Admission은 우회 제출된 hostPath와 위험 설정을 별도로 거부한다.

### 7.5 writable path

승인된 writable path마다 독립된 `emptyDir`와 `sizeLimit`을 생성한다.

- volume 이름은 container 이름과 정렬된 path index로 결정한다.
- 같은 volume을 서로 다른 컨테이너가 자동 공유하지 않는다.
- 메모리 기반 `emptyDir`는 resource profile이 명시한 경우에만 사용한다.
- disk 기반 `emptyDir` 사용량은 container ephemeral-storage limit와 Namespace quota 안에 포함되도록 산정한다.
- writable path 합계가 container 또는 Namespace ephemeral storage 상한을 넘으면 생성 전에 거부한다.

### 7.6 ResourceQuota

ResourceQuota는 Namespace 전체 합계에 다음 hard limit을 둔다.

- `requests.cpu`, `limits.cpu`
- `requests.memory`, `limits.memory`
- `requests.ephemeral-storage`, `limits.ephemeral-storage`
- `pods`
- `services`
- `services.loadbalancers: 0`
- `services.nodeports: 0`
- `count/deployments.apps`
- `count/replicasets.apps`
- `count/secrets`
- `count/configmaps`
- `count/persistentvolumeclaims: 0`

Pod, Service, Deployment와 ReplicaSet 상한은 컨테이너 수와 운영 여유분을 resource profile이 계산한 값으로 고정한다. 문제 제작자가 object count를 직접 지정하지 않는다.

ephemeral-storage quota가 실제 적용되려면 각 컨테이너의 requests/limits가 모두 설정되어야 한다. 기존 코드의 명시적 ephemeral-storage 설정을 유지한다.

### 7.7 LimitRange

LimitRange는 container 단위 최소·최대값과 기본 requests/limits를 설정한다.

- Provisioner가 만든 모든 컨테이너에는 명시적 requests/limits를 넣는다.
- LimitRange 기본값은 mutation 우회 또는 향후 보조 컨테이너 누락에 대한 방어 계층이다.
- maximum은 resource profile의 단일 컨테이너 상한을 넘지 않는다.
- request-to-limit 비율은 resource profile에서 고정하며 Scheduler 임의값으로 결정하지 않는다.

### 7.8 NetworkPolicy

각 Namespace에 최소한 다음 정책을 생성한다.

1. `default-deny-all`: 모든 Pod의 ingress와 egress 차단
2. `allow-dns`: 모든 문제 Pod에서 승인된 CoreDNS Pod의 TCP/UDP 53으로만 egress 허용
3. `allow-public-ingress-<container>`: Ingress controller에서 expose된 container/port로만 ingress 허용
4. `allow-internal-<source>`: 선언된 source container에서 destination container/port로 egress 허용
5. `allow-internal-<destination>`: 선언된 source container에서 destination container/port로 ingress 허용
6. `allow-public-egress`: profile이 승인한 경우에만 공인 CIDR과 port로 egress 허용

source와 destination은 `msgctf.io/container-name` Pod label로 선택한다. Namespace가 인스턴스마다 다르므로 podSelector만 사용한 내부 연결은 같은 인스턴스 안으로 제한된다.

외부 Ingress peer는 ClusterConfig의 Namespace와 Pod selector를 모두 만족해야 한다. K3s 기본값은 `kube-system`과 Traefik label을 사용하지만 설치별 차이가 있으므로 코드에 숨겨진 상수로 가정하지 않는다.

### 7.9 표준 NetworkPolicy의 한계

Kubernetes NetworkPolicy 명세상 Pod가 실행되는 노드와의 트래픽은 항상 허용될 수 있으며, resident node에서 들어오는 트래픽도 표준 정책만으로 차단할 수 없다. `hostNetwork` Pod의 selector 처리도 CNI 구현에 따라 달라진다.

따라서 다음을 별도 target 보안 계층으로 강제한다.

- Pod CIDR에서 node management IP와 K3s API `6443` 접근 차단
- Pod CIDR에서 AWS/GCP/NCP metadata endpoint 접근 차단
- kubelet, container runtime, SSH와 운영 agent 포트 접근 차단
- 업무상 필요한 node-local DNS 또는 프록시만 명시적으로 허용
- host firewall 또는 해당 기능을 제공하는 CNI/eBPF 정책 적용

이 계층은 Provisioner의 namespaced NetworkPolicy만으로 구현할 수 없으므로 별도 보안 이슈로 추적하고 `#24` target bootstrap과 연결한다. 해당 계층과 probe가 준비되지 않은 target은 `STANDARD@v1` production capability를 갖지 못한다.

## 8. 생성 순서와 fail-closed

생성 순서는 다음과 같다.

1. HTTP 스키마와 immutable ref 형식 검증
2. profile resolver로 challenge/profile assignment와 digest 검증
3. container, writable path, 내부 연결과 자원 합계 검증
4. target capability 재검증
5. ResourceSet 전체 생성
6. 기존 리소스의 소유권과 이름 충돌을 전체 preflight
7. Namespace 생성 또는 소유권 확인
8. ServiceAccount, ResourceQuota와 LimitRange 적용
9. default-deny와 모든 allow NetworkPolicy 적용
10. 보호 리소스를 API에서 다시 읽어 spec hash와 소유권 확인
11. Deployment 생성
12. Service와 Ingress 생성
13. 모든 Deployment, Pod와 EndpointSlice 준비 확인
14. Runtime Binding 저장 후 Operation 성공

보호 리소스가 생성·검증되기 전에는 Deployment를 생성하지 않는다. NetworkPolicy API에는 dataplane 적용 완료 상태가 없으므로 policy를 Pod보다 먼저 생성하고, 실제 enforcement 여부는 target capability와 `#11` probe 결과로 보완한다.

다음 실패는 모두 workload 미실행 또는 소유 Namespace 전체 롤백으로 처리한다.

- profile을 찾을 수 없음
- challenge/profile assignment 불일치
- digest 불일치
- target capability 부족 또는 검증 만료
- 보호 리소스 ownership conflict
- 보호 리소스 생성/갱신/재조회 실패
- Deployment 또는 Endpoint 준비 실패

이미 다른 소유자의 Namespace나 보호 리소스가 있으면 삭제하지 않고 `RESOURCE_OWNERSHIP_CONFLICT`로 중단한다.

## 9. 멱등성과 Binding

같은 `request_id`와 같은 resolved policy는 기존 Operation 결과를 반환한다. 같은 `request_id`에 profile digest, internal connection, image digest 또는 writable path가 달라지면 충돌로 거부한다.

Runtime Binding에는 다음 정보를 저장한다.

- `instance_id`, `team_id`, `target_id`, Namespace
- challenge ID/version/digest
- isolation profile name/version/digest
- resource profile name/version/digest
- 최종 resolved CPU, memory, ephemeral storage와 object quota
- container별 image digest, runAsUser와 writable path
- internal connections와 outbound mode
- target capability 검증 결과와 검증 시각

삭제는 Binding과 Namespace label을 대조한 후 해당 instance Namespace만 제거한다. 같은 팀 또는 다른 팀의 다른 Namespace는 조회·수정·삭제하지 않는다.

## 10. 코드 경계

구현 파일의 책임은 다음처럼 나눈다.

- `internal/httpapi/create.go`: 새 API DTO와 형식 검증, Domain 변환
- `internal/provisioner/create.go`: profile ref, container requirement와 internal connection Domain 타입
- `internal/isolation/profile.go`: isolation/resource policy Domain 모델
- `internal/isolation/resolver.go`: `PolicyResolver` 인터페이스
- `internal/isolation/static_registry.go`: versioned YAML profile 로드, canonical digest와 assignment 검증
- `internal/k3s/resources.go`: 기존 workload 리소스 조립 유지
- `internal/k3s/security_resources.go`: ServiceAccount, Quota, LimitRange와 SecurityContext 조립
- `internal/k3s/network_policies.go`: deny-first, DNS, Ingress, internal과 public egress 정책 조립
- `internal/k3s/adapter.go`: preflight, 보호 리소스 우선 적용, 검증과 rollback 순서
- `internal/k3s/cluster.go`: target security capability와 네트워크 selector 설정
- `internal/runtimebinding/binding.go`: 적용된 immutable ref와 resolved policy 기록
- `config/isolation-profiles/`: trusted versioned profile과 assignment fixture

Kubernetes 타입 생성은 K3s 계층에 한정한다. HTTP DTO, Domain policy와 Kubernetes manifest를 하나의 구조체로 공유하지 않는다.

## 11. 테스트 전략

### 11.1 DTO와 Domain 테스트

`internal/httpapi/create_test.go`와 `internal/provisioner/create_test.go`에서 다음을 검증한다.

- 정상 immutable ref 파싱
- digest 형식 오류 거부
- unknown profile과 assignment 불일치 거부
- container 이름/port와 internal connection 참조 오류 거부
- root UID 거부
- 금지 writable path, 중복/중첩 path와 크기 초과 거부
- raw security 설정 필드가 계약에 존재하지 않음
- 명령 복사와 멱등 비교에 slice/map alias가 없음

### 11.2 Profile Resolver 테스트

`internal/isolation/static_registry_test.go`에서 다음을 검증한다.

- 동일 canonical profile은 동일 digest 생성
- YAML key 순서와 공백은 digest에 영향을 주지 않음
- 실제 정책값 변경은 digest를 변경함
- challenge/profile assignment가 없으면 fail-closed
- name/version이 같아도 digest가 다르면 거부
- duplicate profile과 duplicate assignment는 시작 실패

### 11.3 Manifest 단위 테스트

`internal/k3s/resources_test.go`, `security_resources_test.go`와 `network_policies_test.go`에서 실제 Kubernetes 객체를 검사한다.

- Namespace와 모든 보호 리소스의 ownership/policy digest
- ServiceAccount와 Pod token automount false
- host namespace false
- privileged false, privilege escalation false
- capability `ALL` drop
- seccomp RuntimeDefault
- runAsNonRoot와 approved UID
- readOnlyRootFilesystem와 sized emptyDir
- requests/limits와 Quota 총량 일치
- Pod/Service/Deployment/ReplicaSet/PVC object quota
- default-deny ingress/egress
- DNS TCP/UDP 53 외 목적지 없음
- 공개 container/port에만 Traefik ingress 허용
- 선언된 container 연결만 양방향 policy 조건 충족
- public egress에서 private, link-local, metadata, cluster와 node CIDR 제외
- spec hash가 보안 정책 변경을 추적함

### 11.4 Adapter 테스트

`internal/k3s/adapter_test.go`의 fake client reactor로 다음 순서를 검증한다.

- Deployment create보다 보호 리소스 create가 먼저 실행됨
- 보호 리소스 preflight ownership conflict 시 mutation 없음
- Quota, NetworkPolicy 또는 ServiceAccount 적용 실패 시 Deployment 미생성
- 보호 리소스 read-back 불일치 시 Namespace rollback
- rollback은 소유 Namespace에만 실행됨
- 같은 요청 재시도는 리소스를 중복 생성하지 않음
- 다른 team/instance 리소스는 변경하지 않음

fake client 테스트는 manifest와 제어 흐름만 증명하며 네트워크 차단 효과를 증명하지 않는다.

### 11.5 실제 K3s isolation suite

`internal/k3s/isolation_integration_test.go`는 개발 전용 K3s에서 실행한다. 테스트용 kubeconfig는 운영 credential을 사용하지 않는다. 테스트 fixture image는 CI가 `K3S_ISOLATION_PROBE_IMAGE`에 immutable digest로 주입하며 shell, HTTP server, DNS 조회, TCP 연결, UID/capability/seccomp/rootfs 검사 기능만 포함한다.

테스트는 매 실행마다 고유 instance ID와 Namespace를 사용하고 `t.Cleanup`에서 Namespace 삭제 후 `NotFound`까지 확인한다.

네트워크 시나리오는 다음과 같다.

- 다른 팀 instance Service/Pod IP 연결 실패
- 같은 팀의 다른 instance Service/Pod IP 연결 실패
- 같은 instance에서 선언되지 않은 container 연결 실패
- 같은 instance에서 선언된 container/port 연결 성공
- expose되지 않은 container에 대한 Traefik 경로 접근 실패
- expose된 container/port에 대한 Traefik 경로 접근 성공
- DNS 조회 성공
- Kubernetes API Service IP 연결 실패
- metadata IP 연결 실패
- profile이 `NONE`이면 공인 인터넷 연결 실패
- profile이 `PUBLIC_INTERNET`이면 승인된 공인 목적지는 성공하고 private/node/metadata 목적지는 실패

프로세스·파일시스템 시나리오는 다음과 같다.

- ServiceAccount token 경로가 없음
- UID가 0이 아님
- effective capability 집합이 비어 있음
- `NoNewPrivs`가 활성화됨
- seccomp가 필터 모드임
- root filesystem 쓰기 실패
- 승인된 emptyDir path 쓰기 성공
- host PID/IPC/network 공유가 없음

자원 시나리오는 다음과 같다.

- Quota를 넘는 추가 Pod/Service/Deployment 생성이 Forbidden
- memory limit 초과 프로세스가 해당 container 안에서 종료되고 다른 instance는 유지
- ephemeral storage/emptyDir 상한 초과가 해당 Pod에만 영향을 줌
- PID limit capability가 있는 target에서 fork 폭주가 제한됨
- 테스트 종료 후 Namespace와 namespaced object가 남지 않음

표준 NetworkPolicy가 resident node 트래픽을 보장하지 못하므로 node IP, kubelet, SSH, container runtime과 K3s API 실제 차단은 target host-boundary suite에서도 별도로 실행한다. 이 테스트가 실패한 target은 production capability를 잃는다.

### 11.6 Admission 테스트

`#13`에서는 Provisioner를 우회해 다음 Pod를 직접 제출하고 API Admission에서 거부되는지 검증한다.

- privileged
- allowPrivilegeEscalation
- hostNetwork, hostPID, hostIPC
- hostPath
- capability 추가
- seccomp Unconfined
- root user
- 허용되지 않은 RuntimeClass

정상 Provisioner manifest는 같은 Admission 환경에서 실행돼야 한다.

### 11.7 실행 명령

단위·제어 흐름 테스트:

```powershell
go test ./internal/httpapi ./internal/provisioner ./internal/isolation ./internal/k3s
go test ./...
go vet ./...
go build ./...
```

실제 K3s 테스트는 기존 integration 환경변수에 isolation probe image와 target capability 설정을 추가한 뒤 별도 이름으로 실행한다.

```powershell
go test ./internal/k3s -run '^TestK3sIsolation' -count=1 -v
```

환경변수가 없으면 로컬 기본 테스트에서는 명시적으로 skip하고, 보안 검증 CI job에서는 skip을 실패로 취급한다.

## 12. 이슈별 처리 위치

| 격리 항목 | 구현·검증 위치 |
|---|---|
| 인스턴스별 Namespace와 삭제 범위 | `#29`, 소유권 강화는 `#19` |
| 다른 팀·같은 팀 다른 인스턴스 네트워크 차단 | `#19` NetworkPolicy, `#11` 실제 K3s 검증 |
| 같은 인스턴스 내부 최소 통신 | `#19` internal connections, `#11` allow/deny 검증 |
| ServiceAccount token 차단 | `#19` manifest, `#11` 파일 부재 검증 |
| privileged·권한 상승·host namespace·hostPath 차단 | `#19` manifest, `#13` Admission 최종 거부, `#11` 런타임 검증 |
| capabilities·seccomp·non-root·read-only | `#19` manifest, `#11` 런타임 검증, `#13` 우회 거부 |
| CPU·메모리·ephemeral storage·Pod/object 수 | `#19` Quota/LimitRange, `#31` 값 산정, `#11` 실제 제한 검증 |
| PID 제한 | `#19` target capability, `#11` fork 제한 검증, target kubelet/runtime 설정 |
| Kubernetes API·metadata 차단 | `#19` default-deny, `#11` Service/metadata probe, target host-boundary 보안 이슈 |
| resident node·관리 포트 차단 | target host-boundary 보안 이슈와 `#24` bootstrap; 표준 NetworkPolicy만으로 완료 처리하지 않음 |
| 고위험 sandbox/전용 target | `#13` |
| 팀당 동시 인스턴스 2개 | Scheduler slot 이슈; Kubernetes 격리와 별도 |

## 13. 배포 단계와 완료 기준

### 단계 1: Provisioner baseline

- 모든 요청에 ServiceAccount, SecurityContext, Quota, LimitRange와 deny-first NetworkPolicy 생성
- internal connections와 writable path 계약 추가
- 보호 리소스 우선 적용과 rollback 구현
- 단위, manifest와 adapter 테스트 통과

### 단계 2: 불변 profile 계약

- challenge/isolation/resource ref 추가
- trusted static registry와 digest 검증
- Binding과 감사 정보 확장
- 운영 환경에서 profile 누락 fail-closed

### 단계 3: 실제 K3s 검증

- `#11` isolation suite 자동화
- NetworkPolicy, runtime context와 resource limit의 실제 효과 검증
- 보안 CI job에서 skip 금지

### 단계 4: target과 Admission 최종 강제

- resident node와 metadata host-boundary 적용 및 검증
- `#24` capability/bootstrap에 검증 결과 연결
- `#13` Admission과 고위험 RuntimeClass 적용

production 완료 조건은 다음과 같다.

- 단계 1~4가 모두 완료됨
- shared K3s target의 NetworkPolicy와 host-boundary probe가 성공함
- 승인되지 않은 profile과 capability 부족 target이 fail-closed로 거부됨
- 다른 팀 및 같은 팀 다른 인스턴스 접근 차단 E2E가 성공함
- ServiceAccount token, privileged/host 접근과 자원 고갈 테스트가 성공함
- 테스트 실패 후 Namespace와 workload가 남지 않음

## 14. 공식 근거

- Kubernetes NetworkPolicy: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- K3s Network Policy controller와 CoreDNS/Traefik: <https://docs.k3s.io/networking/networking-services>
- K3s CIS hardening의 NetworkPolicy 고려사항: <https://docs.k3s.io/security/hardening-guide>
- Kubernetes ServiceAccount token 자동 마운트 차단: <https://kubernetes.io/docs/concepts/security/service-accounts/>
- Kubernetes SecurityContext: <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/>
- Kubernetes Pod Security Standards: <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- Kubernetes seccomp: <https://kubernetes.io/docs/reference/node/seccomp/>
- Kubernetes ResourceQuota: <https://kubernetes.io/docs/concepts/policy/resource-quotas/>
- Kubernetes LimitRange: <https://kubernetes.io/docs/concepts/policy/limit-range/>
- Kubernetes ephemeral storage resource 관리: <https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/>

특히 Kubernetes 공식 NetworkPolicy 문서는 Pod가 실행되는 node와의 트래픽 예외 및 resident node 트래픽 차단 불가를 명시한다. 따라서 본 설계는 NetworkPolicy 생성만으로 host/metadata 격리를 완료 처리하지 않는다.
