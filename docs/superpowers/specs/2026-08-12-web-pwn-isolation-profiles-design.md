# Web/Pwn 격리 프로파일 합성 설계

## 목적

현재 `STANDARD@v1` 공통 격리를 모든 문제에 강제하면서, Web 문제와 일반 Pwn 문제에 필요한 차이만 별도 프로파일로 합성한다.

이번 구현의 목표는 다음 두 생성 경로를 명확히 만드는 것이다.

```text
Web = STANDARD@v1 + WEB@v1
Pwn = STANDARD@v1 + PWN@v1
```

`STANDARD@v1`을 복제한 완성형 프로파일 두 개를 만들지 않는다. 공통 기준은 한 곳에서만 관리하며 Web/Pwn 프로파일은 공통 기준을 완화할 수 없는 추가 제약으로만 동작한다.

## 범위

이번 범위에는 다음 항목이 포함된다.

- Web과 Pwn 문제 유형을 API 계약에서 명시적으로 구분
- 공통 격리와 문제 유형별 정책 합성
- Web용 기본 컨테이너 런타임과 HTTP/NodePort 노출 검증
- Pwn용 gVisor RuntimeClass와 NodePort 노출 강제
- Target Registry의 RuntimeClass capability 선언과 fail-closed 검증
- 생성 리소스, 멱등성 해시, 롤백 및 상태 검증에 합성 정책 반영
- 단위 테스트와 Kubernetes fake client 통합 테스트

다음 항목은 포함하지 않는다.

- 커널 문제 또는 높은 권한이 필요한 문제
- `DEDICATED_TARGET`과 전용 VM 수명주기
- Broker의 gVisor/K3s 자동 설치
- Challenge Catalog의 최종 스키마와 서명/digest 검증
- Admission Controller를 이용한 클러스터 전체 강제
- 외부 인터넷 egress 허용
- 실제 대회 K3s를 이용한 라이브 부하 테스트

## 선택한 접근

고려한 접근은 세 가지다.

1. `STANDARD@v1`과 Web/Pwn 추가 정책을 합성한다.
2. Web과 Pwn이 각각 공통 보안 설정까지 전부 소유한다.
3. 하나의 Resolver 안에서 문제 유형에 따라 조건문으로 모든 설정을 직접 변경한다.

첫 번째 접근을 선택한다. 두 번째 접근은 공통 설정이 서로 다르게 변하는 정책 드리프트가 발생하기 쉽다. 세 번째 접근은 어떤 설정이 공통이고 어떤 설정이 문제별인지 경계가 불명확해지고 테스트하기 어렵다.

## API 계약

현재 `isolation_ref`는 계속 `STANDARD@v1`만 허용한다. 여기에 문제 유형별 추가 정책을 선택하는 `workload_profile_ref`를 추가한다.

```json
{
  "isolation_ref": {
    "name": "STANDARD",
    "version": "v1"
  },
  "workload_profile_ref": {
    "name": "WEB",
    "version": "v1"
  }
}
```

Pwn 문제는 `workload_profile_ref`만 다음과 같이 바뀐다.

```json
{
  "isolation_ref": {
    "name": "STANDARD",
    "version": "v1"
  },
  "workload_profile_ref": {
    "name": "PWN",
    "version": "v1"
  }
}
```

새 계약을 사용하는 요청은 두 필드를 모두 명시해야 한다. 알 수 없는 이름이나 버전, `STANDARD@v1` 이외의 공통 격리는 거부한다.

기존 정책 필드 전체가 없는 legacy 요청만 이전 동작과의 호환을 위해 `STANDARD@v1 + WEB@v1`으로 정규화한다. 새 계약에서 `workload_profile_ref`만 누락한 요청을 Web으로 추측하지는 않는다.

Challenge Catalog 계약이 확정되기 전까지 Scheduler는 신뢰된 내부 호출자로서 문제 정의에 지정된 `workload_profile_ref`를 전달한다. 외부 사용자가 Provisioner API를 직접 호출하지 못하게 하는 인증과 네트워크 경계가 전제다. 이후 Catalog가 확정되면 `challenge_ref`와 프로파일의 불변 매핑을 검증하여 Pwn 문제가 Web 프로파일을 선택하는 다운그레이드를 차단한다.

## 정책 모델

`isolation.Request`와 `isolation.ResolvedPolicy`에 `WorkloadProfileRef`를 추가한다. 해결된 정책은 어댑터가 문자열 프로파일 이름을 다시 해석하지 않도록 다음 실행 결정을 포함한다.

- 공통 `Baseline`
- `RuntimeClassName`
- 필요한 외부 노출 방식
- endpoint protocol(`HTTP` 또는 `TCP`)
- 컨테이너 수와 외부 노출 제약
- 허용 가능한 쓰기 경로 규칙
- 기존 컨테이너, 내부 연결, outbound 및 리소스 제한

Resolver는 먼저 `STANDARD@v1`을 해결한 뒤 Web 또는 Pwn 추가 정책을 적용한다. 추가 정책은 공통 `Baseline`의 boolean 값을 완화할 수 없다.

## STANDARD@v1 공통 정책

모든 Web/Pwn 문제에 다음 정책을 적용한다.

- `instance_id`마다 독립 Namespace 생성
- 전용 ServiceAccount 사용 및 토큰 자동 마운트 차단
- non-root UID/GID 실행
- read-only root filesystem
- privileged와 privilege escalation 금지
- Linux capability 전체 제거
- RuntimeDefault seccomp 적용
- host network, host PID, host IPC 사용 금지
- hostPath, device, 임의 ServiceAccount/RBAC 사용 금지
- ResourceQuota와 LimitRange 적용
- CPU, memory, ephemeral storage requests/limits 강제
- ingress/egress default-deny
- 클러스터 DNS와 선언된 내부 연결만 egress 허용
- 외부에 노출하도록 선언된 컨테이너와 포트만 ingress 허용
- 문제 인스턴스 간 및 같은 팀 인스턴스 간 통신 차단

쓰기 경로는 요청에 선언된 `EmptyDir`만 사용한다. 절대 경로, 정규화된 경로, 크기 제한과 중첩 여부를 검증하고 `/proc`, `/sys`, `/dev`, `/var/run/secrets` 및 그 하위 경로는 금지한다.

## WEB@v1 추가 정책

Web 프로파일은 다음 정책을 공통 기준에 추가한다.

- `runtimeClassName`을 지정하지 않아 Target의 기본 runc를 사용
- 여러 컨테이너 허용
- Web, API, DB 사이 통신은 `internal_connections`에 선언된 TCP 방향과 포트만 허용
- 외부 노출 컨테이너를 하나 이상 요구
- Target이 `INGRESS_PATH`이면 Traefik 등 등록된 ingress controller에서 오는 트래픽만 허용
- Target이 `NODE_PORT`이면 Kubernetes가 할당한 NodePort만 결과 endpoint로 반환
- endpoint protocol은 `HTTP`로 반환
- `/tmp`, 업로드 디렉터리, DB 데이터 디렉터리 등 문제 정의에서 승인한 안전한 쓰기 경로 허용
- public internet outbound는 허용하지 않음

Web 프로파일은 raw SecurityContext, RuntimeClass, host 자원 또는 NetworkPolicy 입력을 호출자에게 제공하지 않는다.

## PWN@v1 추가 정책

Pwn 프로파일은 다음 정책을 공통 기준에 추가한다.

- 모든 문제 Deployment에 `runtimeClassName: gvisor` 강제
- 외부 노출 방식은 `NODE_PORT`만 허용
- 외부 노출 컨테이너는 정확히 하나만 허용
- 외부에 공개되는 TCP 포트는 정확히 하나만 허용
- endpoint protocol은 `TCP`이며 접속 주소는 `tcp://<public-host>:<node-port>`로 반환
- 노출되지 않은 sidecar는 허용하되 내부 통신은 `internal_connections`에 선언된 방향과 포트만 허용
- 모든 Pwn 컨테이너에 동일한 gVisor RuntimeClass 적용
- 쓰기 경로는 `/tmp` 또는 `/tmp`의 하위 경로만 허용
- public internet outbound는 허용하지 않음
- root UID, 추가 capability, setuid를 위한 정책 완화, privileged, host namespace 및 hostPath를 허용하지 않음

이 제한으로 실행할 수 없는 Pwn 문제는 공통 K3s 격리를 약화하지 않는다. 그런 문제는 향후 `DEDICATED_TARGET` 범위로 분리한다.

## Target Registry와 capability

`security_capabilities`에 설치되어 운영자가 검증한 RuntimeClass 목록을 추가한다.

```json
{
  "runtime_classes": ["gvisor"]
}
```

Web 요청은 기존 NetworkPolicy와 SupplementalGroupsPolicy capability를 요구한다. Pwn 요청은 여기에 다음 조건을 추가로 요구한다.

- `runtime_classes`에 정확히 `gvisor`가 존재
- Target의 `exposure_mode`가 `NODE_PORT`

Pwn 요청이 조건을 만족하지 않으면 Kubernetes 리소스를 하나도 만들기 전에 요청을 거부한다. Provisioner는 gVisor를 설치하지 않는다. Broker 또는 K3s bootstrap이 gVisor와 `RuntimeClass/gvisor`를 미리 설치하고 Target Registry에는 검증된 capability만 기록한다.

## 생성 흐름

1. HTTP 계층이 snake_case 계약과 필드 존재 여부를 검증한다.
2. 요청을 `STANDARD@v1 + workload_profile_ref` 형태의 정책 요청으로 변환한다.
3. Resolver가 공통 기준과 Web/Pwn 추가 정책을 합성하고 허용되지 않은 요구를 거부한다.
4. `target_id`로 선택한 Cluster가 해결된 정책을 지원하는지 검사한다.
5. 지원되지 않으면 Namespace 생성 전에 fail-closed 처리한다.
6. Namespace, ServiceAccount, ResourceQuota, LimitRange와 NetworkPolicy를 만든다.
7. 각 Deployment에 공통 SecurityContext를 적용하고 Pwn인 경우 gVisor RuntimeClass를 추가한다.
8. Web은 Target 설정에 따라 Ingress 또는 NodePort를 만들고, Pwn은 NodePort를 만든다.
9. Deployment, Service, Ingress/NodePort endpoint와 소유권을 검증한다.
10. 모든 필수 리소스가 준비된 경우에만 Operation을 성공 처리한다.

생성 중 실패하면 기존 동작과 동일하게 해당 요청이 소유한 Namespace 전체를 정리한다. 재시도는 같은 `request_id`와 같은 정규화 payload만 허용한다.

기존 endpoint 응답에는 `protocol` 필드를 추가한다. Web은 `HTTP`, Pwn은 `TCP`를 반환한다. Web NodePort URL은 기존처럼 `http://<public-host>:<node-port>`를 사용하고, Pwn은 같은 Target의 public host에서 scheme만 `tcp`로 바꾼 `tcp://<public-host>:<node-port>`를 사용한다. 따라서 Scheduler와 프론트엔드는 문자열 형식을 추측하지 않고 `protocol`로 접속 방식을 구분할 수 있다.

## 멱등성과 변경 감지

spec hash에는 기존 컨테이너와 리소스 정보 외에 다음 항목을 포함한다.

- `isolation_ref`
- `workload_profile_ref`
- 해결된 `RuntimeClassName`
- 해결된 외부 노출 방식
- 해결된 endpoint protocol
- 문제 유형별 쓰기 경로 제약 결과

따라서 동일한 이미지라도 Web에서 Pwn으로 프로파일이 바뀌거나 Target의 실행 방식이 달라지면 같은 스펙으로 오인하지 않는다.

## 오류 처리

다음 조건은 재시도로 해결되지 않는 정책 오류로 처리한다.

- 지원하지 않는 공통/문제 프로파일 또는 버전
- 새 계약에서 누락된 `workload_profile_ref`
- Web/Pwn 제약을 위반한 컨테이너, 포트, 쓰기 경로 또는 outbound 설정
- Pwn 프로파일의 root 또는 권한 완화 요청

다음 조건은 Target capability 불일치로 처리한다.

- gVisor RuntimeClass 미지원
- Pwn 요청이 `INGRESS_PATH` Target에 배치됨
- NetworkPolicy 또는 strict supplemental group 정책 미지원

오류 메시지와 상태에는 이미지 이름, kubeconfig 내용 또는 인증 정보를 포함하지 않는다.

## 테스트

### Resolver 단위 테스트

- `STANDARD + WEB` 합성 성공
- `STANDARD + PWN` 합성 성공
- Web 정책이 기본 runtime을 선택하는지 확인
- Pwn 정책이 gVisor와 NodePort 요구사항을 해결하는지 확인
- 공통 정책을 완화하려는 요청 거부
- Pwn 다중 노출 컨테이너/포트 거부
- Pwn의 `/tmp` 밖 쓰기 경로 거부
- public internet outbound 거부
- 알 수 없는 프로파일과 버전 거부

### API 계약 테스트

- `workload_profile_ref` snake_case 역직렬화
- unknown/duplicate field 거부 유지
- 새 계약의 프로파일 누락 거부
- 완전한 legacy 요청만 Web으로 정규화
- 정규화된 정책이 command와 operation payload에 보존되는지 확인
- endpoint 응답의 `protocol`이 snake_case 계약에 맞게 보존되는지 확인

### Target 및 리소스 테스트

- gVisor가 없는 Target에서 Pwn 생성 거부
- Ingress Target에서 Pwn 생성 거부
- Web이 Ingress/NodePort Target에서 모두 생성 가능
- Web Pod에 RuntimeClass가 지정되지 않음
- Pwn의 모든 Pod에 `runtimeClassName: gvisor` 적용
- 두 프로파일 모두 공통 SecurityContext와 NetworkPolicy 유지
- Pwn Service가 NodePort이고 외부 노출이 선언된 한 포트에 한정됨
- Web endpoint는 `HTTP`, Pwn endpoint는 `TCP`와 `tcp://` 주소를 반환
- spec hash가 프로파일과 RuntimeClass 변경을 감지

### 통합 및 실패 테스트

- fake Kubernetes client를 이용한 Web 전체 생성
- fake Kubernetes client를 이용한 Pwn 전체 생성
- capability 실패 시 Namespace가 만들어지지 않음
- 중간 생성 실패 시 요청 소유 Namespace 롤백
- 같은 요청 재시도 시 NodePort와 소유권 유지
- 다른 Namespace 및 선언되지 않은 내부 방향을 허용하는 NetworkPolicy가 생성되지 않음

실제 gVisor 실행 검증은 gVisor가 설치된 K3s Target이 준비된 뒤 별도 운영 테스트로 수행한다.

## 완료 기준

- Web 요청은 `STANDARD@v1 + WEB@v1`로 해결되고 기존 공통 격리를 유지한다.
- Pwn 요청은 `STANDARD@v1 + PWN@v1`로 해결되며 모든 Pod에서 gVisor가 강제된다.
- Pwn을 지원하지 않는 Target은 리소스 생성 전에 거부한다.
- Web/Pwn 정책 차이가 API, operation payload, spec hash와 생성된 Kubernetes 리소스에 일관되게 반영된다.
- 모든 기존 테스트와 새 격리 테스트가 통과한다.
