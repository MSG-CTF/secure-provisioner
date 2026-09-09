# 개발 K3s 인스턴스 네트워크 검증

관련 이슈: #11, #40. `STANDARD@v2`가 구현된 Runtime 소스에서 실행한다.

[2026-09-09 로컬 K3s 실행 결과](results/2026-09-09-local-k3s.md).

## 검증 범위

`TestK3sLiveInstanceNetwork`는 실제 Adapter로 임시 인스턴스 3개와 Pod 6개를 생성한다.

- 동일 인스턴스의 web/api 사이 양방향 Service DNS와 Pod IP 연결, TCP 8080/9000.
- 같은 팀 다른 인스턴스 및 다른 팀 인스턴스의 비공개 api에 연결 차단.
- 차단 검사 전에 대상 인스턴스 내부의 정상 연결을 확인하여 서버 미기동과 구분.
- 차단 대상에 한 번이라도 연결되면 실패. 각 경로에서 연속 3회 차단을 확인.
- `kubectl exec` 실패는 차단 성공으로 처리하지 않음.
- 응답의 공개 endpoint가 web:8080 하나인지, 실제 외부 HTTP 응답이 fixture인지 확인.
- api 및 web:9000에 공개 Service가 생성되지 않았는지 확인.
- 생성 당시 UID와 소유권을 확인하고 Namespace가 없어질 때까지 정리. 생성 실패로
  UID를 확보하지 못했거나 Namespace가 교체됐다면 자동 삭제하지 않고 실패로 기록.

이 테스트는 `NODE_PORT` 노출 모드의 개발용 K3s에서만 사용한다. `INGRESS_PATH`의
backend 분리는 별도 검증이 필요하다. 지정된 registry의 capability 값은 운영자의
설정 선언이며, 이 테스트가 PID·Admission·RuntimeClass·노드·metadata 경계까지
검증했다는 뜻은 아니다. 인터넷 egress 및 비네트워크 격리 검증도 #11의 남은 범위다.
Registry → Scheduler → Runtime 운영 경로는 이 직접 Adapter 테스트와 별도다.

## 입력과 실행

`tests/fixtures/network-probe/Dockerfile`로 이미지를 빌드해 개발용 Registry에 발행하거나
임시 K3s에 가져온다. 두 포트에서 동일 응답을 제공하는 무해한 BusyBox httpd fixture다.
입력에는 tag 대신 실제 `image@sha256:<digest>` 참조를 사용한다.

```bash
export K3S_NETWORK_REGISTRY=/absolute/path/development-registry.json
export K3S_NETWORK_TARGET_ID=development-target
export K3S_NETWORK_IMAGE=your-registry/network-probe@sha256:<actual-digest>
export K3S_NETWORK_REQUIRED=true
go test ./internal/k3s -run '^TestK3sLiveInstanceNetwork$' -count=1 -timeout 16m -v
```

일반 단위 테스트 실행에서는 registry 입력이 없으면 skip한다. 전용 CI job은
`K3S_NETWORK_REQUIRED=true`를 설정해야 환경 누락을 실패로 처리한다. kubeconfig는
registry의 `kubeconfig_path`를 사용하고 기본 kubectl context를 변경하지 않는다.
테스트 runner에서 registry의 `public_gateway`와 공개 포트에 도달할 수 있어야 한다.

로그에는 credential이나 관리 API 주소를 출력하지 않는다. 실패 시 개발 대상의
Pod 상태를 별도로 확인한다. 테스트 완료 뒤 `go test`의 최종 PASS와 Namespace
정리 결과를 함께 확인한다. 본문 최대 8분과 순차 cleanup 최대 6분을 고려해
전체 timeout은 16분으로 둔다.

## CI smoke 연동

DevSecOps의 `runtime_api_smoke_runner.py`는 loopback Runtime API에서
create/poll/delete/poll을 수행한다. Runtime 토큰은 노드의
`/etc/secure-provisioner/service-token`에서 읽고 노드 밖으로 전달하지 않는다.
`RUNTIME_TARGET_ID`, 배포된 Runtime revision 및 GHCR pull credential 설정을
DevSecOps와 맞춘 뒤 실행한다. 새 artifact에는 `internal_connections`를 넣지 않는다.

2026-09-09 확인 시 DevSecOps main의 smoke 변환은 입력에 해당 필드가 있으면
그대로 전달하며 같은 컨테이너의 public/private 혼합 포트도 거절한다. 따라서
Runtime #40/#38 지원과 별개로 caller의 artifact/DTO 전환을 확인해야 한다.
