# NodePort 참가자 접속 URL 설계

## 목적

기존 생성 API의 `service_url`과 `endpoints[].service_url` 계약을 유지하면서, 참가자가 도메인 없이 `http://<target 공인 IP>:<NodePort>`로 문제 컨테이너에 접속할 수 있게 한다.

## 대상 규모

- 75팀, 팀당 최대 2개 문제 인스턴스인 최대 150개를 1차 목표로 한다.
- Kubernetes 기본 NodePort 범위 `30000-32767`의 자동 할당을 사용한다.
- 프로비저너가 자체 포트 풀을 관리하지 않고 Kubernetes API 서버가 충돌 없이 포트를 배정한다.

## Target 설정

Cluster Registry에 노출 모드를 추가한다.

```json
{
  "target_id": "aws-k3s-lab",
  "public_gateway": "http://3.38.101.0",
  "exposure_mode": "NODE_PORT"
}
```

- `NODE_PORT`: 공개 컨테이너를 NodePort Service로 노출하고 Ingress를 만들지 않는다.
- `INGRESS_PATH`: 기존 Ingress path 동작을 유지한다.
- 기존 설정과의 호환성을 위해 `exposure_mode` 생략 시 `INGRESS_PATH`를 사용한다.
- `NODE_PORT`에서는 `public_gateway`에 path, query, fragment, 명시적 port를 허용하지 않는다.

## 생성 동작

1. `expose:false` 컨테이너의 Service는 ClusterIP로 생성한다.
2. `expose:true` 컨테이너의 Service는 NodePort로 생성한다.
3. 요청에는 NodePort를 지정하지 않고 Kubernetes가 포트별 NodePort를 자동 할당한다.
4. Service 생성·갱신 결과에서 할당된 NodePort를 읽는다.
5. 공개 endpoint를 요청 순서대로 다음과 같이 만든다.

```json
{
  "container_name": "web",
  "port": 8080,
  "service_url": "http://3.38.101.0:31042"
}
```

6. 첫 공개 endpoint를 기존 `service_url`에도 동일하게 넣는다.
7. 재시도와 동일 스펙 재생성에서는 기존 Service의 NodePort를 보존한다.

## 상태·삭제

- NodePort 모드의 `endpoint_ready`는 Ingress가 아니라 공개 Service가 참조하는 Ready EndpointSlice를 확인한다.
- 컨테이너 상태와 사용량 응답 형식은 바꾸지 않는다.
- 삭제는 기존처럼 전용 Namespace 전체를 삭제하므로 NodePort도 함께 반환된다.

## 오류 처리

- Service가 공개 포트에 NodePort를 할당하지 않으면 생성 Operation을 `RESOURCE_APPLY_FAILED`로 실패시키고 Namespace를 롤백한다.
- NodePort 범위 고갈이나 Kubernetes Service 생성 오류도 기존 `RESOURCE_APPLY_FAILED` envelope를 사용한다.
- `public_gateway`가 NodePort URL을 만들 수 없는 형태이면 시작 시 `CONFIG_INVALID`로 거부한다.

## 범위 제외

- AWS Security Group과 GCP Firewall 규칙 변경
- Elastic IP·Static External IP 발급
- TCP 포너블용 `tcp://` scheme 선택 계약
- NodePort 범위 변경
- 스케줄러 코드 변경

이번 구현은 HTTP 문제 URL 반환을 우선하며, TCP 문제는 컨테이너 계약에 protocol 또는 scheme 필드를 추가하는 후속 합의가 필요하다.

## 검증

- 단일·다중 컨테이너에서 공개 Service만 NodePort가 되는 단위 테스트
- Kubernetes 할당 NodePort가 endpoint URL에 반영되는 Adapter 테스트
- 동일 Service 갱신 시 NodePort 보존 테스트
- NodePort 모드 상태 조회의 Ready EndpointSlice 테스트
- 기존 Ingress 모드 전체 회귀 테스트
- AWS K3s에서 다중 컨테이너 생성 후 반환 URL과 실제 NodePort Service 확인
