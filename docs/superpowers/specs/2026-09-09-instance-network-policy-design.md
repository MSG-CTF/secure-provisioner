# 인스턴스 내부 통신 기본 정책 전환

## 근거와 범위

- secure-provisioner #40의 2026-09-08 협의 코멘트: 신규 요청에서 `internal_connections`를 제거하고 동일 challenge instance 내부 통신을 허용한다.
- 사용자 승인: 위 변경, #11 검증 기준 갱신, #30 이미지 Pull 검증 요구를 실제 작업으로 처리한다.
- 이 브랜치는 #40의 Runtime 계약·정책·회귀 테스트·명세를 담당한다. 실환경 검증 도구와 결과는 #11/#30에서 별도 추적한다.

## 신규 계약

`workload.internal_connections`는 삭제된 필드다. 값이 `null`, 빈 배열 또는 연결 목록이어도 HTTP API는 거부한다. Scheduler가 전달할 필드는 기존 컨테이너, 자원 한도와 WEB/PWN 격리 프로필이다. 새 DSL이나 raw NetworkPolicy 입력은 추가하지 않는다.

새 요청의 승인 정책은 `STANDARD@v2`다. Namespace 기본 ingress/egress 차단에 동일 Namespace의 동일 소유권 label을 가진 Pod 사이 양방향 통신 허용을 더한다. 내부 포트/프로토콜은 제한하지 않는다. 다른 인스턴스·팀·문제의 Pod를 선택하는 NamespaceSelector나 임의 CIDR을 추가하지 않는다. 인스턴스가 문제의 실행 경계이므로 API에 별도 challenge 식별자를 추가하지 않는다.

DNS와 `ports`/`exposed_ports` 기반 공개 ingress는 유지한다. 외부 egress는 `NONE`이다. 호스트 및 metadata 경계는 #32의 별도 검증 범위다.

## 기존 작업과 롤아웃

기존 DB Operation/Binding의 `STANDARD@v1` 및 연결 목록은 보존한다. 재시도는 저장된 v1 정책으로 실행하고 새 허용 규칙을 추가하지 않는다. 이를 위해 내부 snapshot 모델의 legacy 연결 필드와 v1 builder만 유지하며 신규 snapshot에서는 빈 필드를 생략한다. 새 resolver는 legacy 연결 입력을 받지 않는다. 알 수 없는 정책 버전 및 v2와 legacy 연결 필드의 혼합은 거부한다.

기존 실행 인스턴스의 정책을 일괄 갱신하지 않는다. 동일 요청은 resolver 실행 전에 기존 Operation을 찾아 원래 결과를 반환한다. 외부 입력이 바뀌면 충돌로 거절하고, 새 인스턴스 생성에만 새 request_id/instance_id를 사용한다. 배포 순서는 새 Runtime 준비, caller의 삭제 필드 제거, 신규 인스턴스 생성과 검증이다. 구 caller는 명확히 거절되므로 소비자 전환을 조율해야 한다.

## 검증

- 신규 HTTP 요청에서 필드 부재는 성공, 삭제 필드의 모든 값은 실패.
- 신규 승인 정책 v2, 새 snapshot에서 legacy 필드 부재.
- 동일 인스턴스 양방향 허용, 소유권 및 Namespace 제한, 외부 egress 차단과 공개 포트 제한 유지.
- v1 snapshot round trip 및 기존 그래프 정책 재생, v2 혼합 입력과 미지원 버전 거부.
- 전체 Go 테스트, vet, build, 관련 race 및 PostgreSQL 통합 검사.
- 실제 CNI 차단 효과와 정상 운영 경로 연동은 #11의 개발 K3s 결과로 별도 확인한다.

공식 NetworkPolicy 의미: https://kubernetes.io/docs/concepts/services-networking/network-policies/
