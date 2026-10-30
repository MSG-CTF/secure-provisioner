# 종료된 문제의 Namespace 정리

Gateway가 접속 경로를 제거하고 Pod 종료를 확인한 뒤, 런타임이 자신이 만든 Deployment·ReplicaSet·Service를 먼저 삭제합니다
Namespace 컨트롤러가 이 리소스를 순서대로 정리하기를 기다리는 시간을 줄이기 위한 변경입니다
Gateway의 종료 확인을 거치지 않는 일반 삭제는 기존 Namespace 삭제 순서를 사용합니다

## 삭제 조건

- 저장된 Namespace UID와 팀·인스턴스·관리 주체 레이블이 일치해야 합니다
- Namespace 안에 Pod가 하나라도 있으면 사전 삭제를 건너뜁니다
- 관리 대상 Deployment·ReplicaSet의 replicas가 모두 0이어야 합니다
- 자식 리소스도 팀·인스턴스·관리 주체를 확인하고 UID·resourceVersion 조건을 붙여 삭제합니다
- 각 자식 리소스를 삭제하기 직전에 Namespace 소유자와 UID를 다시 확인합니다
- 자식 리소스 권한이 제한됐거나 이미 삭제·교체됐다면 기존 Namespace 삭제 경로를 사용합니다
- API 연결 실패나 시간 초과는 장애 재시도로 처리합니다

## 완료 기준

Pod의 종료 유예시간과 리소스의 finalizer는 바꾸지 않습니다
Namespace 삭제에도 기존 UID·resourceVersion 조건을 유지합니다
Namespace 조회가 NotFound를 반환하기 전에는 런타임 삭제 성공을 반환하지 않습니다
스케줄러는 그 성공 결과를 받은 뒤 브로커 예약을 반납하므로, 사전 삭제만 끝난 상태에서는 예약을 반납하지 않습니다

추가 사전 조회는 Namespace 삭제 접수 전에만 수행합니다
이미 Terminating 상태인 Namespace를 재조회할 때는 기존 완료 확인 경로를 사용합니다

Kubernetes 자체의 Namespace 삭제 유예는 유지합니다
관련 동작은 [Namespace 컨트롤러](https://github.com/kubernetes/kubernetes/blob/v1.36.5/pkg/controller/namespace/namespace_controller.go#L38-L46)와 [콘텐츠 삭제](https://github.com/kubernetes/kubernetes/blob/v1.36.5/pkg/controller/namespace/deletion/namespaced_resources_deleter.go#L285-L315)에 정의돼 있습니다

## 검증

- go test ./internal/k3s ./internal/gateway ./internal/operations -count=1
- 전체 PostgreSQL·Gateway·배포 복구 CI
- 같은 문제 버전으로 실제 사이트의 생성·종료 시간 비교
- 삭제 도중 finalizer가 남았을 때 Namespace와 예약이 유지되는지 확인
- finalizer 해제 후 Namespace 삭제와 예약 반납까지 확인
