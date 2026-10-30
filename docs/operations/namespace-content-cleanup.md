# Namespace의 남은 자원 정리

기존 Gateway 삭제는 Deployment·ReplicaSet·Service를 먼저 정리하고,
NetworkPolicy·Secret·ServiceAccount·LimitRange·ResourceQuota는 Namespace
컨트롤러에 맡겼습니다 이번 변경은 그 남은 자원도 조금씩 먼저 정리합니다

Namespace가 종료 중이고 종료 표시 후 6초가 지났으며 Pod가 하나도 없을
때만 실행합니다 Namespace와
자원의 UID·팀 소유권을 확인하고, 자원 삭제에도 UID와 resourceVersion을
지정합니다 다른 팀 자원이나 finalizer가 붙은 자원은 기존 컨트롤러에 맡깁니다

한 작업에서 최대 2개를 삭제하며 준비 작업은 250ms로 제한합니다 자체 준비
시간을 다 쓰면 기존 Namespace 컨트롤러에 맡기고 다음 조회로 넘깁니다
상위 작업 취소와 API 오류는 그대로 반환합니다 Namespace가 실제로 사라진
것을 확인하기 전에는 삭제 완료로 처리하지 않습니다

Kubernetes 1.36.4의 Namespace 컨트롤러에는 API 서버들이 종료 상태를
확인할 시간을 주는 5초 대기가 있습니다 API 시각의 초 단위 정밀도까지
감안해 이 준비 작업은 6초 뒤부터 허용합니다 이 대기는 줄이지 않습니다
[Namespace 컨트롤러 구현](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/controller/namespace/namespace_controller.go)

격리 CI는 임시 K3s에 합성 자원을 만든 Namespace 12개를 실제 API로
삭제합니다 loopback 주소만 허용하며 운영 접속 정보나 문제 이미지는
사용하지 않습니다 CPU 원복·브로커 예약 반납과 실제 사이트 속도는 이
시험의 검증 범위에 포함되지 않습니다 운영 시험 결과를 별도로 확인해야 합니다

같은 API의 로컬 요청 예산을 기다리다가 짧은 작업 제한 시간 안에 요청을
보낼 수 없는 경우도 KUBERNETES_API_BUDGET_BUSY로 구분합니다 이 경로는
HTTP 전송 전 로컬 제한기에서만 발생합니다 요청량 20 QPS·burst 40은 유지하며
실제 서버 오류·통신 시간 초과·상위 작업 취소는 이 정상 대기로 바꾸지 않습니다
