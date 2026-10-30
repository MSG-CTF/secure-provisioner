# 런타임 API·저장소 상시 감시

일반 서비스 토큰으로 GET /internal/v1/healthz를 호출하면 API와 PostgreSQL의 Operation·Binding 조회 가능 여부를 확인할 수 있다
2초 제한의 읽기 전용 쿼리를 사용하며 작업 생성·삭제, 스키마 변경, 클러스터 조회를 수행하지 않는다
연결만 살아 있고 필수 테이블·조회 열이 손상된 경우에도 503을 반환한다

| 응답 | status | store_mode | database | 의미 |
| --- | --- | --- | --- | --- |
| 200 | ok | postgres | ok | 두 영속 저장소 조회 정상 |
| 503 | down | postgres | down | 연결·권한·스키마·기한 중 하나 이상 실패 |
| 503 | down | memory | not_configured | 영속 저장소가 없는 개발 모드 |
| 401 | 해당 없음 | 해당 없음 | 해당 없음 | 인증 누락·불일치 |
| 403 | 해당 없음 | 해당 없음 | 해당 없음 | 범위가 제한된 CI smoke 토큰 |

mode는 primary 또는 deployment_bridge이며 checked_at은 해당 쿼리가 끝난 UTC 시각이다
배포 브리지는 worker를 실행하지 않지만 같은 API와 영속 저장소가 준비되면 정상으로 응답한다
응답의 Cache-Control은 no-store이며 DSN·예외 메시지·작업 내용은 반환하지 않는다

SLA에서는 호스트 보고와 별개로 이 API를 점검하고 200·JSON 계약·최근 checked_at이 모두 맞을 때만 정상으로 판단한다
401·403·404·프록시 HTML은 정상 증거로 사용하지 않는다
DB 조회 실패는 API가 응답하는 의존성 장애이며 실행 중인 런타임을 재시작하거나 문제 컨테이너를 삭제할 근거가 되지 않는다
고정 SSH 기동 기능은 별도의 최신 호스트 보고에서 서비스 inactive 또는 failed가 확인된 경우에만 사용한다

이 점검은 클러스터 배치 가능 여부, 문제 웹·DB 기능, worker 처리 지연을 보증하지 않는다
클러스터 보고와 인스턴스별 기능 점검은 각각 유지한다
