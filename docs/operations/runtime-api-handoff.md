# Runtime API 무중단 배포

운영 CI는 PostgreSQL 작업 큐와 Nginx API bridge를 사용해 런타임 관리 프로세스를 교체한다
이미 실행 중인 문제 Pod는 이 배포에서 재생성하거나 정지하지 않는다

## 전환 순서

1. 고정 배포 helper가 artifact 체크섬, 배포 프로토콜, 기존 API 인증을 확인한다
2. 새 바이너리를 API 전용 모드로 실행한다
   기존 환경과 같은 DB·서비스 토큰을 사용하고 worker와 schema migration은 실행하지 않는다
3. 실제 작업 조회 응답과 잘못된 토큰·토큰 누락의 401 응답을 검증한다
   해당 systemd invocation의 worker 비활성화 로그도 확인한다
4. Nginx를 bridge로 전환하고 이전 Nginx worker가 종료될 때까지 기다린다
5. 진행 중인 작업이 끝날 때까지 최대 120초 기다린다
   그동안 API 요청과 기존 worker는 계속 동작한다
6. PostgreSQL SHARE lock을 잡은 상태에서 RUNNING 작업이 없음을 확인한다
   새 작업 선점과 큐 쓰기를 잠깐 대기시킨 뒤 기존 프로세스 종료를 확인한다
7. lock을 해제하고 새 주 프로세스를 기동한다
   bridge가 받은 생성·삭제 요청은 PostgreSQL에 저장되며 새 worker가 처리한다
8. 새 API의 실제 DB 조회와 인증을 검증하고 Nginx를 주 프로세스로 복귀한다
   기존 Nginx worker 종료까지 확인한 뒤 bridge를 제거한다

단순 작업 건수 조회 뒤 재시작하면 조회와 재시작 사이에 새 작업이 시작될 수 있다
SHARE lock은 이 간격의 선점을 차단한다
읽기 요청은 계속 응답하며 큐 쓰기는 주 프로세스 정지에 필요한 짧은 시간만 대기한다
정지 명령 제한은 2초이고 lock은 helper 종료·연결 단절 시 해제된다
별도 프로세스와 PostgreSQL의 제한으로 방치된 lock도 최대 3초 이내 해제된다

## 실패와 복구

- bridge의 인증·worker 비활성화·기존 schema 호환성 검증 실패 시 주 프로세스를 교체하지 않는다
- 진행 중인 작업이 120초 안에 끝나지 않으면 기존 버전으로 경로를 복귀하고 배포를 실패 처리한다
- 새 주 프로세스 검증 실패 시 bridge를 유지하고 새 worker도 drain한 뒤 이전 artifact·환경·토큰·release marker를 복구한다
- 복구된 주 API까지 확인한 경우에만 rollback verified를 출력한다
- 복구나 Nginx 전환을 확인하지 못하면 bridge와 previous snapshot을 남기고 실패한다
  다음 배포는 이를 덮어쓰지 않고 관리자 확인을 요구한다
- GitHub runner 연결이 끊겨도 systemd bridge는 독립적으로 실행된다
  강제 종료로 남은 bridge와 snapshot은 기존 관리자 경로로 확인한다

고정 상태 경로는 /var/lib/msgctf-deploy/runtime/previous이며 파일은 root만 접근할 수 있다
bridge 실행 파일은 /opt/secure-provisioner/bridge, 환경은 /etc/secure-provisioner/bridge.env다
Nginx upstream은 /etc/nginx/snippets/msgctf-runtime-upstream.conf로 관리한다
상태 복구 없이 파일만 지우거나 bridge를 먼저 정지하면 안 된다

## 적용 조건

- 기존 운영 서비스 secure-provisioner와 provisioner 계정, PostgreSQL, IP HTTPS Nginx 설정이 필요하다
- 배포 중 DB URL, registry 경로, policy 경로, 서비스 토큰은 동일해야 한다
  DB 전환·토큰 교체는 별도 운영 절차로 진행한다
- bridge는 기존 schema를 검사하고 변경하지 않는다
  새 migration이나 API 의미 변경이 기존 버전과 호환되는지는 배포 전에 검증해야 한다
- root helper는 기존 관리자 연결에서 검토한 버전을 설치한다
  CI는 데이터 bundle만 보내며 root helper·실행 명령·경로를 지정할 수 없다
- sender는 runtime_api_bridge_v1과 worker_handoff_verified 응답을 요구한다
  이전 stop/start helper의 성공 응답은 무중단 배포 성공으로 인정하지 않는다
- 단일 VM의 프로세스 교체를 위한 절차다
  VM·PostgreSQL·Nginx 자체 장애까지 견디는 다중 서버 HA 구성은 별도다

## 검증

일회용 PostgreSQL에서 실제 Claim, 실행 중 lease, fence 해제, 중복 요청을 확인한다
실제 Go 바이너리·Nginx·PostgreSQL 통합 검증은 정상 전환, 새 버전 실패 후 복구,
복구 실패 후 bridge 유지 세 경우에 HTTP 연속 요청과 큐 보존을 확인한다
이 테스트의 workload target은 의도적으로 미등록 상태이며 실제 K3s 통합 검증으로 계산하지 않는다

SHARE lock의 충돌 범위와 읽기 허용 동작은 [PostgreSQL 공식 문서](https://www.postgresql.org/docs/current/explicit-locking.html)를 따른다
