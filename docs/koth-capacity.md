# KOTH 75팀·150명 운영 설정

2026년 11월 4일 일반 QA 팀 75개로 실제 접속·제출·채점을 진행해 세 가지 운영 설정을 조정했다

| 문제 | 기존 설정에서 확인한 증상 | 적용할 설정 |
| --- | --- | --- |
| Jenga | 동시 50팀 로그인 중 SQLite 잠금으로 500 6건 발생, WAL·CPU 증설 후에도 동시 조회·제출에서 잠금 재현 | 기존 SQLite 파일을 WAL로 열고 CPU 상한 1코어·메모리 상한 512Mi 적용, Caddy에서 게임 연결을 8개로 제한 |
| Swanopoly | 75팀 동시 공식 봇 제출 중 대기열 64개 상한으로 7건이 QUEUE_FULL 응답 | test·submit의 RUNNER_MAX_WAIT_QUEUE를 각각 128로 설정 |
| Dependency Hell | 두 실행 슬롯에서 75개 채점에 최대 870초 소요, replica만 늘리면 CPU 기반 HPA가 대기 중에도 다시 2개로 축소 | coordinator 슬롯 4개·backend HPA 하한 4개, 대기 작업을 한 건씩 확보 |
| Pixel Smuggler | 75팀 제출과 150명 조회가 겹치면 Waitress 대기열이 약 90개까지 늘고 2초 헬스체크가 실패해 Pod 재시작 | 공개·미리보기·점수 조회 경로를 하나의 loopback 풀로 모으고 제출 2개·나머지 요청 4개로 구분 |

게임 이미지와 출제자 코드는 바꾸지 않는다
Pixel은 Pod 설정과 기존 Waitress 8개 스레드도 유지한다
게임 앞단 Caddy에 127.0.0.1 전용 연결 풀을 추가해 직접 Pod로 들어오는 Kubernetes 헬스체크가 처리될 여유를 남긴다
기존 인증·공개 시각·요청 헤더 설정을 통과한 요청만 이 풀로 전달하며 외부에서 loopback 포트로 접속할 수 없다
Jenga의 기존 실행 명령 앞에 게임과 같은 승인 이미지의 초기화 컨테이너를 추가한다
초기화는 기존 /data/jenga.db의 journal_mode만 바꾸며 테이블·경기 데이터·채점 규칙은 유지한다
기존 CPU·메모리 요청량과 디스크 상한도 유지한다
읽기와 쓰기가 한꺼번에 몰릴 때 SQLite를 동시에 두드리는 요청은 Caddy에서 대기시킨다
게임 앞단 HTTP 연결만 제한하며 플랫폼 인증·내부 점수 경로의 접근 제어와 공개 일정은 유지한다
임시 QA 종료 시 복구하는 Caddy 설정과 해시도 함께 갱신해 11월 6일 자동 잠금 뒤에도 같은 연결 상한을 유지한다
Swanopoly의 실행 슬롯·봇 제한 시간·test/submit 격리도 유지한다

## 적용

해당 게임 VM에 deploy/koth_capacity.py와 deploy/koth_pixel_gateway.py를 같은 디렉터리로 전달한 뒤 먼저 계획을 확인한다
경기 중에는 재시작하지 말고 운영자가 정한 점검 시간에 적용한다

    sudo python3 /opt/msgctf-koth/koth_capacity.py jenga
    sudo python3 /opt/msgctf-koth/koth_capacity.py jenga --apply
    sudo python3 /opt/msgctf-koth/koth_capacity.py swanopoly --apply
    sudo python3 /opt/msgctf-koth/koth_capacity.py dependency-hell --apply
    sudo python3 /opt/msgctf-koth/koth_capacity.py pixel-smuggler --apply

Swanopoly는 관리자 환경변수 버전에도 test·submit의 RUNNER_MAX_WAIT_QUEUE=128을 저장하고 실제 값과 대조한다
이후 환경변수 버전 전환에도 같은 값을 사용할 수 있도록 운영 설정을 함께 관리한다
게임 소스의 기본값과 관리자 운영값은 별도로 유지한다
Dependency Hell은 관리자 환경변수 버전의 judge-coordinator MAX_ACTIVE_EVALUATIONS도 4로 저장한다
backend의 RECOVERY_BATCH_SIZE와 RECOVERY_INTERVAL_SECONDS도 각각 1로 저장한다
HPA의 기존 최대 8개와 CPU 기준은 유지하고 최소 replica만 4개로 올린다
작업자가 채점을 기다릴 때 CPU 사용량이 낮아져도 대기열 처리 인원이 줄지 않게 한다
각 작업자가 대기 항목 16개를 먼저 임대하고 순서대로 처리하던 설정도 한 건씩 확보하도록 바꾼다
실행 중인 Job이 없고 전용 실행 노드가 4코어·4GB이며 환경변수 에이전트가 backend 4개를 허용할 때만 확장한다
기존 실행 파일·Hidden Test·20초 응답 패딩·Job별 1코어/640Mi 제한·gVisor·admission 정책은 유지한다

도구는 해당 문제의 단일 game Deployment와 승인된 이미지 경로만 허용한다
적용 전 Deployment는 /var/lib/msgctf-koth-capacity에 root 전용으로 한 번 저장한다
현재 리소스 버전이 달라지면 덮어쓰지 않고 중단한다
이미 적용한 설정은 다시 재시작하지 않는다
Jenga를 다른 DB 경로나 여러 replica로 운영할 때는 이 설정을 그대로 사용하지 않는다

## 확인

일반 팀 토큰으로 75팀이 로그인하고 실제 제출할 때 오류와 대기 시간을 확인한다
15분 구간 종료 후 게임 결과와 플랫폼 점수가 일치하고 같은 구간을 다시 수집해도 중복 지급하지 않는지 확인한다
Jenga는 init container 완료·Pod 준비·DB WAL 모드·기존 경기 데이터도 확인한다
Swanopoly는 정상 코드 75개가 서로 다른 해시로 실제 평가되고 모든 제출이 등록됐는지 확인한다
이 부하는 기본 예제 봇 기준이며 모든 악성 봇이 제한 시간을 끝까지 사용하는 경우의 처리량을 보장하지 않는다

Pixel은 일반 QA 계정 150개·75팀으로 실제 PNG 75개 제출과 3초 간격 조회를 겹쳐 확인했다
제출 75건과 조회 4,113건 모두 200이었고 조회 P95는 약 14.5초에서 6.1초로 줄었다
제출 대기는 최대 25.4초이며, 업로드 처리 시간을 없애는 설정은 아니다
직접 Pod 헬스체크와 재시작 횟수를 함께 대조해 앞단의 정상 응답만으로 통과 처리하지 않는다
Dependency Hell의 DB 교착 수정은 문제 저장소의 API 어댑터와 PostgreSQL 마이그레이션에서 별도로 적용한다
