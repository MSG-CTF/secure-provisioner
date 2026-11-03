# KOTH 75팀 운영 설정

2026년 11월 4일 실제 QA 팀으로 제출 부하를 올렸을 때 두 운영 설정에서 오류가 발생했다

| 문제 | 기존 설정에서 확인한 증상 | 적용할 설정 |
| --- | --- | --- |
| Jenga | 동시 50팀 로그인 중 SQLite 잠금으로 500 6건 발생, WAL·CPU 증설 후에도 동시 조회·제출에서 잠금 재현 | 기존 SQLite 파일을 WAL로 열고 CPU 상한 1코어·메모리 상한 512Mi 적용, Caddy에서 게임 연결을 8개로 제한 |
| Swanopoly | 75팀 동시 공식 봇 제출 중 대기열 64개 상한으로 7건이 QUEUE_FULL 응답 | test·submit의 RUNNER_MAX_WAIT_QUEUE를 각각 128로 설정 |
| Dependency Hell | 75개 미캐시 실행은 모두 PASS했지만 두 실행 슬롯에서 마지막 결과까지 870초 소요 | 기존 4코어 실행 노드에서 coordinator 슬롯 4개·public backend replica 4개 사용 |

게임 이미지와 출제자 코드는 바꾸지 않는다
Jenga의 기존 실행 명령 앞에 게임과 같은 승인 이미지의 초기화 컨테이너를 추가한다
초기화는 기존 /data/jenga.db의 journal_mode만 바꾸며 테이블·경기 데이터·채점 규칙은 유지한다
기존 CPU·메모리 요청량과 디스크 상한도 유지한다
읽기와 쓰기가 한꺼번에 몰릴 때 SQLite를 동시에 두드리는 요청은 Caddy에서 대기시킨다
게임 앞단 HTTP 연결만 제한하며 플랫폼 인증·내부 점수 경로의 접근 제어와 공개 일정은 유지한다
임시 QA 종료 시 복구하는 Caddy 설정과 해시도 함께 갱신해 11월 6일 자동 잠금 뒤에도 같은 연결 상한을 유지한다
Swanopoly의 실행 슬롯·봇 제한 시간·test/submit 격리도 유지한다

## 적용

해당 게임 VM에 이 파일과 deploy/koth_capacity.py를 전달한 뒤 먼저 계획을 확인한다
경기 중에는 재시작하지 말고 운영자가 정한 점검 시간에 적용한다

    sudo python3 /opt/msgctf-koth/koth_capacity.py jenga
    sudo python3 /opt/msgctf-koth/koth_capacity.py jenga --apply
    sudo python3 /opt/msgctf-koth/koth_capacity.py swanopoly --apply
    sudo python3 /opt/msgctf-koth/koth_capacity.py dependency-hell --apply

Swanopoly는 관리자 환경변수 버전에도 test·submit의 RUNNER_MAX_WAIT_QUEUE=128을 저장하고 실제 값과 대조한다
이후 환경변수 버전 전환에도 같은 값을 사용할 수 있도록 운영 설정을 함께 관리한다
게임 소스의 기본값과 관리자 운영값은 별도로 유지한다
Dependency Hell은 관리자 환경변수 버전의 judge-coordinator MAX_ACTIVE_EVALUATIONS도 4로 저장한다
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
