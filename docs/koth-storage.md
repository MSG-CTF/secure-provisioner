# KOTH 6개 Pod 내부 백업·검수·복구

deploy/koth_storage.py와 두 Pod 작업 파일이 Jenga·Card·Grand·Dependency Hell·Pixel·Swanopoly의 공통 도구다
호스트 제어기는 닫힌 전용 백업 바이트만 읽으며 SQLite 엔진을 가져오지 않는다

백업 대상은 고정 프로필의 SQLite·PostgreSQL DB와 인증 키 이력이다
Grand는 제출 소스와 연습·공식 리플레이, Dependency Hell은 DB가 현재 참조하는 content-addressed 산출물도 함께 백업한다
DB에 참조가 없는 임시 업로드·고아 파일·격리 파일과 비밀값 마운트는 포함하지 않으며 전체 PVC 파일 복사로 취급하지 않는다
Dependency Hell에서 이미 참조를 해제하고 삭제한 과거 산출물은 재생성하지 않는다

## DB와 파일 정합성

Grand는 서비스 Pod 안에서 만든 완료 SQLite 스냅샷의 제출·대진 참조·연습·공식 리플레이 행을 읽어 파일 목록을 고정한다
Dependency Hell은 PostgreSQL Pod의 완료 dump를 임시 DB에 복원한 뒤 그 DB의 산출물 참조를 읽고 서비스 Pod에 전달한다
원본 DB를 호스트 엔진으로 열거나 현재 디렉터리 전체를 DB 스냅샷과 무관하게 복사하지 않는다

파일은 DB의 경로·SHA-256·크기를 기준으로 읽고 DB에 크기가 없는 리플레이는 해시와 제한 안의 실제 크기를 기록한다
디렉터리와 파일을 FD로 고정하고 심볼릭 링크·하드 링크·특수 파일·경로 탈출·중복 참조 충돌을 거절한다
누락·크기 차이·해시 차이·복사 중 불일치가 있으면 백업을 성공으로 게시하지 않는다
동시 제출·참조 해제·정리 때문에 파일이 사라진 경우에는 해당 실패를 확인한 뒤 새 작업 UUID로 다시 백업한다
성공한 아카이브는 해당 DB 스냅샷의 파일 참조에 맞는 바이트를 보유하며 여섯 서비스 전체의 단일 전역 트랜잭션을 뜻하지 않는다

파일 묶음은 경로 추출 기능이 없는 전용 레코드와 파일별 zlib 스트림을 사용하고 제출물·실행 파일을 실행하지 않는다
파일 1개는 64 MiB, 고유 파일 수는 100,000개, 파일 원본 합계는 16 GiB, 압축 파일 묶음은 8 GiB로 제한한다
복원 중에도 길이·해시·참조 목록·압축 종료·후행 바이트를 검사해 압축 폭탄과 잘린 스트림을 거절한다
복원한 DB에서 참조를 다시 읽어 복원 파일을 대조하고 현재 인증 이력과 세션 폐기 검증도 함께 수행한다

파일 포함 아카이브의 외부 형식은 버전 2이며 내부 SQLite 프레임은 버전 1을 유지한다
Grand·Dependency Hell의 과거 DB 전용 아카이브는 COMPLETE_ARTIFACT_BACKUP_REQUIRED로 검수·복원을 거절하므로 새 전체 범위 백업을 먼저 만든다
복구 권한 확보용 내부 DB 전용 스냅샷은 파일 백업을 대체하지 않는다
격리 PVC는 원본 크기·압축 묶음·작업 공간을 계산해 최소 2 GiB에서 최대 32 GiB까지 정하며 원본 PVC를 확장하거나 덮어쓰지 않는다

## Core 이전 뒤 내부 경로

Core의 HTTPS 게이트웨이가 /internal/ 기본 차단을 사용하면 KOTH 경로도 별도 허용해야 한다
deploy/koth_core_gateway.py는 팀 토큰 검증·팀 조회·UUID로 고정한 환경 조회·상태·이미지 티켓 경로만 추가한다
KOTH 서버 6개와 Core 자체 점검 IP를 각각 /32로 허용하고 다른 내부 경로·기존 Broker 규칙은 보존한다
서비스 자격값 검증은 Core 앱이 계속 수행하며 IP 허용만으로 인증을 대체하지 않는다

Core 운영자는 기존 설정 SHA-256·작업 UUID·운영자·허용 IP를 명시해 계획을 확인한 뒤 --apply로 반영한다
도구는 root 소유 설정·실제 컨테이너의 디렉터리 마운트·원본 해시를 확인하고 기존 사용자 정의 nginx 설정으로 문법 검사와 무중단 reload를 수행한다
문법 검사나 reload가 실패하면 원본 설정을 복원하고 다시 검사·reload한다
원본 설정은 root 전용 사건 경로에 보관하며 결과에는 설정 해시와 허용 IP만 기록한다
설정은 VM 디렉터리 마운트에 남으므로 Core 앱 이미지 교체 뒤에도 유지된다
이미 허용 블록이 같은 설정은 검사 후 변경 없이 끝내고 내용이 다른 허용 블록은 운영자가 다시 검토해야 한다

## 저장 경계

SQLite backup API·무결성 검사·원본 행 비교는 실행 중인 서비스 Pod 안에서 수행한다
Swanopoly는 Node SQLite backup API, 나머지는 Python SQLite backup API를 사용한다
Dependency Hell의 PostgreSQL dump·복원·SQL 비교는 PostgreSQL Pod 안에서 수행한다
호스트 PVC 경로에 SQLite를 연결하거나 실행 중인 DB·WAL·SHM 파일을 직접 복사하지 않는다
읽기 전용 연결도 예외가 아니다

Card·Swanopoly의 gVisor 환경에서는 호스트와 서비스 프로세스의 잠금 문맥이 달라 호스트 연결이 살아 있는 WAL·SHM 이름을 지울 수 있다
삭제된 DB·WAL·SHM 핸들을 발견하면 LIVE_SQLITE_HANDLE_DELETED로 중단한다
이때 새 SQLite 연결·체크포인트·재시작·스케일 변경을 먼저 실행하지 않는다
서비스 프로세스를 보존한 채 사건별 WAL 수집과 복구 판단이 필요하다
이 도구는 손상된 WAL을 임의로 재구성하지 않는다

## 설치와 재배포

검증한 secure-provisioner dev 커밋의 deploy 파일을 게임 VM의 root 전용 경로로 전달한다
운영 코드가 있는 브랜치는 dev이며 README 전용 main을 설치 원본으로 쓰지 않는다

    sudo python3 deploy/install_koth_storage.py --source-sha "$REVIEWED_SHA" --game card-battle-arena

설치기는 /usr/local/lib/msgctf-koth-storage 아래에 커밋별 불변 디렉터리와 current 링크를 만든다
실행기는 /usr/local/sbin/msgctf-koth-storage, 설정은 /etc/msgctf-koth-storage/config.json이다
설정은 root 0600, 상태·백업·기록 디렉터리는 root 0700, 완성한 백업은 root 0400이다
게임 범위·소스 커밋·작업 파일 SHA-256을 설정에 고정하고 실행 때 실제 파일과 대조한다
같은 커밋의 파일 변경과 다른 게임으로의 재설정은 거절한다
Pod·이미지 재배포 후에도 VM 설치와 영속 DB의 인증 이력을 유지한다
VM 교체 시 같은 검증 커밋으로 재설치하고 암호화 보관한 백업을 접근 제한한 경로에 전달한다

## 백업과 검수

명령마다 새 UUID 작업 ID와 실제 운영자를 기록한다
게임별 flock은 동시 작업을 거절하고 실패 시에도 해제된다

    sudo msgctf-koth-storage inspect --game card-battle-arena --operation-id "$INSPECT_ID" --actor operator
    sudo msgctf-koth-storage backup --game card-battle-arena --operation-id "$BACKUP_ID" --actor operator
    sudo msgctf-koth-storage verify --game card-battle-arena --operation-id "$VERIFY_ID" --actor operator \
      --archive "$ARCHIVE_PATH" --sha256 "$ARCHIVE_SHA256"

백업 응답의 archive_path와 archive_sha256을 검수·복구에 그대로 전달한다
버전 1 JSON 헤더와 순서 고정 바이너리 프레임에서 크기·SHA-256·끝 바이트를 검증한다
압축 해제 경로나 외부 파일명은 받지 않는다
메타데이터에는 원본 Pod/PVC UID·실행 이미지 다이제스트·DB별 스키마·업무·키 이력 해시·행 수가 들어간다
백업 API가 만든 완료 스냅샷만 체크포인트하고 단일 파일로 닫는다
원본 저널 모드·WAL·SHM은 변경하지 않는다
Pod의 Python 비버퍼 표준 출력과 Node 파일 쓰기가 일부 바이트만 받아도 남은 바이트를 끝까지 반복해 쓰고 프레임 길이·해시로 완전성을 검사한다
inspect의 업무 해시는 한 읽기 트랜잭션 기준이며 실행 중인 본체 파일 해시를 일관 스냅샷으로 쓰지 않는다
별도 게임·인증 DB와 Dependency Hell의 두 엔진은 각각 일관 스냅샷이며 전체를 한 트랜잭션으로 묶지 않는다

| 게임 | SQLite 저장소 | 원본 보존 비교 |
| --- | --- | --- |
| Jenga | JENGA_DB | jenga_ticks·jenga_periods·jenga_mutations |
| Card | DATABASE_PATH와 .auth.sqlite3 | rounds·holds·period_snapshots·period_results |
| Grand | KOTH_DATABASE_PATH와 .auth.sqlite3 | score_period_results·replays |
| Pixel | DATABASE_PATH와 .auth.sqlite3 | rounds·mode_decks·best_submissions·score_snapshots |
| Swanopoly | STATE_DIR/현재 매치/swan.db | bot_codes·bot_submissions·bot_period_evaluations·period_results·period_team_scores |
| Dependency Hell | DATA_DIR/session-bindings.sqlite3와 PostgreSQL | period_results·PENDING 외 submissions |

백업의 확정 행이 현재 원본에도 같은 값으로 존재해야 한다
새 행 증가는 허용하고 과거 행 변경·삭제는 실패 처리한다
Deployment 소유 관계·이미지 다이제스트·Pod UID·PVC UID를 고정하며 바뀐 원본을 같은 대상으로 취급하지 않는다
임시 상태와 세션 수를 점수 보존 판정에 넣지 않는다

## 복구 시험과 전환

    sudo msgctf-koth-storage restore --game card-battle-arena --operation-id "$RESTORE_ID" --actor operator \
      --archive "$ARCHIVE_PATH" --sha256 "$ARCHIVE_SHA256"

restore는 현재 원본에서 권한 스냅샷을 먼저 확보한다
새 네임스페이스·PVC와 원본과 같은 다이제스트의 이미지로 격리 Pod를 만들고 과거 업무 데이터를 실제 복원한다
현재의 활성·퇴역 키 이력을 복원본에 합치고 모든 게임 세션·연결 행을 지운다
업무 해시는 과거 백업과 같고 키 이력 해시는 현재 스냅샷과 같으며 세션은 0이어야 한다
Dependency Hell의 PostgreSQL 보호 HMAC 이력도 현재 dump에서 가져오고 과거 세션은 지운다
선택 테이블 추출에 쓰는 dump는 PostgreSQL Pod 내부의 전용 임시 파일에 길이·해시를 확인해 저장하고 완료·실패 때 정리한다
추출 작업에는 Pod 내부 시간 제한을 적용하고 복구가 끝나면 원본 PostgreSQL 키 이력도 다시 대조한다
스키마·매치 경로·원본 PVC가 다르거나 복구 중 원본 키 이력이 바뀌면 실패한다

복구 Pod는 원본 PVC·Core 비밀값·서비스 계정 토큰을 받지 않는다
Ingress·Egress를 모두 거절하고 참가자 Service를 만들지 않는다
같은 노드의 캐시된 고정 이미지만 사용하고 권한 상승을 막으며 CPU·메모리를 제한한다
PostgreSQL 임시 DB는 마이그레이션 소유자로 만들고 PUBLIC의 CONNECT를 거절한다
원본 PostgreSQL DB에 pg_restore를 실행하는 경로는 거절한다
성공·실패 모두 작업 UID로 확인한 네임스페이스와 임시 DB를 정리한다

이 명령은 실제 복원·검증 뒤 시험 자원을 정리한다
restore 명령은 운영 PVC를 전환하지 않으며 운영 전환에는 아래의 별도 cutover 명령을 사용한다
source_pvc_untouched는 원본 PVC를 복원 대상으로 쓰지 않았다는 의미다
백업 중 서비스 Pod의 전용 임시 파일 작성과 정상 서비스 쓰기는 계속 발생하므로 원본 PVC 전체 바이트 불변을 뜻하지 않는다
실제 장애 전환은 아래의 쓰기 차단·최신 백업·현재 인증 이력·새 PVC·검증·공개 결정을 기록하는 절차로 수행한다
현재 이력을 확보할 수 없으면 별도 보관한 최신 이력과 새 키 또는 새 epoch가 필요하며 과거 권한만으로 기동하지 않는다

## 실패·중단·감사

    sudo msgctf-koth-storage cleanup --game card-battle-arena --operation-id "$RESTORE_ID" --actor operator

/var/lib/msgctf-koth-storage/journals에 최신 JSON과 추가 기록 JSONL을 남긴다
시각·운영자·작업 ID·소스 커밋·해시·UID·결과를 기록한다
cleanup은 저장한 네임스페이스 UID와 작업 라벨이 맞을 때만 삭제한다
Pod 내부에서는 같은 작업의 전용 임시 파일만 정리하며 열린 핸들과 예상 밖 파일은 거절한다
PostgreSQL에서는 UUID·소유자·작업 표식이 맞는 임시 DB만 정리한다
강제 종료가 DB 생성과 표식 기록 사이에 끼면 자동 삭제를 거절하므로 운영자가 감사 기록과 소유 관계를 확인한다
호스트에 남은 .partial 파일은 닫힌 전용 바이트이며 소유·경로 확인 후 정리하고 새 UUID로 재시도한다

감사에는 현재 키 이력·복구본 세션 0·원본 행 비교·정상 로그인·기존 세션·확정 점수·임시 자원 정리를 함께 남긴다
키·토큰·쿠키·복호화된 행과 dump 본문은 PR·감사 JSON·표준 출력에 쓰지 않는다
백업은 암호화 세션과 PostgreSQL 보호 키를 포함하므로 root 전용 저장과 별도 암호화 보관 정책을 적용한다
비밀값 검사를 통과한 메타데이터만 독립 감사 호스트에 읽기 전용으로 복제한다

## 회귀 테스트

    KOTH_STORAGE_PG_CONTAINER="$POSTGRES_TEST_CONTAINER" python3 -m unittest discover -s deploy -p test_koth_storage.py -v

Linux·Node 24에서 실제 WAL을 유지하는 Python·Node 작성자로 6개 프로필을 검사한다
WAL 커밋 포함·inode 보존·삭제 핸들 차단·원본 행 손실·잘린 프레임·해시·Pod 문맥·경로·현재 키·세션 0·잠금·실패 정리를 확인한다
CI PostgreSQL 18 서비스에서 실제 dump·복원·HMAC 이력·점수·임시 DB 정리를 검사한다
Core와의 정상 로그인·점수 수집은 운영에서 별도 실측한다

## Core 서버 IP 이전

DNS 변경 뒤에도 기존 Pod 네트워크 정책의 Core 주소가 남아 있으면 팀 토큰 검증이 시간 초과된다
새 Core에서 도메인 TLS와 DB·캐시 건강 확인을 통과한 뒤 기존 HTTPS 전용 규칙의 정확한 이전 /32 주소만 교체한다

    sudo msgctf-koth-core-endpoint plan --game jenga --previous-address 34.158.192.98 --address 136.108.97.182 --operation-id "$PLAN_ID" --actor operator
    sudo msgctf-koth-core-endpoint apply --game jenga --previous-address 34.158.192.98 --address 136.108.97.182 --operation-id "$APPLY_ID" --actor operator

계획·적용은 기존 정책의 UID·리비전·전체 spec을 검사하며 다른 정책이나 포트·DNS·수신 규칙을 바꾸지 않는다
기존 규칙이 없는 게임에는 새 정책을 만들지 않는다
적용 뒤 설정을 다시 읽어 확인하고 호스트에 Core 주소 핀과 감사 기록을 남긴다
이 설정은 게임 이미지·Pod 재배포와 독립적으로 유지된다
Core 내부 API 경로와 실제 정상 로그인은 별도로 확인하며 건강 확인 200만으로 인증 연동을 통과시키지 않는다

## 운영 PVC·DB 전환과 자동 롤백

    sudo msgctf-koth-cutover start --game card-battle-arena --operation-id "$CUTOVER_ID" --actor operator
    sudo msgctf-koth-cutover status --game card-battle-arena --operation-id "$CUTOVER_ID"

start는 새 UUID의 계획을 root 전용으로 저장하고 systemd 일회 작업을 비동기 시작한다
SSH 연결이 끊겨도 작업은 계속하며 작업 종료 뒤 ExecStopPost가 미완료 저널을 복구한다
호스트 재부팅 때도 k3s 뒤·환경 반영 에이전트 앞에서 복구 서비스를 실행한다
복구 서비스가 실패하면 환경 반영 에이전트의 시작 의존성이 충족되지 않으며 미완료 상태를 덮어쓰지 않는다
status는 작업 잠금과 독립적으로 원자 저장한 메타데이터만 읽는다

1) Deployment·PVC·Service·HPA UID와 템플릿을 고정하고 환경 반영 에이전트를 중지한다
2) namespace의 모든 Service 선택자를 닫고 HPA의 전용 임시 대상을 지정한 뒤 모든 Deployment를 0으로 줄인다
3) 기존 Pod 종료를 기다리고 Dependency Hell은 운영 DB의 다른 역할 연결도 0인지 확인한다
4) 같은 고정 이미지의 비밀값 없는 유지보수 Pod에서 마지막 DB·참조 파일 백업과 현재 키 이력을 확보한다
5) 새 local-path PVC에 실제 복원하고 현재 활성·퇴역 키 이력을 합치며 세션을 비운다
6) 원본 용량보다 작지 않은 새 PVC로 Deployment 템플릿을 전환한다
7) Dependency Hell은 PostgreSQL 후보 DB의 소유자·ACL·접속 제한·DB별 설정을 보존하고 DB 이름을 트랜잭션으로 교환한다
8) 원래 복제 수로 기동하고 원본 확정 행·참조 파일·키 이력·세션 0을 검사한다
9) 공개 결정을 먼저 fsync한 뒤 Service 선택자·HPA·환경 반영 에이전트를 복원한다

각 게임을 하나씩 전환하며 해당 게임의 참가자·점수 경로는 이 구간에 잠시 사용할 수 없다
전환 전체를 6개 게임의 전역 트랜잭션으로 묶지 않는다
PostgreSQL 원본 DB에 pg_restore를 실행하지 않으며 DB 파일이 있는 PostgreSQL 서버 PVC는 그대로 둔다
Dependency Hell은 복원한 논리 DB와 산출물 PVC를 함께 전환한다
원래 DB 이름과 접속 비밀값을 유지하므로 앱의 비밀값을 새로 만들거나 공개하지 않는다
새 PVC는 Deployment에 명시하며 환경·이미지 반영 에이전트는 현재 템플릿의 이 볼륨 연결을 보존한다

선택 아카이브가 필요하면 start에 archive와 sha256 인자를 함께 전달한다
현재 PVC UID·DB 경로·스키마·모든 업무 해시·파일 참조가 쓰기 차단 뒤 마지막 백업과 같아야 한다
오래된 백업이 최신 업무 행을 버리면 RECOVERY_WOULD_DISCARD_CURRENT_BUSINESS_ROWS로 중단한다
현재 권한과 업무 상태를 읽을 수 없는 완전 유실 장애를 오래된 자료만으로 자동 개방하는 명령은 제공하지 않는다
그 경우 검증된 외부 보관본과 최신 권한을 확보하는 별도 복구 판단이 필요하다

공개 시작 전 실패는 트래픽 차단을 유지하며 원래 PVC·DB로 자동 복귀한다
기존 PVC를 읽거나 롤백하는 유지보수 Pod에는 fsGroup을 지정하지 않아 실행 잠금 등 기존 파일·디렉터리의 권한을 보존한다
OnRootMismatch도 루트 권한에 따라 0700 디렉터리를 재귀적으로 넓힐 수 있으므로 기존 볼륨에는 사용하지 않는다
fsGroup은 아직 복원하지 않은 새 후보 PVC의 첫 마운트에만 적용하고 복원 완료·기존 원본·기동한 후보의 재마운트에서는 거절한다
기존 경로를 서비스 UID 10001로 읽을 수 없으면 권한을 넓히지 않고 차단 상태에서 원인을 검수한다
Python·Node SQLite 비교의 임시 파일은 Pod 안의 해당 작업 전용 0700 PVC 경로로 고정하고 설정을 다시 읽어 확인한다
큰 확정 행 대조가 작은 메모리 /tmp를 채우지 않도록 하며 작업이 끝나면 프로세스의 이전 임시 경로를 복원하고 파일을 정리한다
SQLite 설정은 별도 작업 프로세스에만 적용하며 서비스 프로세스와 운영 DB의 journal 설정을 바꾸지 않는다
원본 exec와 유지보수 Pod의 UID가 달라도 UID별 전용 임시 경로를 사용하며 다른 UID의 디렉터리를 인수하지 않는다
재마운트가 전용 임시 디렉터리에 현재 프로세스 그룹의 접근 비트를 추가했으면 Pod 내부에서 FD로 소유자를 확인한 뒤 0700으로 좁힌다
다른 소유자·다른 접근 그룹·일반 사용자 접근·심볼릭 링크는 자동 수용하지 않는다
후보에서 확보한 최신 업무·파일·키 이력을 원래 PVC·DB에 반영하고 기존 세션도 비워 구 세션이 부활하지 않게 한다
후보 기동 중 자율 작업자가 만든 새 라운드·확정 행도 새 스냅샷에 포함하며 재시도마다 현재 상태를 다시 확보한다
SQLite는 작성자와 이전 유지보수 Pod가 모두 종료된 뒤 원본 Pod 문맥에서 검수한 닫힌 DB를 원자 교체한다
이때만 닫힌 원본의 WAL·SHM·journal을 정리하며 실행 중인 작성자가 있으면 교체를 거절한다
파일은 원래 PVC 안에 별도 검수 복사본을 만들고 전체 해시 검증 뒤 파일별로 원자 교체하므로 그 공간이 추가로 필요하다
PostgreSQL은 OID로 고정한 비활성 이전 DB에 한 트랜잭션으로 최신 내용을 복원하고 원래 이름을 되돌린다
참가자가 사용하는 이름의 DB에 pg_restore를 실행하지 않으며 원래 DB 객체의 OID를 유지한다
유지보수 Pod를 먼저 종료해 중단된 kubectl exec 프로세스가 남아 있는 경우도 정리한다
원본 확정 행과 파일을 다시 검사하고 정상 기동한 뒤에만 원래 경로를 연다
후보가 기존 확정 행을 잃었거나 UID·템플릿·DB OID가 외부에서 바뀌면 두 저장소를 보존하고 needs_recovery로 남긴다
다른 운영자의 변경이나 새 확정 행을 덮어쓰며 성공으로 처리하지 않는다

공개 결정 뒤에는 새 요청이 접수됐을 수 있으므로 과거 PVC로 자동 복귀하지 않는다
일부 Service만 열린 상태에서 중단돼도 새 PVC·DB를 유지하며 남은 공개 절차를 재개한다
공개 후의 장애는 최신 상태를 기준으로 새 UUID의 복구 작업을 수행한다

    sudo msgctf-koth-cutover recover --game card-battle-arena --operation-id "$CUTOVER_ID" --actor operator

수동 복구도 같은 저널·flock·UID·리비전 조건을 사용한다
계획 변경에 같은 UUID를 재사용할 수 없으며 완료된 작업의 재실행은 저장소를 다시 전환하지 않는다
진행 중에는 설치 도구가 새 릴리스로의 교체를 거절한다
저널의 템플릿과 백업은 root 0600 또는 0400으로 보관하고 status와 JSONL에는 비밀값 없는 전환 메타데이터만 남긴다

## 실패 주입과 보관 자원

    sudo msgctf-koth-cutover start --game card-battle-arena --operation-id "$FAILURE_ID" --actor operator --fault after_ready

after_freeze·after_restore·after_pvc_switch·after_pg_swap·after_ready에서 실패를 주입할 수 있다
after_ready는 후보 PVC·DB로 실제 기동한 뒤 공개 전에 실패시키므로 실제 전환과 자동 롤백 경로를 함께 검사한다
게임별 롤백 뒤와 성공 전환 뒤에 정상 로그인·보호 경로·이전 세션·폐기 토큰 재로그인·Core 점수를 실제 HTTP로 확인한다
실패 주입은 해당 게임의 동일한 점검 중단 구간을 사용한다

원래 PVC와 성공 전환 전 DB는 복구 근거로 보관하며 자동 삭제하지 않는다
이전 PostgreSQL DB는 작업 UUID의 이름과 OID를 기록하고 새 연결을 거절한다
실패 후보도 검증이 끝날 때까지 작업 라벨과 UID로 보관한다
롤백 완료 뒤 필요 없는 실패 후보만 다음 명령으로 정리한다

    sudo msgctf-koth-cutover retire-failed --game card-battle-arena --operation-id "$FAILURE_ID" --actor operator

진행 중인 작업이나 Pod·워크로드에서 참조하는 PVC는 삭제하지 않는다
롤백된 작업의 후보 PVC UID·작업 라벨과 PostgreSQL 후보 OID·작업 표식이 모두 맞아야 삭제한다
원래 PVC와 현재 운영 DB는 이 명령의 삭제 대상이 아니다

추가 회귀 테스트는 실제 Python·Node SQLite의 원본 inode·업무·최신 키 보존·세션 폐기와 PostgreSQL 18의 실제 전환·역전환·중간 SQL 실패·OID 충돌을 검사한다
공개 전후 재시도·중단 복구 결정·HPA 중지·CAS·부팅 순서·후보 삭제 차단·재배포 뒤 PVC 보존도 검사한다
