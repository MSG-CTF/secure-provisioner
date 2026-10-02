# WEB 이미지별 런타임 정책

## 목적과 적용 범위

문제 저장소의 `info.yaml`을 수정하지 않고, 운영자가 승인한 **정확한 이미지 digest**마다 컨테이너의 실행 UID, 쓰기 가능 디렉터리, 외부 공개 포트를 지정한다. 정책 파일은 [`config/web-image-policies.json`](../../config/web-image-policies.json)이다. 비밀값은 이 파일에 넣지 않는다.

Provisioner는 `PROVISIONER_IMAGE_POLICIES`가 가리키는 파일을 시작할 때 읽는다. 설정이 없으면 기존 Runtime API 동작을 유지한다. 설정이 있으면 목록에 있는 GHCR 저장소의 미등록 digest, 다른 컨테이너 이름·포트·격리 프로필, `blocked` 이미지를 생성 전에 거절한다. 등록된 digest의 요청값 중 `run_as_user`, `writable_paths`, `exposed_ports`는 이 파일의 값으로 교체한 뒤 기존 Runtime 요청 검증과 격리 resolver를 다시 통과시킨다. 이는 임의 경로 자동 탐색 기능이 아니다.

예시 서버 설치 위치는 `/etc/secure-provisioner/web-image-policies.json`이다. 서비스 환경 파일에 `PROVISIONER_IMAGE_POLICIES=/etc/secure-provisioner/web-image-policies.json`을 추가하고 서비스 계정이 정책 파일을 읽을 수 있어야 한다. 새 파일과 바이너리를 함께 배포하고 서비스를 재시작한다. 정책 파일은 Git에서 검토·버전 관리하며 VM에서만 수동 수정하지 않는다. 같은 digest의 정책을 바꾸면 새 인스턴스나 재생성에 다른 사양이 적용될 수 있으므로, 변경 이유와 영향을 검토하고 이미 실행 중인 인스턴스의 생성 기록을 확인한다.

## 현재 이미지별 판정

| 문제 | 생성 상태 | 적용 또는 필요한 설정 |
| --- | --- | --- |
| Grade Tampering | `create_enabled` | `web` UID 10001, `/tmp` 32 MiB + `/app/instance` 32 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Daily Point | `create_enabled` | `web` UID 10001, `/tmp` 64 MiB + `/app/data` 64 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Open House | `create_enabled` | `web` UID 10001, `/tmp` 64 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Logout Please | `blocked` | UID 10001, `/tmp` 64 MiB, 8080만 공개하고 9090은 내부 health. 운영 `FLAG` Secret 주입 계약이 없어 생성 차단 |
| Notebook | `blocked` | `web`은 `/tmp` 64 MiB·8080 공개. `db`는 `/tmp` 64 MiB, `/var/lib/postgresql/data` 256 MiB, `/var/run/postgresql` 16 MiB·5432 비공개. DB 이미지의 `PGDATA` 수정과 새 생성 검증 전까지 차단 |
| AFTERIMAGE | 미발행·차단 | 일곱 이미지 저장소를 관리 대상으로 등록했으며 digest 정책은 아직 없다. indexer의 UID 전환·spool 소유권, 인스턴스별 Secret, bot 자원을 해결하기 전에는 생성하지 않는다 |

`create_enabled`는 위 digest의 기본 생성 smoke가 통과했다는 운영 게이트다. 팀 간·호스트·metadata 경계의 실제 격리 검증이나 문제 풀이, reset, 데이터 보존까지 승인했다는 뜻이 아니다. 현재 두 GCP Target의 capability `true` 선언도 격리 실측을 대신하지 않는다.

## 2026-10-03 테스트 VM 적용 기록

GCP `provisioner-test-1`에 코드 커밋 `24c5d0490807a1c781a900d518b4394519235188`의 Linux 바이너리(SHA-256 `d812ab3a35a6b1aa116f526fac9898b3395ea9e5114c3f59e8140da36f9bfa92`)와 정책 파일을 함께 배포했다. `/etc/secure-provisioner/web-image-policies.json`은 `root:provisioner` 0640, 환경 파일은 `root:root` 0600이며 서비스와 Nginx가 active다. 배포 스크립트의 인증된 Runtime API 헬스 확인을 통과했다.

미등록 Grade digest와 차단된 Logout digest를 실제 생성 API에 보내 모두 `422 IMAGE_POLICY_REJECTED`를 확인했다. Grade, Daily Point, Open House는 요청에서 `writable_paths`를 빼고 기존 `expose: true`를 보냈다. 세 문제 모두 새 정책으로 생성 성공, Pod Ready·재시작 0회, HTTP 200, 삭제 성공을 확인했다. Grade는 `/login` 5번째, Daily Point는 `/` 첫 번째, Open House는 `/` 8번째 시도에 응답했다. 이 결과는 정책이 새 생성에 적용된 증거이며 팀 간 격리·문제 풀이·reset 검증은 아니다.

## 공통 격리와 비밀값

이미지별 정책은 공통 `STANDARD@v2`/`WEB` 격리의 예외 권한을 만들지 않는다. Root UID, writable root filesystem, 추가 Linux capability, 외부 egress 허용은 이 파일에서 설정할 수 없다. 격리 프로필은 이미지와 요청이 일치하는지 확인하는 조건이다. Runtime은 root filesystem을 읽기 전용으로 두고, 허용된 디렉터리만 크기가 제한된 `emptyDir`로 마운트한다. `emptyDir` 데이터는 Pod 제거 시 사라지므로 SQLite와 PostgreSQL 문제의 reset 및 재시작 동작을 별도로 확인해야 한다.

`FLAG`, `INTERNAL_TOKEN` 등의 값은 이 파일에 넣지 않는다. Logout Please와 AFTERIMAGE를 활성화하려면 인스턴스별 Secret 생성·주입 경로를 별도로 구현하고 검증해야 한다. Notebook의 `PGDATA`는 비밀이 아니므로 DB 이미지에 설정할 수 있지만, 현재 digest의 Pod에 수동 적용한 시험만 통과했다.

## 새 이미지 발행 시

1. 발행 산출물의 정확한 `image@sha256:<digest>`와 컨테이너 이름·내부 포트를 확인한다.
2. 읽기 전용 root filesystem과 UID 10001로 문제 기능을 시험한다. 실패한 경로를 자동 허용하지 말고 필요한 디렉터리만 크기와 함께 검토한다. 마운트할 디렉터리에 이미지가 원래 제공하던 파일이 있는지도 확인한다.
3. 정책 파일에 새 digest를 추가하거나 기존 digest를 교체한다. `blocked`를 `create_enabled`로 바꾸려면 새 이미지로 Runtime 생성, 모든 Pod Ready, 실제 HTTP/DB 기능, 공개·비공개 포트, reset·삭제를 확인한다.
4. 정책 파일과 바이너리를 함께 배포하고, 잘못된 digest의 요청이 `422 IMAGE_POLICY_REJECTED`로 거절되는지 확인한다. 기본 정책이 없는 다른 이미지의 기존 Runtime 요청은 그대로 처리된다.

문제별 상세 시험 근거는 작업 공간의 `docs/web-challenge-runtime-handoff.md`에 있다.
