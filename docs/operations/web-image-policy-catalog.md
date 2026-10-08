# WEB 이미지별 런타임 정책

## 목적과 적용 범위

문제 저장소의 `info.yaml`을 수정하지 않고, 운영자가 승인한 **정확한 이미지 digest**마다 컨테이너의 실행 UID, 쓰기 가능 디렉터리, 외부 공개 포트를 지정한다. 정책 파일은 [`config/web-image-policies.json`](../../config/web-image-policies.json)이다. 비밀값은 이 파일에 넣지 않는다.

Provisioner는 `PROVISIONER_IMAGE_POLICIES`가 가리키는 파일을 시작할 때 읽는다. 설정이 없으면 기존 Runtime API 동작을 유지한다. 설정이 있으면 목록에 있는 GHCR 저장소의 미등록 digest, 다른 컨테이너 이름·포트·격리 프로필, `blocked` 이미지를 생성 전에 거절한다. 등록된 digest의 요청값 중 `run_as_user`, `writable_paths`, `exposed_ports`는 이 파일의 값으로 교체한 뒤 기존 Runtime 요청 검증과 격리 resolver를 다시 통과시킨다. 이는 임의 경로 자동 탐색 기능이 아니다.

## 2026-10-06 시험 배포와 CI smoke 계약

GCP `provisioner-test-1`에 코드 커밋 `d806276e328a6e58611ebb875c2e186dd79448b7`에서 빌드한 Linux/AMD64 바이너리(SHA-256 `ebcf206bcce299a45632c1a836ae7e6e7051f251a09f900e3b50ba9a6a910577`)와 정책 파일(SHA-256 `73ec68ba29e84800cb429b7c1e8a76b66e79bcac70d4bf475f5fb299b61959c7`)을 함께 배포했다. VM의 `/opt/secure-provisioner/release.json`이 이 값을 기록한다. 서비스는 active다. 기존 FLAG 파일의 값은 변경하지 않았다.

정책 파일의 `readiness_http`는 해당 digest의 컨테이너에 HTTP readiness probe를 붙인다. 현재 Grade Tampering, Daily Point, Open House, Logout Please의 8080 `/`에 적용한다. 생성 Operation의 `SUCCEEDED`는 이 probe와 EndpointSlice 준비를 통과한 뒤 반환한다. 앱의 모든 기능·풀이 경로가 정상이라는 뜻은 아니다. CI 전용 이미지 허용 표시는 `ci_smoke_enabled`이며 Grade Tampering, Daily Point, Open House 세 digest에만 켰다. FLAG가 필요한 Logout Please는 제외했다.

CI용 토큰은 `/etc/secure-provisioner/ci-smoke-token`에 `root:provisioner` 0640으로 저장한다. 서비스 환경 파일은 `PROVISIONER_CI_SMOKE_TOKEN_FILE`, `PROVISIONER_CI_SMOKE_TEAM_ID`, `PROVISIONER_CI_SMOKE_TARGET_ID`로 토큰 경로와 전용 팀·Target을 연결한다. 시험 배포의 전용 팀은 `c0a720f9-4301-4a1f-804f-222769cf90b2`, Target은 `broker-test2`의 `b794d71b-51ef-45fd-87c1-9721e2999e79`다. 같은 토큰을 문제 검증 워크플로의 호출 저장소 `MSG-CTF/2026_MSG_CTF`에 GitHub Actions Secret `RUNTIME_API_TOKEN`으로 등록했다. API URL·팀·Target은 이 저장소의 Actions 변수 `RUNTIME_API_URL`, `RUNTIME_CI_TEAM_ID`, `RUNTIME_TARGET_ID`에 등록했다. Actions는 `Authorization: Bearer`로 전송한다. GitHub 호스팅 러너의 승인된 Grade 수동 smoke가 아래와 같이 통과했다. 발행 직후 자동 smoke는 DevSecOps PR #16이 아직 병합되지 않아 비활성 상태다. CI용 토큰은 기존 전체 권한 서비스 토큰 및 노드의 GHCR pull 인증과 별개다.

CI 토큰은 전용 팀·Target에서 위 세 WEB digest 중 하나의 단일 컨테이너 생성만 허용한다. 요청 상한은 CPU 500m, 메모리 512 MiB, 임시 저장공간 1024 MiB다. 해당 팀·Target의 Runtime 상태·Operation 조회와 정확한 인스턴스 삭제만 허용한다. 시험에서는 이 토큰으로 Grade 생성 Operation `fd659e37e6ab661b94b1d9b44fa90807`이 `SUCCEEDED`, 상태 `READY`와 `endpoint_ready=true`, Pod HTTP readiness probe `/`:8080, 공개 `/login` HTTP 200을 확인했다. 삭제 Operation `74d732227f054993421ec873f21d953e`는 `SUCCEEDED`이고 Namespace가 제거됐다. 다른 팀의 상태·Operation 조회, 다른 팀 생성, FLAG가 필요한 이미지 생성은 각각 HTTP 403이었다. 이 시험은 VM 내부에서 했으며 GitHub Actions, Scheduler reset, 다중 문제 동시 부하는 별도 시험이다.

외부 PC에서 공개 `https://34.67.93.98:443/internal/v1`의 인증서 검증 결과는 성공이었고 무인증 요청은 HTTP 401, CI 토큰을 단 다른 팀 Operation 조회는 HTTP 403이었다. 따라서 공개 HTTPS와 CI 토큰의 외부 인증 경로는 확인했지만 GitHub 호스팅 러너 출발지 시험은 아니다.

문제 저장소의 [수동 GitHub Actions 실행](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/37443357952)은 승인된 Grade digest `9ffbf476…0956d`를 고정한 `artifact-v2.json`으로 create와 delete를 모두 `SUCCEEDED`로 마쳤다. 시험 인스턴스 `ff93e661-0fd6-44c9-a7b1-db789c2eb461`의 Namespace 제거도 K3s에서 재조회했다. 첫 실행 `37443144713`은 당시 workflow가 가리킨 구형 smoke runner가 HTTPS를 거절해 Runtime 요청 전에 실패했고, runner 고정 커밋을 HTTPS 지원 버전으로 바꾼 뒤 재실행했다. 이 수동 시험은 **새로 발행한 digest**의 승인·cold pull이나 발행 직후 자동 실행을 검증한 것은 아니다.

예시 서버 설치 위치는 `/etc/secure-provisioner/web-image-policies.json`이다. 서비스 환경 파일에 `PROVISIONER_IMAGE_POLICIES=/etc/secure-provisioner/web-image-policies.json`을 추가하고 서비스 계정이 정책 파일을 읽을 수 있어야 한다. 새 파일과 바이너리를 함께 배포하고 서비스를 재시작한다. 정책 파일은 Git에서 검토·버전 관리하며 VM에서만 수동 수정하지 않는다. 같은 digest의 정책을 바꾸면 새 인스턴스나 재생성에 다른 사양이 적용될 수 있으므로, 변경 이유와 영향을 검토하고 이미 실행 중인 인스턴스의 생성 기록을 확인한다.

## 현재 이미지별 판정

| 문제 | 생성 상태 | 적용 또는 필요한 설정 |
| --- | --- | --- |
| Grade Tampering | `create_enabled` | `web` UID 10001, `/tmp` 32 MiB + `/app/instance` 32 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Daily Point | `create_enabled` | `web` UID 10001, `/tmp` 64 MiB + `/app/data` 64 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Open House | `create_enabled` | `web` UID 10001, `/tmp` 64 MiB, 외부 8080. 해당 digest의 실제 K3s 생성·HTTP 응답·삭제 확인 |
| Logout Please | `create_enabled` | 최신 발행 digest `c1736999…931909`, UID 10001, `/tmp` 64 MiB, 8080만 공개하고 9090은 내부 health. `requires_flag: true`이며 백엔드의 승인된 비밀값 참조로 Kubernetes Secret에 주입. 기존 VM 방식에서 생성·HTTP·삭제 확인, 백엔드 전환은 추가 검증 필요 |
| Notebook | `blocked` | `web`은 `/tmp` 64 MiB·8080 공개. `db`는 `/tmp` 64 MiB, `/var/lib/postgresql/data` 256 MiB, `/var/run/postgresql` 16 MiB·5432 비공개. DB 이미지의 `PGDATA` 수정과 새 생성 검증 전까지 차단 |
| AFTERIMAGE | 미발행·차단 | 일곱 이미지 저장소를 관리 대상으로 등록했으며 digest 정책은 아직 없다. indexer의 UID 전환·spool 소유권, 인스턴스별 Secret, bot 자원을 해결하기 전에는 생성하지 않는다 |

`create_enabled`는 위 digest의 기본 생성 smoke가 통과했다는 운영 게이트다. Logout Please는 아래에 적은 공식 풀이도 통과했다. 다른 문제의 풀이, 팀 간·호스트·metadata 경계의 실제 격리 검증, reset, 데이터 보존까지 승인했다는 뜻은 아니다. 현재 두 GCP Target의 capability `true` 선언도 격리 실측을 대신하지 않는다.

## 2026-10-05 Logout Please 최신 이미지 시험

문제 저장소 `2026_MSG_CTF`의 발행 산출물(소스 커밋 `f146e2011c0f602771a01749c944847671ddd20a`)에서 `service@sha256:c1736999c957b408c09dda518d49eecbfcb37ffae0d9227e6a378a666f931909`를 확인했다. 이전 정책의 `c4407d42…8ab702`는 이전 소스 이미지라 현재 공식 풀이가 HTTP 404로 실패했다. 테스트 VM의 바이너리는 `83227e8a2e98c5d1e81b7251e6185fa27d8032a5`에서 빌드한 버전이며, Pod의 `enableServiceLinks: false`로 Kubernetes가 주입하는 `SERVICE_PORT` 환경변수와 문제의 숫자 포트 설정이 충돌하지 않게 했다. 새 정책 커밋은 `055768f5dcf2870f62c8dfe815a85004d13441c7`이다.

`info.yaml`의 FLAG와 VM 비공개 FLAG 목록 값이 일치함을 값 출력 없이 확인했다. 이미지 digest와 FLAG 목록의 키를 함께 새 digest로 교체하고 서비스 재시작·무인증 `401`을 확인했다. `broker-test-3`에 새 인스턴스 `699ec681-5686-4225-b388-855dfaa36611`을 생성한 Operation `a0f59c36aceec09c06d84418de77bda0`은 `SUCCEEDED`였다. Pod는 `READY`, 재시작 0회, 사설·공개 URL 모두 HTTP 200이었다. `FLAG`는 변경 불가 namespace Secret `challenge-env`에서 `service` 키로 주입됐고, NodePort 서비스는 8080만 공개했다. 최신 소스의 공식 풀이가 주입된 FLAG와 정확히 일치했다. 삭제 Operation `eff591326fd0c7c7519580b0bd2355f8`은 `SUCCEEDED`이고 namespace 조회는 `404`였다. 시험 URL은 삭제 후 사용하지 않는다. Backend 채점 hash와 reset, 여러 팀 사이 격리는 이 시험에 포함되지 않았다.

## 2026-10-03 테스트 VM 적용 기록

GCP `provisioner-test-1`에 코드 커밋 `24c5d0490807a1c781a900d518b4394519235188`의 Linux 바이너리(SHA-256 `d812ab3a35a6b1aa116f526fac9898b3395ea9e5114c3f59e8140da36f9bfa92`)와 정책 파일을 함께 배포했다. `/etc/secure-provisioner/web-image-policies.json`은 `root:provisioner` 0640, 환경 파일은 `root:root` 0600이며 서비스와 Nginx가 active다. 배포 스크립트의 인증된 Runtime API 헬스 확인을 통과했다.

미등록 Grade digest와 차단된 Logout digest를 실제 생성 API에 보내 모두 `422 IMAGE_POLICY_REJECTED`를 확인했다. Grade, Daily Point, Open House는 요청에서 `writable_paths`를 빼고 기존 `expose: true`를 보냈다. 세 문제 모두 새 정책으로 생성 성공, Pod Ready·재시작 0회, HTTP 200, 삭제 성공을 확인했다. Grade는 `/login` 5번째, Daily Point는 `/` 첫 번째, Open House는 `/` 8번째 시도에 응답했다. 이 결과는 정책이 새 생성에 적용된 증거이며 팀 간 격리·문제 풀이·reset 검증은 아니다.

2026-10-03에는 FLAG 주입 코드 커밋 `79a4caa8491c35bd651cf5450daa268c57a7aad4`의 Linux 바이너리(SHA-256 `36edc58afb1382f3f2cc7024ff2bdaa6a4810d11c8a258c59dec373b32e46738`)와 새 정책(SHA-256 `1cc532e5c0780bb83365bf0ef09da9465823f7955bc6f86be54271443c29cec9`)을 같은 VM에 배포했다. `/etc/secure-provisioner/flags.json`은 `root:provisioner` 0640으로 **빈 목록**을 두고 `PROVISIONER_FLAG_FILE` 경로를 연결했다. 서비스·인증 API·두 K3s 연결 검증을 통과했고, Logout 생성 요청은 계속 `422 IMAGE_POLICY_REJECTED`로 차단됐다.

임시 시험에서는 이미 K3s 실행이 확인된 공개 Nginx digest에만 `requires_flag` 정책과 **시험용 FLAG**를 추가했다. `broker-test2`에서 인스턴스 `80c641c8-7974-4aba-8857-6debebdf71d5`의 생성 Operation `SUCCEEDED`, Runtime `READY`·endpoint ready를 확인했다. K3s에서 namespace Secret의 값과 변경 불가 설정, Deployment의 `FLAG` → `secretKeyRef` 연결을 직접 조회해 일치 여부를 확인했고, 삭제 Operation도 `SUCCEEDED`였다. 이후 임시 정책·값을 복구했으며 원래 정책의 SHA-256, 빈 FLAG 파일, 서비스 active, Logout 422를 다시 확인했다. 운영 FLAG 값과 Backend hash 일치, 실제 문제 풀이 및 채점은 검증하지 않았다.

코드 검토에서 파일 소유권과 부모 경로 검사 누락을 발견해 `acc75e52d5d2784b6e465951a54bc661b618065a`에서 수정했다. 수정 바이너리 SHA-256 `0f8a78bfdcfb61a3de520fe4a8ea912d076bdd124d22047882d4cf7537368ead`를 같은 VM에 재배포했다. `verify.sh`의 서비스·인증 API·두 K3s 연결, 공개 HTTPS 무인증 `401`, 정책 체크섬 불변, `root:provisioner` 0640 FLAG 파일의 빈 목록(0개)을 확인했다. 앞 문단의 임시 생성·삭제 시험은 이전 바이너리에서 진행했으며 보안 수정 이후에는 반복하지 않았다.

## 공통 격리와 비밀값

이미지별 정책은 공통 `STANDARD@v2`/`WEB` 격리의 예외 권한을 만들지 않는다. Root UID, writable root filesystem, 추가 Linux capability, 외부 egress 허용은 이 파일에서 설정할 수 없다. 격리 프로필은 이미지와 요청이 일치하는지 확인하는 조건이다. Runtime은 root filesystem을 읽기 전용으로 두고, 허용된 디렉터리만 크기가 제한된 `emptyDir`로 마운트한다. `emptyDir` 데이터는 Pod 제거 시 사라지므로 SQLite와 PostgreSQL 문제의 reset 및 재시작 동작을 별도로 확인해야 한다.

FLAG와 INTERNAL_TOKEN 등의 값은 이 파일에 넣지 않습니다
백엔드가 릴리스에 고정한 비밀값 참조를 사용합니다
AFTERIMAGE의 인스턴스별 값 생성은 여전히 미지원입니다 Notebook의 `PGDATA`는 비밀이 아니므로 DB 이미지에 설정할 수 있지만, 현재 digest의 Pod에 수동 적용한 시험만 통과했다.

## 현재 FLAG 주입 경로

백엔드가 비밀값과 버전을 관리하고 런타임이 실행 직전에 조회합니다
VM 파일 방식은 제거했으며 PROVISIONER_FLAG_FILE이 남아 있으면 시작하지 않습니다
requires_flag 이미지에는 승인된 FLAG 참조가 필요합니다
전환 순서와 조회 계약은 [백엔드 비밀값 주입](backend-secret-injection.md)을 따릅니다

앞의 10월 3일·5일·6일 기록은 당시 VM 파일 방식의 시험 결과입니다
백엔드로 옮긴 뒤 같은 배포가 이미 검증됐다는 뜻은 아닙니다

## 새 이미지 발행 시

1. 발행 산출물의 정확한 `image@sha256:<digest>`와 컨테이너 이름·내부 포트를 확인한다.
2. 읽기 전용 root filesystem과 UID 10001로 문제 기능을 시험한다. 실패한 경로를 자동 허용하지 말고 필요한 디렉터리만 크기와 함께 검토한다. 마운트할 디렉터리에 이미지가 원래 제공하던 파일이 있는지도 확인한다.
3. 정책 파일에 새 digest를 추가하거나 기존 digest를 교체한다. `blocked`를 `create_enabled`로 바꾸려면 새 이미지로 Runtime 생성, 모든 Pod Ready, 실제 HTTP/DB 기능, 공개·비공개 포트, reset·삭제를 확인한다.
4. 정책 파일과 바이너리를 함께 배포하고, 잘못된 digest의 요청이 `422 IMAGE_POLICY_REJECTED`로 거절되는지 확인한다. 기본 정책이 없는 다른 이미지의 기존 Runtime 요청은 그대로 처리된다.

문제별 상세 시험 근거는 작업 공간의 `docs/web-challenge-runtime-handoff.md`에 있다.
