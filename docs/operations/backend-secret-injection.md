# 백엔드 비밀값 주입

FLAG 관리 주체를 백엔드로 옮깁니다
스케줄러 요청에는 일반 env와 승인된 릴리스 컨테이너의 secret_ref만 담습니다
런타임 worker는 실행 직전에 백엔드에서 값을 조회해 변경 불가 Kubernetes Secret으로 주입합니다

## 2026-10-15 배포 상태

현재 `younhochoi`의 운영 Runtime은 구형 FLAG 파일 계약을 유지하는 hotfix `47d2c3e74704a8466809acfdfb6ffe98aa34e068`입니다. 바이너리 SHA-256은 `66e67d39eb9d1c9a0bfcb8b1432a1053630df75b8ded9c97d8c0e1c95d23e070`입니다. 이 서버는 요청의 `env`·`secret_ref`를 아직 받지 않습니다. 이 문서의 새 계약은 Runtime PR #47에서 구현됐으며, Backend PR #101과 Scheduler PR #63의 전환을 기다리고 있습니다. 현재 서버의 이미지 정책 SHA-256은 `ecdaade386a7cbdd4f3edbce76986be4d5642ee712859b4eeadd83ec1516e898`이며 저장소 정책 파일로 무조건 덮어쓰지 않습니다.

PR #47을 별도 DB·포트와 임시 Target으로 띄운 실제 K3s 시험에서 정상 HTTP healthcheck의 생성·접속·삭제, 실패 healthcheck의 `WORKLOAD_NOT_READY` 및 namespace 정리, 일반 `env`와 `secret_ref`의 Kubernetes Secret 주입을 확인했습니다. 이때 Backend 응답은 별도 loopback 시험 서버로 대체했으므로 실제 Backend #101의 운영 인증·비밀값 등록까지 검증한 결과는 아닙니다. 운영 서비스와 DB는 이 시험에서 변경하지 않았습니다.

운영 전환 시에는 Scheduler의 `exposed-ports-enabled`와 `healthcheck-enabled`를 모두 켜야 합니다. 전자는 공개 포트 계약을, 후자는 검사 결과를 Runtime에 전달합니다. 둘 다 기본값은 꺼져 있습니다. Backend 비밀값 API·암호화 키·문제별 값·전용 조회 토큰과 정확한 이미지 digest 정책을 준비한 뒤 아래 순서로 전환합니다.

수동 배포 워크플로는 `dev` 브랜치와 GitHub Environment `runtime-test`에서만 실행합니다. Environment 변수 `PROVISIONER_DEPLOY_SSH_HOST`, `PROVISIONER_DEPLOY_SSH_USER`, `PROVISIONER_TAILSCALE_TAGS`와 Secret `PROVISIONER_DEPLOY_SSH_HOST_KEY`, `PROVISIONER_SSH_PRIVATE_KEY`, `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET`을 설정해야 합니다. 이 값들은 현재 워크플로에 등록된 것으로 간주하지 않습니다. 승인된 현재 서버 정책 SHA-256을 실행 입력으로 넣고, 새 환경 파일·정책을 적용할 때는 서버에 미리 준비한 절대 경로와 새 정책 SHA-256을 함께 입력합니다. 환경 파일 후보는 현재 파일과 같은 소유자이며 group/other 접근이 없어야 합니다. 스크립트는 정책 드리프트나 인증된 API 확인 실패 시 바이너리·환경·정책을 복구합니다. 기존 FLAG 설정 그대로 PR #47을 배포하면 기동 확인에 실패하고 복구됩니다.

| 설정 | 용도 |
| --- | --- |
| PROVISIONER_BACKEND_SECRET_URL | 백엔드 origin, 운영은 HTTPS, 로컬 시험은 리터럴 loopback HTTP 허용 |
| PROVISIONER_BACKEND_SECRET_TOKEN | 백엔드 조회 전용 Bearer 토큰 |
| PROVISIONER_IMAGE_POLICIES | 승인 digest·UID·포트·쓰기 경로와 requires_flag 유지 |

PROVISIONER_FLAG_FILE은 제거합니다
이 값이 남아 있으면 런타임이 시작되지 않습니다
백엔드 조회 설정이 없는데 활성 이미지가 FLAG를 요구해도 시작되지 않습니다
구형 대기 요청도 worker가 현재 FLAG 요구 목록과 대조해 참조 없이는 실행하지 않습니다

## 전달 계약

| Runtime 컨테이너 필드 | 의미 |
| --- | --- |
| env | 일반 환경변수의 이름과 문자열 값 |
| secret_ref | 백엔드 릴리스 컨테이너의 UUID, 요청자는 조회 URL·비밀값 원문을 지정할 수 없음 |

조회 경로는 /internal/v1/runtime-secrets/resolve로 고정합니다
참조·컨테이너 이름·정확한 이미지 digest를 함께 확인합니다
프록시와 리다이렉트를 사용하지 않으며 응답 크기·시간을 제한합니다
조회 오류의 응답 body나 토큰을 로그·에러에 넣지 않습니다

일반 env와 비밀값을 합쳐 컨테이너당 128개, 값당 UTF-8 4096바이트, 이름과 값의 합계 16384바이트까지 허용합니다
일반 값은 Kubernetes 변수 보간 없이 그대로 주입합니다
이름 충돌·누락·형식 오류는 Kubernetes 리소스를 만들기 전에 실패합니다

Secret 이름은 challenge-env이며 키는 컨테이너 이름과 환경변수 이름으로 나눕니다
각 컨테이너에는 자신의 키만 secretKeyRef로 연결합니다
원문은 Operation DB·Deployment spec에 저장하지 않으며 namespace 삭제 시 Secret도 지워집니다
운영 클러스터의 Secret 암호화·etcd 접근 제한은 별도 인프라 설정입니다

## 전환 순서

1) FLAG 문제의 신규 생성·reset을 잠시 중단하고 기존 대기 요청을 정리합니다
2) 백엔드 마이그레이션·암호화 키·전용 토큰을 준비하고 문제별 비밀값을 등록합니다
3) Runtime 조회 설정을 연결하고 기존 FLAG 파일 환경 설정을 제거합니다
4) 새 스케줄러를 배포한 뒤 schema 2.1 릴리스를 등록·활성화합니다
5) 생성·접속·reset·삭제를 확인한 뒤 FLAG 문제의 요청을 재개합니다

설정을 바꿔도 이미 실행 중인 Pod의 값은 자동 교체되지 않습니다
기존 namespace를 새 형식으로 덮어쓰지 않습니다
구형 릴리스로 롤백하려면 FLAG 주입 계약도 함께 맞춰야 합니다

현재 비밀값은 릴리스에 고정된 버전입니다
AFTERIMAGE의 인스턴스별 비밀값 생성, Notebook의 DB 경로, 문제별 외부 통신 허용은 이 변경의 완료 범위에 포함되지 않습니다
이미지 차단과 STANDARD@v2의 기본 차단·DNS·같은 인스턴스 통신 정책을 유지합니다

검사: [비밀값 조회](../../internal/k3s/backend_secrets_test.go), [주입·구형 요청](../../internal/k3s/secret_resources_test.go)
