# 백엔드 비밀값 주입

FLAG 관리 주체를 백엔드로 옮깁니다
스케줄러 요청에는 일반 env와 승인된 릴리스 컨테이너의 secret_ref만 담습니다
런타임 worker는 실행 직전에 백엔드에서 값을 조회해 변경 불가 Kubernetes Secret으로 주입합니다

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

일반 env와 비밀값을 합쳐 컨테이너당 32개, 값당 UTF-8 4096바이트, 이름과 값의 합계 16384바이트까지 허용합니다
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
