# 런타임 CI/CD

PR에서는 Go·PostgreSQL 검사와 배포 복구 검사를 실행하고 Linux 바이너리를 만듭니다
dev 반영 또는 dev에서 수동 실행하면 같은 실행에서 검사한 바이너리를 서버로 전송합니다
기존 Tailscale 시험 서버의 수동 배포는 별도로 유지합니다

## GitHub 설정

control-production 환경은 dev 브랜치만 허용합니다

| 구분 | 이름 | 내용 |
|---|---|---|
| Variable | DEPLOY_HOST | 런타임 API VM 주소 |
| Secret | DEPLOY_SSH_KEY | 런타임 전용 배포 키 |
| Secret | DEPLOY_KNOWN_HOSTS | 확인한 서버 SSH 호스트 키 |
| Secret | DEPLOY_ENV | 기존 런타임 환경 파일과 DB·비밀값 조회 설정 |
| Secret | DEPLOY_SERVICE_TOKEN | 런타임 서비스 토큰 파일 내용 |

DEPLOY_ENV는 기존 경로를 사용합니다

```dotenv
PROVISIONER_SERVICE_TOKEN_FILE=/etc/secure-provisioner/service-token
PROVISIONER_IMAGE_POLICIES=/etc/secure-provisioner/image-policies.json
```

## 서버 준비와 배포

관리자 계정으로 deploy/bootstrap.py와 release.py, 해당 서버용 공개키를 같은 폴더에 복사하고 한 번 실행합니다

```sh
sudo python3 bootstrap.py runtime --public-key runtime-ci-key.pub
```

배포 계정은 msgctf-deploy이며 SSH 키는 고정된 배포 프로그램만 실행할 수 있습니다
관리자 접속 키와 배포 키를 함께 사용하지 않습니다
배포 프로그램을 수정하면 관리자 계정으로 bootstrap을 다시 실행해야 합니다

배포 후 인증된 Operation 조회의 정상적인 404와 인증 누락·잘못된 토큰의 401을 확인합니다
실패하면 직전 바이너리·환경 파일·토큰·배포 기록을 복원하고 기존 API 응답까지 확인합니다
DB 마이그레이션은 되돌리지 않습니다

K3s registry와 이미지 실행 정책은 서버에 보존하며 CI가 임의로 승인하거나 바꾸지 않습니다
배포 기록은 /opt/secure-provisioner/release.json에서 확인합니다
이 검사는 API 배포 확인이며 실제 문제 생성·삭제 검증은 실행 대상이 준비된 뒤 별도로 진행합니다

새 API 전용 VM은 #50의 빈 registry 지원이 먼저 필요합니다
현재 실행 대상은 0개이고 이미지 실행 정책은 차단 상태이므로 문제를 생성할 수 없습니다
