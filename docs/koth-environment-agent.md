# KOTH 전용 VM 환경변수 적용

이 에이전트는 관리자에서 선택한 환경변수 버전만 고정된 K3s Deployment에 반영한다
문제 코드, 이미지, 네트워크 정책, 자원 제한과 PVC는 교체하지 않는다
현재 값이 같으면 Pod를 재시작하지 않고 적용을 확인한다
이때 관리 중인 변수 전체가 같은지 대조하며 이전 버전에만 있는 변수가 남아 있으면 새 설정으로 교체한다
설정하지 않음은 플랫폼에서 해당 값을 주입하지 않고 출제자 이미지·프로그램의 기본 동작을 따르는 의미다

## 설치

운영자가 검증한 배포 기준으로 root 전용 설정을 작성한다
예시의 값은 실제 비밀값을 포함하지 않는다

    {
      "schema_version": 1,
      "target_id": "gcp:123456789",
      "base_url": "https://msgctf.kr/internal/v1/koth_environments",
      "games": [{
        "challenge_id": "12345678-1234-1234-1234-123456789abc",
        "namespace": "koth-example",
        "deployment": "game",
        "source_revision": "40자리 소스 커밋",
        "token": "이 문제의 에이전트 전용 토큰",
        "containers": {
          "service": {
            "image": "ghcr.io/승인된경로@sha256:64자리digest",
            "managed_secrets": ["runtime-env"],
            "protected": { "INTERNAL_TOKEN": "HMAC-SHA256(에이전트토큰, 기존연동값)" }
          }
        }
      }]
    }

에이전트 토큰은 게임 인증·점수 조회 토큰과 구분하고 문제마다 다르게 발급한다
백엔드에는 같은 토큰의 SHA-256만 등록한다
protected에는 보호된 연동값의 HMAC을 등록해 백엔드에서 잘못 연결한 값도 VM에서 차단한다
managed_secrets에는 기존 Deployment에서 사용하는 환경변수 전용 Secret만 적는다

- 에이전트 파일: /opt/msgctf-koth/koth_environment_agent.py, root 소유 0755
- 설정: /etc/msgctf-koth-environment/agent.json, root 소유 0600
- 상태: /var/lib/msgctf-koth-environment, root 소유 0700
- 서비스: deploy/koth-environment-agent.service

systemd 서비스를 설치하고 daemon-reload 후 활성화한다
VM 전원을 껐을 때는 적용 대기로 남고 다음 부팅 때 이어서 확인한다
경기 시작 전에는 관리자에서 적용 확인과 최근 VM 확인 시각을 확인한다

## 적용과 복구

15초마다 문제별로 조회하며 변경 없는 응답에는 환경변수를 다시 받지 않는다
로그는 문제 식별자와 상태가 바뀔 때만 기록하고 환경변수·응답 본문·원격 명령 출력을 남기지 않는다
정상 조회의 백엔드 확인 시각 갱신도 1분에 한 번으로 제한한다

변경할 설정은 적용 요청별 불변 Secret에 저장하고 Pod template의 환경변수 참조만 조건부 교체한다
90초 안에 준비 상태와 실제 프로세스 값이 확인되지 않으면 이전 template으로 복구한다
다른 운영 작업이 template을 바꿨다면 이를 덮어쓰지 않고 복구 충돌로 보고한다
경기 진행 중인 요청이나 고정 VM·이미지·소스·연동값이 다른 요청은 적용하지 않는다

적용 전후 단계를 fsync한 journal로 남긴다
프로세스가 중단되거나 적용 완료 응답이 유실돼도 같은 요청을 재확인하며 중복 rollout을 시작하지 않는다
실패한 요청은 자동으로 반복하지 않고 관리자가 새 적용을 요청해야 재시도한다
롤백에 필요한 ReplicaSet·Pod가 참조하는 Secret은 유지하고 참조가 없는 자체 생성 Secret만 10분마다 정리한다
기존 Secret과 PVC·볼륨·게임 데이터는 삭제하지 않는다

백엔드 계약은 docs/koth-environment.v1.json과 동일하다
