# GCP 개발 K3s 복구와 격리 검증 순서

## 2026-09-28 관찰

- 단일 노드는 Kubernetes API에서 `Ready`로 보이지만 `k3s.service`는
  `activating/start`, 재시작 횟수 476회였다.
- API 서버 로그는 암호화된 `kube-system/chart-values-traefik` Secret을
  `identity transformer`로 읽으려다 실패한다고 반복한다.
- `/var/lib/rancher/k3s/server/cred/encryption-config.json`은 존재한다.
  `/etc/rancher/k3s/config.yaml`은 `kubelet-arg`만 남아 있고, 파일 수정 시각은
  암호화 설정 파일 생성 시각보다 늦다. 과거
  `scripts/configure-gcp-k3s-pwn.sh`가 기본 설정 파일을 덮어쓴 것이 유력한 원인이다.
- 루트 디스크는 8.7 GiB 중 약 950 MiB만 남았다. 이 상태에서 이미지 pull 시험이나
  새 workload를 시작하지 않는다.

Kubernetes의 `Node Ready` 결과만으로 API 서버와 Secret 저장소의 정상 동작을
판정하지 않는다. 복구 전에는 이 target을 운영용으로 승인하지 않는다.
`scripts/configure-gcp-k3s-pwn.sh`는 설치 전에 K3s 서비스와 Secret API를
확인하며, 둘 중 하나라도 실패하면 패키지 설치와 K3s 재시작을 시작하지 않는다.

## 복구 전 보존할 것

1. GCP 부팅 디스크 snapshot 또는 동등한 외부 백업을 만든다. VM 안의 복사본은
   디스크 장애에 대한 백업이 아니다.
2. K3s의 SQLite datastore 디렉터리, 서버 token,
   `server/cred/encryption-config.json`, 현재 K3s 설정과 systemd unit을
   소유자만 읽을 수 있는 위치에 함께 보존한다. token과 암호화 키의 원문을
   로그나 이슈에 붙이지 않는다.
3. 대상 VM, 백업 식별자, 현재 설정 파일과 서비스 인자를 기록한다. 다른 VM의
   token이나 암호화 설정으로 바꾸지 않는다.

[K3s의 SQLite 백업 문서](https://docs.k3s.io/datastore/backup-restore)는 datastore와
서버 token을 함께 보존하도록 요구한다. 암호화 설정도 이번 복구의 핵심 자료다.

## 설정 복원과 판정

백업을 확인한 다음, 기존 `config.yaml`을 다시 쓰지 말고 K3s 설정 drop-in에
`secrets-encryption: true`를 복원한다. 이 설정은 기존 암호화 키를 가진 서버에만
적용한다. 변경된 systemd unit이 있으면 `daemon-reload` 뒤 K3s를 재시작한다.
설정 파일의 백업과 새 drop-in 경로를 기록해 롤백할 수 있게 한다.

재시작 후 아래가 모두 확인되어야 복구가 끝난다.

- `k3s.service`가 `active`이고 재시작 횟수가 계속 증가하지 않는다.
- `k3s secrets-encrypt status`가 정상적으로 응답한다.
- `kubectl get secrets -n kube-system`이 성공한다. Secret 내용은 출력하지 않는다.
- Node와 시스템 Pod가 Ready이며, 기존 Runtime Namespace도 확인한다.
- 디스크 여유를 늘리고 로그 증가 원인을 해결한 뒤 이미지 pull 시험을 시작한다.

하나라도 실패하면 추가로 키를 회전하거나 Secret을 삭제하지 않는다. 보존한
설정과 datastore로 돌아갈 수 있는 상태를 유지하고 실패 로그의 원인만 조사한다.
[K3s 암호화 키 회전 문서](https://docs.k3s.io/cli/secrets-encrypt)는 절차 오류가
클러스터를 영구 손상시킬 수 있다고 경고한다.

## 복구 후 GCP 검증

1. `scripts/test-k3s-isolation-config.sh`와
   `scripts/test-gvisor-containerd-template.sh`,
   `scripts/test-k3s-bootstrap-preflight.sh`로 bootstrap 렌더링과 차단 검사를
   검사한다. 실제 설치 전에는 `scripts/check-k3s-before-bootstrap.sh`도
   대상 노드에서 성공해야 한다.
   `scripts/configure-gcp-k3s-pwn.sh`는 재시작 후에도 같은 Secret API 검사를
   통과해야 완료를 알린다. containerd 템플릿은 생성된 `config.toml`의 v2/v3
   버전에 맞는 활성 템플릿만 수정하며 버전이 불분명하면 중단한다.
   gVisor smoke는 digest 고정 이미지로 고유한 임시 Namespace에서 실행하고
   성공·실패 시 해당 Namespace만 삭제한다. 이미 존재하는 `gvisor` RuntimeClass의
   handler가 `runsc`와 다르면 중단한다. `pod-max-pids` 파일 설정과 실제 fork
   상한은 별개이므로 라이브 PID 제한 시험 전에는 격리 완료로 판정하지 않는다.
2. `docs/testing/instance-network.md`의 digest 고정 fixture로 동일 인스턴스
   양방향 연결, 다른 인스턴스 차단, 공개 포트 및 Namespace 정리를 실제 GCP
   target에서 실행한다.
3. GHCR cold pull·인증 실패와 revision 보존은
   `docs/testing/ghcr-pull.md`의 별도 시나리오로 증거를 남긴다.
4. PWN/gVisor 실행, PID 상한, Admission, 인터넷 egress 및 노드 metadata 경계는
   각각 시험하고 통과한 기능만 Target Registry에 선언한다.
