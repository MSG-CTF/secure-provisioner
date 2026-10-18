# PWN 발행 이미지 실행

PWN은 실제 gVisor와 NODE_PORT를 지원하는 노드에서 실행합니다
정책만 gvisor로 표시해 두고 일반 컨테이너로 실행하지 않습니다

Python 3.12 이상인 Linux x86_64 K3s 노드에서 아래 명령으로 고정 버전의 gVisor를 설치합니다
공식 배포 파일의 SHA-512를 확인하고, 기존 설정이 다르면 덮어쓰지 않습니다
문제 Pod가 남아 있으면 K3s 재시작 전에 중단합니다

```sh
sudo python3 deploy/bootstrap_gvisor.py
```

이 명령은 RuntimeClass까지 만들며 타깃 Registry의 지원 여부는 바꾸지 않습니다
실제 gVisor Pod에서 dmesg, TCP 응답, CPU·메모리·PID 제한을 확인한 뒤 해당 타깃의 security_capabilities.runtime_classes에 gvisor를 추가합니다
이후 Runtime을 재시작합니다

[공식 설치 안내](https://gvisor.dev/docs/user_guide/install/)와 [containerd 설정 안내](https://gvisor.dev/docs/user_guide/containerd/quick_start/)를 기준으로 구성했습니다
KVM 장치가 없는 검증 VM에서는 systrap을 사용하며 systemd cgroup을 적용합니다

문제 파일과 이미지는 바꾸지 않습니다
관리자는 승인된 릴리스에 FLAG 비밀값 참조를 저장하고, Runtime은 정확한 이미지 digest의 [PWN 정책](../../config/pwn-image-policies.json)을 적용합니다

| 문제 | UID | 공개 포트 | FLAG 전달 |
| --- | --- | --- | --- |
| random6 | 31337 | 6666 | 환경변수 |
| Simple Note | 1001 | 9999 | /home/ctf/flag.txt |
| Ghost File | 1000 | 31337 | /flag |
| price-tag | 1000 | 9999 | /home/player/flag.txt |

기존 WEB 문제도 함께 운영하면 현재 호스트 정책을 보존하고 PWN 정책의 managed_repositories와 images를 합쳐 적용합니다
PROVISIONER_IMAGE_POLICIES는 합친 정책 파일을 가리켜야 합니다
운영 설정과 비밀값은 Git에 넣지 않습니다
새 Runtime 바이너리가 기존 정책으로 정상 기동한 뒤 파일 주입 정책을 적용합니다
이전 바이너리로 되돌릴 때는 함께 백업한 이미지 정책도 복원해야 합니다

flag_file_path는 운영자 정책에만 있습니다
백엔드·스케줄러의 생성 요청에는 기존 secret_ref만 전달하며, 참가자는 파일 경로나 Kubernetes 보안 설정을 고를 수 없습니다
Runtime은 해당 컨테이너의 FLAG 키만 immutable Secret에서 읽기 전용 파일로 연결합니다
그 파일은 이미지의 기존 플래그 파일을 가리던 위치에 놓이며, 컨테이너 UID의 그룹만 읽을 수 있습니다
다른 비밀값과 다른 컨테이너에는 파일을 붙이지 않습니다

root 권한, SUID 권한 상승, 추가 capability는 허용하지 않습니다
파일 경로도 immutable 명세 해시에 포함하며, 이전 큐의 명령이 현재 파일 주입 정책을 빠뜨리면 Namespace 생성 전에 거절합니다

2026-10-18 검증은 별도 검증용 백엔드·실제 브로커, 배포된 스케줄러, 수정한 Runtime 후보 바이너리와 실제 K3s·gVisor를 사용했습니다
발행 이미지 네 개는 소스 revision 1dea73b652f9eeb98204c1fda7f66b9afb89505d의 기존 GHCR digest를 고정했습니다
기본 이미지 플래그와 다른 값을 백엔드에 등록해 실제 주입 여부를 구분했습니다
컨테이너형 PWN을 대상으로 하며 커널 VM 문제인 msgdriver와 공식 풀이·채점 검증은 포함하지 않습니다
