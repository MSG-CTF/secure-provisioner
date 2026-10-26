# Afterimage 실행 정책과 인수 기준

## 실행 경로

Afterimage는 일반 WEB K3s 프로필로 실행하지 않는다. **기존 전용 VM
프로필**을 사용한다. 서로 다른 팀의 동시 인스턴스에는 각각 별도 VM과
예약이 필요하다. VM 한 대를 여러 팀이 공유하는 구성이 아니다.

- 운영자 입력: `PROVISIONER_VM_TARGETS`의 전용 VM target 카탈로그.
- 예시: [targets.example.json](../../deploy/vm/targets.example.json).
- 실행 프로필: `deploy/vm/profiles/5db3aa5cbee93da4999fb1c6ed07d9425eccb3fc5c1b2209f879838e1839e8a0.json`.
- 서버 정책: `PROVISIONER_IMAGE_POLICIES`의 `vm_required_repositories`.
  저장소 기본 파일은 `config/web-image-policies.json`이다.
- 설치·방화벽·키 분리: [dedicated-vm.md](dedicated-vm.md).

VM 프로필과 target 파일은 이미 구현돼 있었다. 이번 변경은 이 실행 경로를
이미지 저장소에 명시적으로 연결하고, 일반 K3s 실행으로 우회되는 것을 막는다.
운영 파일을 자동 갱신하거나 새 VM을 생성하지 않는다.

## 문제별로 달라지는 실행 설정

| 역할 | 기존 VM 프로필에서 사용하는 설정 | 이유 |
| --- | --- | --- |
| bot | 이미지 기본 사용자(node), 쓰기 가능한 이미지 파일시스템, `/dev/shm` 1GiB | Chromium의 HOME/config/cache 생성이 필요함 |
| indexer | 이미지 기본 사용자(root)인 부모, `cap_drop: ALL` + `SETUID/SETGID`만 추가, read-only rootfs, `no-new-privileges` | 자식 프로세스를 UID/GID 1001로 분리하는 원래 동작을 보존함 |
| indexer 쓰기 경로 | `/tmp` 16MiB, `/var/spool/m13` 1MiB tmpfs, `nosuid,noexec`, spool UID/GID 0, mode 0755 | 원래 spool과 자식 실행 방식을 유지함 |
| indexer / case-vault | 각각 PID 48 / 32 제한, case-vault read-only·capability 전체 제거 | 민감한 역할의 프로세스·파일 접근 범위 제한 |
| portal / core / exporter / inventory-metadata | 기존 이미지 실행 사용자·쓰기 동작 유지 | 문제 소스의 실행 조건 보존 |
| 전체 | `msg-afterimage.slice`, 서비스별 250MB overlay 쓰기 한도, 로그 회전 | VM 합계 CPU/메모리 및 디스크 사용량 제한 |

aggregate 요청 한도는 CPU 2000m, 메모리 4000MiB, 임시 저장소 2048MiB로
target 파일과 정확히 일치해야 한다. 디스크 한도에는 XFS project quota와
Docker overlay2 준비가 필요하다. 단순히 JSON만 복사해서 완료되는 설정은 아니다.

indexer 부모를 UID 1001로 바꿔 `spawn EPERM`만 없애는 수정은 하지 않는다.
부모와 자식을 같은 UID로 만들면 원래 문제의 프로세스·비밀값 분리가 바뀐다.
K3s PSA `restricted`나 STANDARD@v2의 root/capability 제한도 완화하지 않는다.

## 네트워크·FLAG·healthcheck

VM의 Compose bridge 그룹을 그대로 사용한다.

| 그룹 | 소속 서비스 |
| --- | --- |
| edge | portal |
| appnet | portal, core, bot |
| exportnet | portal, exporter, inventory-metadata |
| cartridgenet | portal, indexer |
| vaultnet | core, case-vault |

참가자 공개 포트는 portal만 노출한다(예시 VM 호스트 18080 → 컨테이너 8080).
나머지는 private 서비스다. VM 방화벽에서 외부 egress, 메타데이터와 호스트·관리망
접근을 차단해야 한다. K3s NetworkPolicy가 이 VM을 보호하는 것은 아니다.
PR #49의 선택적 K3s network graph와도 별도 계약이다.

호출자는 `target.runtime_type: "VM"`, 등록된 `target_id`, 정확한 7개 digest,
컨테이너 이름·포트·리소스, 전체 일반 환경변수와 역할별 Backend `secret_ref`를
전달한다. 승인된 구성은 target 예시 파일의 각 `containers[]` 항목에 있다.
`internal_connections`, 임의 capability, root 실행 예외를 요청에 추가하지 않는다.
`run_as_user`와 `/tmp` 힌트는 호환용이고 실제 권한은 trusted VM 프로필이 결정한다.

비밀값은 Backend 참조를 생성 직전에 조회해 SSH stdin으로 전달하고 `/run` tmpfs의
Compose 설정에만 넣는다. FLAG는 case-vault에만 주입한다. 프로필·정책·PR·로그에
실제 FLAG나 토큰 값을 기록하지 않는다. VM 준비 상태는 기존 guest helper의
서비스 상태/Compose healthcheck 계약을 따른다. 이번 PR에서 요청형 HTTP probe를
새 VM 기능으로 추가하지 않는다.

## 잘못된 K3s 실행 차단

`vm_required_repositories`는 `managed_repositories`의 부분집합이며 중복을
허용하지 않는다. 같은 저장소에 일반 K3s 이미지 정책 행을 함께 선언하면 시작 시
설정 오류로 거절한다. target에서 잠시 VM을 제거해도 이 목록은 유지한다.

1. VM 카탈로그에 포함된 이미지 저장소는 자동으로 VM 전용이 된다.
2. 운영자 이미지 정책의 목록도 별도로 적용된다. VM target이 없어도 보호된다.
3. 다른 K3s target, legacy `workload.image`, `containers[]`, 새 digest와 tag 모두
   저장소 단위로 차단한다. tag는 원래 immutable image 검증에서도 허용하지 않는다.
   `ghcr.io:443`, `ghcr.io.`와 같은 동일 호스트 표기도 정규화해 차단한다.
   운영자 `managed_repositories` 키는 정규 호스트 표기로 작성해야 한다.
4. HTTP에서는 `VM_POLICY_REJECTED` 또는 `IMAGE_POLICY_REJECTED`(422)로 거절한다.
   이전 버전에서 접수된 K3s 생성 명령도 worker에서 `VM_POLICY_REJECTED`로 차단한다.
5. 이전 worker가 만든 Namespace는 먼저 기존 소유권·operation·UID 검증을 거쳐
   정리한다. Namespace 부재를 확인하지 못하면 정리 완료로 표시하지 않는다.
6. VM 요청은 계속 정확한 target/profile/digest 조합만 허용한다. 새 이미지 digest를
   발행했다고 자동 승인되는 것은 아니다.

## 2026-10-23 K3s 진단 결과

진단 기준 Runtime은 `a4c1f47d5a96f44222c87cc3fd458943771a61b7`이며,
별도 lab에서 PR #49 리소스 빌더로 생성한 7개 실제 Afterimage 이미지를 검사했다.
Runtime API·Backend Secret·Scheduler를 경유한 전용 VM E2E 시험은 아니다.

- 7개 Pod가 health 응답과 Ready 상태를 보였고 최초 실행은 모두 cold pull이었다.
  실행 imageID는 요청 digest와 일치했다.
- 서비스 간 허용·차단, Namespace 밖 ingress/egress, 외부 egress, UDP를 포함한
  네트워크 검사 **114/114 통과**(허용 34, 차단 80), DNS 7/7 통과.
- 그러나 bot의 실제 Chromium 실행은 HOME/config 경로의 read-only 제약으로
  실패했다. Chrome 자식 환경만 `HOME=/tmp`, `XDG_CONFIG_HOME=/tmp/.config`,
  `XDG_CACHE_HOME=/tmp/.cache`로 바꾼 진단 실행은 성공했다. 전체 bot 작업 성공의
  증거는 아니며, 이미 쓰기 가능한 기존 VM 프로필을 바꿔야 한다는 근거도 아니다.
- indexer는 `/health`와 달리 정상 입력의 `/run`이 `spawn EPERM`으로 실패했다.
  K3s의 non-root/capability 제거 상태에서 UID 전환을 할 수 없기 때문이다.
- lab 노드 `podPidsLimit=-1`, Pod의 `pids.max=17351`이었다. Registry의 true 선언과
  일치하지 않는다. 노드 PID 256 설정·검증은 별도 작업이며 이번 PR로 해결되지 않는다.
- **2026-10-23 10:59:22 UTC** 확인: 시험 Namespace
  `ctf-6608102a79b1483ba02430837932eb21`, 진단 Namespace
  `qa-afterimage-peer-6608102a` 모두 부재, 잔여 namespaced 리소스와 live Pod 0.
  이미지 캐시는 유지했다. 운영 바이너리와 정책은 변경하지 않았다.

7개 고정 digest의 원본은 위 target 예시와 SHA 고정 VM 프로필에서 확인한다.
2026-10-20의 전용 VM solver 88/88 기록은 기존 운영 문서의 과거 증거이며,
이번 K3s 진단이나 이번 PR의 새로운 E2E 결과로 계산하지 않는다.

## 반영 순서·롤백·남은 검증

1. 코드 검사 후 Runtime 바이너리를 먼저 반영한다. 이전 바이너리는 새
   `vm_required_repositories` 필드를 모르면 정책 파일 전체를 거절한다.
2. 현재 운영자 정책을 백업하고 VM 전용 목록을 병합한다. 저장소 기본 정책을
   그대로 덮어써 다른 승인 digest·CI 범위를 잃지 않도록 한다.
3. 시작 시 정책 파싱, 잘못된 K3s 요청의 422, 올바른 VM 요청의 접수를 확인한다.
   기존 VM 예약·리소스를 먼저 확인한 뒤 별도 QA 인스턴스로 시험한다.
4. VM 이미지·프로필 변경은 drain 후 새 SHA 프로필, target, Backend release를
   함께 검토한다. 승인 대상 VM에 새 이미지를 미리 pull하고 자격증명은 남기지 않는다.
5. 배포 롤백은 저장해 둔 바이너리와 호환되는 정책 파일을 함께 복원한다.
   새 바이너리를 유지하면서 VM target만 철회할 때는 VM 전용 목록을 지우지 않는다.
   이전 바이너리로 되돌리면 이번 K3s 오실행 방어가 사라지므로 배치에서 VM만 허용하고
   K3s 오배치 요청을 중단한 상태에서 되돌려야 한다.

실제 참가자 공개 경로, 전체 bot/indexer 기능과 solver, 정상·실패 health 상태,
재시작/삭제 후 VM·예약 정리는 전용 VM 경로로 다시 시험해야 한다.
이번 PR 생성은 운영 배포나 해당 E2E 완료를 의미하지 않는다.
