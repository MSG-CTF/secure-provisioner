# PSA restricted 적용 및 검증 — 2026-10-04

> 이 문서는 10월 4일의 시험 기록이다. 이후 10월 6일 두 K3s 노드의 kubelet `podPidsLimit`을 256으로 변경했고, Runtime 시험 배포 커밋은 `d806276e328a6e58611ebb875c2e186dd79448b7`이다. 아래 `podPidsLimit=-1` 및 배포 커밋은 당시의 값이다. PID 변경과 남은 운영 조건의 현재 상태는 작업 공간의 `docs/k3s-runtime-target-installation-final.md`를 참고한다.

## 적용한 변경

Provisioner가 새 문제 Namespace를 만들 때 다음 세 라벨을 함께 설정한다.

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted
```

`enforce`는 위반 Pod의 생성·변경을 거절하며, `audit`와 `warn`은 감사·경고 모드다. 세 라벨은 Namespace에만 설정한다. ServiceAccount, NetworkPolicy, Deployment, Pod의 소유권 라벨에는 추가하지 않는다. 기준 버전 라벨은 지정하지 않았으므로 클러스터의 기본 `latest` 기준을 따른다. K3s 업그레이드 전 호환성 검증이 필요하다. [Kubernetes PSA 문서](https://kubernetes.io/docs/concepts/security/pod-security-admission/)

Namespace 생성 응답에서 라벨이 누락되거나 바뀌면 하위 리소스를 생성하지 않고, 해당 요청이 만든 Namespace를 UID와 resourceVersion 조건으로 정리한다. 최종 조회에서 라벨 변경을 발견하면 생성 성공을 반환하지 않는다. 기존 소유권 충돌 처리에 따라 해당 Namespace를 보존하므로 운영자 확인이 필요하다. 지속적인 라벨 복구 컨트롤러를 추가한 것은 아니다.

## 배포 기록

- VM: `provisioner-test-1`, GCP `us-central1-c`
- 코드 커밋: `1e3f8ac901eaf7caf082042fbfe7e8238d2d7176`
- 작업 브랜치: `fix/psa-restricted-namespaces` (이번 작업에서 GitHub push/병합은 수행하지 않음)
- Linux/AMD64 바이너리 SHA-256: `ac403c4a416ac3b54aa43d3f775a2fea80abf3549a8283d3b6b1f875cf68d489`
- Go `1.26.5`, `CGO_ENABLED=0`, `-buildvcs=false`
- 배포 메타데이터: VM `/opt/secure-provisioner/release.json`
- 이미지별 실행정책·FLAG 지원을 포함한 기존 배포 코드를 기반으로 수정했다. 환경 파일, Registry, FLAG 파일의 체크섬 불변을 확인했다.

## 검증 결과

| 검증 | 결과 |
| --- | --- |
| 회귀 테스트 | 변경 전 신규 builder 테스트가 PSA 라벨 누락으로 실패. 변경 후 전체 11개 Go 패키지 테스트 통과 |
| 실패 시 처리 | 세 PSA 라벨 각각의 삭제·변조 6건: 하위 생성 중단 및 UID/resourceVersion 조건 삭제. 최종 조회 변조 6건: 성공 거부 및 기존 충돌 보존 처리 |
| 빌드·정적 검사 | `go vet ./...`, `git diff --check`, Linux/AMD64 빌드 통과 |
| `broker-test2` 실제 문제 | 생성 `SUCCEEDED`, `READY`, endpoint ready, Pod Running·재시작 0 |
| `broker-test-3` 실제 문제 | 동일하게 통과 |
| 실제 새 Namespace | 두 타깃 모두 enforce/audit/warn `restricted` 확인 |
| 실제 Pod 보안 설정 | token automount 꺼짐, Strict 그룹, RuntimeDefault seccomp, 권한 상승 금지, 읽기 전용 root, capability ALL drop 확인 |
| NetworkPolicy 리소스 | default-deny-all, allow-dns, allow-instance-internal, allow-public-ingress-web 확인 |
| PSA 정상 Pod dry-run | 실제 Pod spec과 PSA 라벨을 복사한 별도 시험 Namespace에서 두 타깃 모두 `201` |
| PSA 위반 dry-run | 권한 상승 허용, UID 0, Unconfined seccomp, NET_ADMIN 추가를 각각 시험해 모두 `403`·PodSecurity 사유 확인 |
| 실제 문제 Namespace admission | 두 타깃의 실제 문제 Pod에 ephemeral container 추가를 `dryRun=All`로 제출. 준수 설정 `200`, 같은 네 위반은 각각 `403`·PodSecurity 사유. 재조회에서 컨테이너 미저장·기존 Pod UID 동일 확인 |
| 시험 정리 | 두 Runtime 삭제 `SUCCEEDED`, 해당 Namespace 및 admission 시험 Namespace 삭제 후 `404` 확인 |
| 기존 문제 보완 | 기존 Grade Namespace에도 세 라벨 적용. Pod UID 동일·Ready 확인, 기존 공개 `/login` HTTP `200` |
| API·기존 정책 | 서비스 active, 인증 API 접근 확인, 공개 무인증 API `401`, 차단 중인 Logout 이미지 `422 IMAGE_POLICY_REJECTED` 유지 |

Windows에서 첫 전체 테스트는 패키지 모두 통과했지만 종료 시 임시 EXE 파일 잠금으로 Go 정리가 실패했다. `go test -work -count=1 ./...`로 다시 실행해 종료 코드 0을 확인했다.

Pod 생성의 PSA 거부 시험은 Pod quota가 결과를 가리지 않도록 별도의 빈 Namespace에서 진행했다. 실제 Runtime Namespace에서 확인한 라벨과 실제 문제 Pod spec을 사용했고, ServiceAccount만 시험용으로 바꿨다. 추가로 **실제 문제 Namespace**의 기존 Pod에 `/ephemeralcontainers?dryRun=All` 업데이트를 제출해 정상 설정 허용과 네 위반 거부를 확인했다. 모든 위반 요청은 서버 측 dry-run으로만 제출하여 실행하지 않았다. NetworkPolicy 항목은 이번 변경 후 리소스 확인이며, 네트워크 차단의 실제 통신 시험은 앞선 격리 감사 기록에 있다.

실제 생성·삭제에 사용한 인스턴스:

- `broker-test2`: `9a865344-a22e-49c8-a6da-f78409664693`
- `broker-test-3`: `164c2476-40c7-407f-9376-8bc0c08593b0`
- `broker-test-3` 실제 Namespace admission 추가 시험: `8cb51642-9dab-42ae-9ab5-109740c23f73` (생성·READY·삭제 성공, Namespace `404`)
- 유지한 기존 Namespace: `ctf-47633385bb7548748d48cd36b8c0fb56`

워크스페이스 검증 스크립트: `.scratch/psa-live-validation.py`, 실제 Namespace 추가 검증은 `--actual-admission`. 최종 배포 메타데이터·바이너리 일치, 이미지 정책 체크섬 불변과 FLAG 값 목록 0개를 재확인했다. 토큰·인증서·FLAG 원문은 출력하지 않았다.

## 남은 운영 조건

- 두 노드의 `podPidsLimit=-1`: PID 제한 설치·설정은 아직 필요하다. Registry의 `pod_pid_limit_enforced=true`와 실제 상태가 불일치한다.
- 두 타깃에 `RuntimeClass/gvisor`가 없다. PWN용 runsc·shim·containerd 연결 및 실행 검증은 별도 작업이다.
- 공개 NodePort에는 팀 인증 게이트웨이가 없다. PSA 적용으로 팀별 접속 인증이 생기지는 않는다.
- 기존 운영 FLAG 목록은 비어 있다. 이번 시험은 Grade 실행과 PSA 검증이며 모든 문제의 FLAG·풀이·채점 검증 완료를 의미하지 않는다.

따라서 **PSA 누락은 수정·배포·검증 완료**이며, 전체 격리의 운영 승인과는 구분한다.
