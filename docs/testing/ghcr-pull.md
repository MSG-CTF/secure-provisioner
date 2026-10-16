# GHCR 이미지 공급 계약과 실환경 Pull 수용 기준

관련 이슈: #30, #11, #27. 이 문서 추가만으로 #30을 종료하지 않는다.

## 결정된 공급 계약

- 원본 OCI Registry는 GHCR이다.
- CI가 문제의 `build:` 및 외부 `image:`를 검사하고 MSG-CTF GHCR에 발행하여 digest를 확정한다.
- Challenge Registry는 승인된 revision과 digest를 저장한다. 등록 계약은 msg-backend#19에서 관리한다.
- Scheduler가 선택한 revision의 `image@sha256:<digest>`를 Runtime으로 전달한다.
- Runtime은 Dockerfile 빌드나 Registry 재선택을 하지 않고 선택된 target에 배포한다.
- Pod의 `imagePullPolicy`는 `IfNotPresent`다. 전체 노드 pre-pull은 필수 조건이 아니다.
- 실행 중인 workload의 image digest를 새 발행 revision으로 자동 교체하지 않는다.

## 검증 준비

DevSecOps/운영 담당자와 개발 전용 target_id, 접근 방법, 배포 Runtime commit,
GHCR 테스트 package/revision/digest, 해당 image의 architecture를 확인한다.
정상 CI smoke에는 아래 값이 필요하다.

| 위치 | 설정 |
|---|---|
| GitHub Secret | `AWS_ROLE_TO_ASSUME`, `AWS_REGION`, `AWS_K3S_INSTANCE_ID`, `AWS_CD_ARTIFACT_BUCKET` |
| GitHub Variable | `RUNTIME_TARGET_ID`, `ENABLE_RUNTIME_SMOKE=true` |
| 대상 노드 | 실행 중인 Provisioner, `/etc/secure-provisioner/service-token`, GHCR pull credential |

토큰은 노드에서만 읽는다. kubeconfig·인증값·registry 인증 원문은 결과물에 넣지 않는다.
CI의 OIDC → S3 staging → SSM → loopback Runtime API 경로와 Scheduler 운영 요청
경로는 서로 다른 검증이다. 한쪽 성공으로 다른 쪽까지 완료 처리하지 않는다.

K3s의 node-wide registry 인증 또는 사전 구성된 ServiceAccount/Pod imagePullSecret 중
운영 방식과 회전 주체를 확인한다. Runtime API는 pull credential 입력을 받지 않는다.
신규 Namespace의 `challenge-runtime` ServiceAccount에 credential이 실제로 적용되는지
확인한다. 다른 Namespace의 Secret이 자동으로 사용된다고 가정하지 않는다.

## 실행 시나리오

| 시나리오 | 선행 조건 | 반드시 남길 증거 |
|---|---|---|
| 정상 cold pull | 새 개발 노드 또는 테스트 image가 CRI 캐시에 없음을 확인한 노드 | 생성 전 해당 digest 부재, Pull 성공, 실제 imageID, create `SUCCEEDED`, delete `SUCCEEDED`, Namespace 제거 |
| 캐시 재사용 | 앞 단계와 같은 digest, `IfNotPresent` 유지 | 동일 digest 및 정상 생성·삭제. 단순 속도 차이만으로 캐시 사용을 확정하지 않음 |
| GHCR 인증 실패 | 존재와 digest를 별도 정상 인증으로 확인한 private 테스트 package, 인증이 없는 별도 개발 target | GHCR 401/403 등 인증 거절 근거를 민감정보 없이 기록, `ErrImagePull`/`ImagePullBackOff`, Runtime 최종 실패와 롤백 |
| 이미지 미존재 | 인증이 정상인 별도 테스트 package에서 존재하지 않는 digest | manifest 부재 근거, Pod pull 실패, Runtime 최종 실패와 롤백. 인증 실패와 구분 |
| revision 보존 | revision A로 실행한 instance와 새 revision B | A의 실행 imageID 유지, B를 선택한 신규 instance에서 B의 imageID 사용 |

실행 중인 노드의 인증을 제거하거나 활성 workload의 image cache를 비워서 실패를 만들지
않는다. 실패 시나리오에는 별도 개발 target을 사용한다. private package에 인증 실패가
발생해도 이미 캐시된 image를 사용하면 실패를 관찰하지 못하므로 반드시 cache 상태를
함께 확인한다. 이 확인에는 대상 노드의 `crictl images` 또는 `crictl inspecti` 결과를
사용하며, Kubernetes Node.status.images의 일부 목록만으로 부재를 확정하지 않는다.

Runtime 생성 후 Operation을 폴링하는 동안 해당 테스트 Namespace의 Pod waiting reason과
Event를 관찰한다. 생성 실패 롤백 뒤에는 Pod/Event가 없어질 수 있으므로 관찰 결과를
실행 중에 수집한다. 오류 원문은 로컬에서 검토하고 공유 결과에는 분류와 상태만 남긴다.

## 현재 Runtime 오류 계약

현재 `dev`의 Create Adapter는 image pull 인증 실패·이미지 미존재를 별도 오류 코드로
구분하지 않는다. Pod가 준비되지 않은 채 readiness timeout에 도달하면
`WORKLOAD_NOT_READY`로 처리하고 소유 Namespace를 롤백한다. 세부 오류 분류는 #27의
후속 범위다. `WORKLOAD_NOT_READY`만으로 GHCR 인증 실패가 검증됐다고 기록하지 않는다.

삭제 성공이나 롤백 성공은 해당 Namespace가 Kubernetes API에서 `NotFound`가 될 때까지
확인한다. 남은 리소스와 실패 Operation은 결과에 명시하고 완료로 처리하지 않는다.

## 결과 기록 형식

아래 항목을 실제 실행 결과로 채운 뒤 #30에 첨부한다. 미실행 항목은 `미실행`으로 남긴다.

```text
실행 시각(UTC), Runtime commit, K3s/containerd 버전, 테스트 target_id
공급 revision, image digest, architecture, 생성 전 CRI cache 상태
경로: CI 직접 smoke / Registry-Scheduler-Runtime
시나리오: cold pull / cache / auth failure / missing digest / revision preservation
create Operation 상태 및 last_error_code
Pod waiting reason, 민감정보를 제거한 원인 분류, 실행 imageID
delete 또는 rollback 결과, Namespace NotFound 확인
결론: 통과 / 실패 / 미실행, 필요한 후속 작업
```

## 2026-09-09 확인된 배포 차단 요인

Secure Provisioner `dev`의 `ec100fb` 배포 run은 테스트·vet·빌드까지 통과했으나
`Upload release candidate` 단계에서 SSH port 22 접속 시간 초과로 실패했다.
`Deploy and verify`는 실행되지 않았다. 이 기록은 해당 run이 새 binary를 배포하지
못했다는 증거이며, 서버의 현재 binary가 무엇인지는 접속 후 별도로 확인해야 한다.

- 배포 run: https://github.com/MSG-CTF/secure-provisioner/actions/runs/34118938447
- 공급망 계약: https://github.com/MSG-CTF/secure-provisioner/issues/30
- Backend 등록 계약: https://github.com/MSG-CTF/msg-backend/issues/19

현재 실행 환경에는 AWS CLI/credential, 대상 SSH private key, 기본 kubeconfig context가
없다. DevSecOps repository의 Actions 설정 조회도 권한 오류가 발생했다. 실제 개발 대상의
접속 경로와 설정 확인이 끝나기 전까지 GHCR 실환경 검증은 미실행으로 유지한다.
