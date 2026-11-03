# 새 K3s 노드의 이미지 준비 연결

노드가 이미지 캐시를 갖고 있어도 새 digest를 받을 수 있다는 뜻은 아닙니다
배정 전에 GHCR 인증과 실제 pull, 이미지 준비 에이전트를 확인합니다
문제 이미지나 출제자 코드는 수정하지 않습니다

## 적용 순서

1. Broker에서 대상 노드의 신규 배정을 막고 예약과 문제 Namespace가 없는지 확인합니다
2. 기존 enrollment 정책과 같은 형식으로 노드 한 곳의 UID, 이름, machine ID, provider ID, architecture, 검토된 agent digest를 고정합니다
3. 신뢰하는 제어 서버에서 아래 도구를 먼저 dry run으로 실행합니다
4. 실제 적용 후 private 이미지 pull과 agent Ready, 임시 Namespace 제거를 확인합니다
5. Broker 배정을 다시 열고 Runtime이 이를 반영한 뒤 기존 enrollment 정책에 노드를 추가합니다
6. 지원되는 publish-policy와 reconcile을 사용합니다 기존 정책의 노드를 유지하고 등록 결과 파일을 직접 편집하지 않습니다
7. Backend의 IMAGE_PREPARATION_TARGET_IDS에 준비할 대상을 넣고 IMAGE_PREPARATION_ACTIVATE_WHEN_READY를 활성화합니다
8. 새 버전 활성화가 준비 완료를 기다리는지 확인하고 사이트에서 생성, 접속, 종료와 예약 반납을 확인합니다

Backend의 IMAGE_PREPARATION_READINESS_MAX_AGE_SECONDS는 실제 관측 주기와 맞춰야 합니다
과거에 준비한 이미지도 다시 검사하므로 ObserveInterval만으로 전체 순회 시간을 계산할 수 없습니다
예를 들어 전체 순회가 약 200초이고 Runtime의 readiness TTL이 300초라면 Backend의 60초 기준으로는 유효한 결과도 거절됩니다
이 경우 최대 관측 나이를 300초로 맞추되 Runtime의 ready와 valid_until 검사는 그대로 유지합니다
IMAGE_PREPARATION_MAX_ATTEMPTS도 정상 관측 대기 시간을 감당하는지 확인합니다
토큰 거절이나 잘못된 정책 같은 영구 오류를 재시도 대상으로 바꾸지는 않습니다

```sh
sudo python3 deploy/image_preparation_bootstrap.py \
  --policy /root/approved-node.json \
  --kubeconfig /root/approved-node-kubeconfig.json \
  --registry-auth /root/registry-pull.yaml \
  --probe-image ghcr.io/APPROVED/PRIVATE_IMAGE@sha256:REPLACE_WITH_DIGEST \
  --agent-manifest deploy/image-agent.example.yaml
```

변경 내용과 대상을 확인한 뒤 같은 명령에 --apply를 추가합니다
입력 파일과 상위 디렉터리는 root 소유로 두고 다른 사용자가 쓰지 못하게 합니다
인증 파일은 기존 K3s registries.yaml 형식이며 configs.ghcr.io.auth의 username과 password를 사용합니다
인증값은 명령 인자, Git 저장소, 결과 문서에 넣지 않습니다

도구는 대상 identity와 문제 Pod 부재를 확인하고, 보호된 K3s 인증 파일을 원자적으로 교체합니다
기존 mirror와 TLS, 다른 registry 설정을 유지하며 기존 파일은 같은 노드에 백업합니다
인증이 바뀐 경우에만 K3s를 재시작합니다
probe는 Always로 private manifest를 확인하고 일치하는 image ID를 요구합니다
캐시에 없던 이미지의 전체 cold pull을 입증하려면 적용 전 CRI inventory도 별도로 확인합니다
문제 Namespace는 건드리지 않으며 임시 Namespace 삭제에는 UID precondition을 사용합니다

실패한 노드는 배정을 계속 막아 둡니다
노드 API와 K3s 상태를 먼저 복구한 뒤 다시 실행합니다
인증 적용 직후 실패했다면 보호된 원본 백업을 확인합니다
등록 정책이나 Broker의 노드 identity가 바뀐 경우에는 새 승인 없이 기존 고정을 풀지 않습니다

관련 계약은 [이미지 준비 운영 문서](image-preparation.md)와 [GHCR pull 검증](../testing/ghcr-pull.md)을 따릅니다
