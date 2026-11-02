# K3s 문제 노드의 컨트롤러 요청 예산

Cashout 12개를 동시에 종료했을 때 Pod는 4초 안에 사라졌지만 Namespace 정리가 끝날 때까지 최대 40초가 걸렸습니다
실행 노드의 실제 configz에서는 kube-controller-manager의 요청 예산이 20 QPS·burst 30이었습니다
이 문서의 도구는 그 예산을 50 QPS·burst 100으로 조정해 비교하는 운영 도구입니다

Namespace 컨트롤러는 남아 있는 리소스를 정리하고 부재를 확인한 뒤 finalizer를 해제합니다
이 동작과 기본 5초 대기는 유지합니다 도구가 finalizer를 지우거나 Namespace를 강제로 종료하지 않습니다

- [Kubernetes Namespace 컨트롤러](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/controller/namespace/namespace_controller.go)
- [Namespace 내부 리소스 정리](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/controller/namespace/deletion/namespaced_resources_deleter.go)
- [컨트롤러 요청 예산 옵션](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [K3s 설정 파일과 목록 병합](https://docs.k3s.io/installation/configuration#value-merge-behavior)

## 적용

운영자가 브로커에서 해당 노드의 신규 배정을 멈추고 활성 예약이 없는지 확인한 뒤 실행합니다
노드에 ctf- Namespace가 하나라도 남아 있으면 도구가 재시작을 거절합니다 종료 중인 Namespace도 포함합니다
노드는 한 번에 한 곳씩 처리합니다

해당 노드에서 root로 실행합니다 Node UID는 브로커·런타임에 등록된 값과 대조합니다

```sh
python3 k3s_lifecycle_client.py plan --expected-node-uid NODE_UID
python3 k3s_lifecycle_client.py apply --expected-node-uid NODE_UID
```

기존 설정은 수정하지 않고 별도 파일을 추가합니다 목록을 덮어쓰지 않도록 K3s의 + 병합을 사용합니다

```yaml
# /etc/rancher/k3s/config.yaml.d/zz-msgctf-lifecycle-client.yaml
kube-controller-manager-arg+:
  - kube-api-qps=50
  - kube-api-burst=100
```

다른 Node UID, 기존 예산 변경, CLI 설정 덮어쓰기, 심볼릭 링크, 다른 설정 파일 변경은 거절합니다
적용 후 같은 Node UID·Ready 상태·실제 configz의 50/100을 확인해야 성공합니다
재시작 후 검증에 실패하면 추가한 파일을 제거하고 기존 예산으로 복구합니다
재시작 직전에 문제가 새로 생성되면 파일만 철회하고 서비스를 재시작하지 않습니다

## 복구

```sh
python3 k3s_lifecycle_client.py restore --expected-node-uid NODE_UID
```

도구가 만든 파일의 해시가 같고 다른 설정이 바뀌지 않았을 때만 제거합니다
같은 Node UID와 기존 20/30을 확인한 뒤 브로커의 신규 배정을 다시 엽니다
체크포인트는 /var/lib/msgctf-k3s-lifecycle 아래에 남깁니다 인증값이나 문제 비밀값은 기록하지 않습니다

이 도구는 일반 런타임 배포 시 자동으로 실행되지 않습니다 출제자 코드·문제 이미지·환경변수·CPU 설정은 변경하지 않습니다
실제 개선 폭과 API 서버 부하는 운영 검증 결과로 따로 확인합니다
