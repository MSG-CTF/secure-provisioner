# SQLite 문제 노드의 Namespace 삭제 지연

Cashout을 12개 동시에 종료했을 때 Pod는 4초 안에 사라졌지만 참가자 API에서 종료 완료를 확인하기까지 최대 40.04초가 걸렸습니다
주된 대기는 Namespace 컨트롤러가 각 리소스 종류를 정리하는 구간이었습니다
실제 API 지표에서도 비어 있는 리소스의 DeleteCollection에 0.1~1초씩 걸렸습니다

현재 노드는 K3s v1.36.4+k3s1과 SQLite를 사용합니다
이 버전의 Kine와 API 서버 watch cache 사이에 생기는 대기를 피하려고 전용 문제 노드에서 watch cache를 끄는 설정을 비교했습니다
Kubernetes의 정상 Namespace 정리와 finalizer 처리는 그대로 사용합니다

- [K3s의 같은 삭제 지연 보고](https://github.com/k3s-io/k3s/issues/14399)
- [Kine의 캐시 동기화 대기 설명](https://github.com/k3s-io/kine/issues/731)
- [API 서버 watch-cache 옵션](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [K3s 설정 목록 병합](https://docs.k3s.io/installation/configuration#value-merge-behavior)

## 실제 사이트 검증

같은 Cashout revision 734·이미지 digest와 운영 백엔드·스케줄러·런타임을 사용했습니다
12개 중 1개는 실제 참가자 화면에서 생성·종료했고, 나머지 11개는 같은 운영 API를 동시에 호출했습니다
시간은 생성 또는 삭제 HTTP 요청부터 운영 API에서 RUNNING 또는 CLEANED를 관찰할 때까지입니다
서로 다른 시점의 각 1회 비교이며, 노드별 배정 수와 네트워크 지연 차이가 포함됩니다

| 확인 항목 | 기존 | watch cache 해제 |
| --- | ---: | ---: |
| 삭제 중앙값 | 34.98초 | 12.39초 |
| 삭제 최댓값 | 40.04초 | 14.82초 |
| Namespace 삭제 요청부터 실제 소멸 | 별도 지연 관측 | 중앙값 5.82초·최대 6.26초 |
| 실제 생성·웹 접속 | 12개 | 12개 통과 |
| CPU 1000m에서 250m 원복 | 12개 | 12개 통과 |
| 자원 정리 뒤 예약 반납 | 12개 | 12개 통과 |

참가자 화면의 종료 버튼 조작과 확인 대화상자까지 포함한 시험 실행 시간은 최대 16.07초였습니다
이미지·환경변수·비밀값은 값 대신 해시로 대조했고, CPU 변경 전후에도 같은 컨테이너가 유지됐습니다
기존 접속 주소 12개는 종료 뒤 모두 차단됐습니다

노드 4곳에 3·1·2·6개가 배정됐습니다
2초 간격 표본에서 노드 CPU 최고 73.17%, K3s 프로세스 최고 약 1.05 vCPU, RSS 최고 666.7MiB였고 OOM은 없었습니다
최소 가용 메모리는 14GiB 이상이었습니다 장기 부하나 더 큰 클러스터에서 같은 결과를 보장하는 수치는 아닙니다

별도 QA 인스턴스의 ResourceQuota에 시험용 finalizer를 붙였을 때는 Pod가 사라진 뒤에도 Namespace와 종료 작업이 남았습니다
100초 이상 지난 뒤에도 예약은 COMMITTED였고 참가자 화면은 STOPPING이었습니다
시험용 finalizer 하나만 UID·resourceVersion으로 확인해 해제한 뒤 정상 정리와 예약 반납을 다시 확인했습니다

## 적용

이 설정은 검증한 SQLite 단일 노드에 한정합니다
watch cache를 끄면 목록 조회와 watch의 저장소 부하 특성이 바뀌므로 다른 버전·etcd·큰 클러스터는 따로 측정해야 합니다
일반 런타임 자동 배포에서는 이 도구를 실행하지 않습니다

브로커에서 해당 노드의 신규 배정을 멈추고 HELD·COMMITTED 예약이 0개인지 확인합니다
노드는 한 곳씩 작업합니다 도구도 ctf- Namespace가 남아 있으면 종료 중인 경우까지 포함해 재시작을 거절합니다

해당 노드에서 root로 실행합니다 Node UID는 브로커·런타임에 등록한 값과 대조합니다

```sh
python3 k3s_namespace_cache.py plan --expected-node-uid NODE_UID
python3 k3s_namespace_cache.py apply --expected-node-uid NODE_UID
```

기존 파일을 보존하고 아래 파일 하나를 추가합니다 + 병합으로 기존 API 서버 인자를 유지합니다

```yaml
# /etc/rancher/k3s/config.yaml.d/zz-msgctf-namespace-cache.yaml
kube-apiserver-arg+:
  - watch-cache=false
```

적용 뒤 같은 Node UID·Ready 상태와 실제 API 서버 시작 로그의 설정값을 확인합니다
브로커 배정은 이 검증이 끝난 뒤 다시 엽니다
다른 Node UID, 기존 캐시 설정, 외부 저장소, CLI 덮어쓰기, 설정 파일 변경은 수동 확인 대상으로 거절합니다

## 복구

```sh
python3 k3s_namespace_cache.py restore --expected-node-uid NODE_UID
```

같은 방식으로 신규 배정을 막고 활성 예약이 없는 상태에서 실행합니다
도구가 추가한 파일의 내용과 다른 설정 해시가 같을 때만 파일을 제거합니다
원래 캐시 설정과 같은 Node UID·Ready를 확인한 뒤 브로커 배정을 다시 엽니다

적용 중 검증 실패가 나면 노드가 비어 있고 다른 설정이 그대로인 경우에만 자동 복구합니다
새 문제가 생겼거나 설정이 달라졌거나 API 상태를 확인할 수 없으면 재시작을 멈추고 노드를 배정 중지 상태로 유지해야 합니다
노드별 파일 잠금으로 동시 apply·restore를 막습니다

체크포인트는 /var/lib/msgctf-k3s-cache-profile 아래에 남깁니다
복구가 완료된 체크포인트는 이력을 별도 보관한 뒤 옮겨야 다시 적용할 수 있습니다
prepared 상태는 실제 파일·시작 로그·노드 상태를 먼저 대조하고 수동으로 복구합니다

검증은 출제자 코드·문제 이미지·환경변수·플래그·CPU 할당을 유지한 상태로 진행했습니다
