# 150건 동시 요청과 Provisioner Worker 수

기준 소스: `dev`의 `a4c1f47`. `PROVISIONER_WORKERS` 기본값은 10이다.
이 문서는 격리 환경의 실측과 운영 K3s에 대한 코드 분석을 구분한다.
운영 Worker 설정은 변경하지 않았다.

## 측정 범위

150개의 서로 다른 request/team/instance가 barrier에서 동시에 생성 요청을 보낸다.
실제 인증 HTTP handler, 이미지 승인 정책, isolation resolver, Runtime service,
PostgreSQL operation store, lease worker, checkpoint, binding 기록을 사용한다.
Worker의 production 경로를 사용하도록 `WorkerID`를 지정했다.
접수된 요청은 실제 HTTP operation API로 5초마다 조회한다.

실행 adapter만 정해진 시간 뒤 성공하는 구현으로 교체했다. 따라서 **실제 Kubernetes,
Pod Ready, GHCR 인증·다운로드, 다중 컨테이너 기동, 노드 자원 경합을 측정한 결과가 아니다.**
1초/10초는 관측된 운영 실행 시간이 아니라 실험 입력값이다.
단일 승인된 합성 WEB 이미지, 100m CPU / 128Mi memory 요청을 사용한다.
최종 operation 150건과 CREATED binding 150건이 모두 저장돼야 통과한다.

측정 환경은 Windows host의 Ubuntu 24.04 WSL2 (Linux 6.6.87.2),
Linux/amd64 Go 1.26.5, PostgreSQL 16.15이다. 논리 CPU 16개,
`GOMAXPROCS=16`, WSL guest memory 약 11.65GiB에서 로컬 HTTP/DB를 사용했다.
Windows에서 Linux test binary를 cross-compile한 뒤 WSL에서 새로 실행했다.
실제 노드의 크기나 네트워크를 대표하는 환경이 아니다.

- 실제 Worker 동시성: 10 / 20 / 30 / 50
- 실제 PostgreSQL pool: 최대 30 / idle 10, 관측용 별도 pool 최대 3
- lease 3분 / 갱신 1분, 빈 큐 claim 대기 200ms, 최대 시도 4회
- 1초 profile: 각 Worker 수마다 3회
- 10초 profile: 각 Worker 수마다 1회
- retry profile: 20 / 30 Worker, 매 10번째 요청의 첫 실행만 retryable 실패 (총 15건)
- 100ms마다 terminal 행 수를 관측하고 모두 저장된 시점의 drain 시간을 기록

접수 지연은 HTTP 응답 body까지 받은 시간이다. 요청별 queue/completion과
`first_claim_to_terminal`은 애플리케이션이 DB에 전달한 **logical timestamp** 차이다.
`first_claim_to_terminal`에는 재시도 대기와 재실행도 포함된다.
최종 저장 지연까지 포함하는 값은 `all_150_persisted_terminal_observed_ms`이며,
100ms 관측 간격 및 query 지연이 더해진다. logical timestamp 역전 수도 별도 기록한다.
캐시된 테스트 결과가 아니라 새로 실행한 binary에서 raw JSON을 생성한다.

## 1초 실행 profile 실측

아래 범위는 3회 실행의 최솟값~최댓값이며 통계적 신뢰구간이 아니다.
Worker별 450건 전부 접수·성공·binding 저장됐고 HTTP polling 오류는 0건이었다.

| Worker | HTTP 접수 p95 | logical 완료 p95 | 150건 저장 완료 관측 |
|---:|---:|---:|---:|
| 10 | 177.9~227.1ms | 15.59~15.97초 | 15.69~16.07초 |
| 20 | 185.9~199.4ms | 8.40~8.72초 | 8.47~8.78초 |
| 30 | 187.5~188.3ms | 5.33~5.49초 | 5.35~5.55초 |
| 50 | 179.3~188.4ms | 3.26~3.46초 | 3.32~3.53초 |

150건 동시 접수에 Worker 150개가 필요한 구조가 아니다. 현재 환경에서는
Worker 10개로도 접수가 가능했고, Worker 증가는 주로 큐 대기/전체 drain을 줄였다.
실제 adapter 실행 peak가 각각 설정한 Worker 수까지 올라간 것을 확인했다.
이 결과는 CPU·메모리 한계를 찾는 saturation test가 아니다.

## 10초 실행 및 재시도 실측

10초 profile은 각 Worker 수에 대해 1회 측정했다. 모든 case에서 150건 전부
접수·성공했고, 최종 binding도 150개였다.

| Worker | HTTP 접수 p95 | logical 완료 p95 | 150건 저장 완료 관측 |
|---:|---:|---:|---:|
| 10 | 224.9ms | 151.30초 | 151.35초 |
| 20 | 178.7ms | 80.54초 | 80.61초 |
| 30 | 184.3ms | 50.28초 | 50.34초 |
| 50 | 180.6ms | 30.27초 | 30.35초 |

1초 실행 + 15건의 첫 시도 실패 profile에서는 20 Worker가 10.61초,
30 Worker가 8.57초에 전체 저장을 완료했다. 각 case는 정확히 165회 실행됐고,
실패를 주입한 각 요청이 2회, 나머지가 1회 실행됐는지 검증했다.

합계 18 case / 2,700 요청 / 2,730 실행 / HTTP 상태 조회 7,914회에서
최종 실패 및 HTTP polling 오류는 없었다. [요청별 raw JSON](results/2026-10-24-worker-capacity-150/)
18개에 각 case의 환경·설정·관측·150개 표본을 함께 보존했다.

logical queue timestamp가 음수인 표본 34건(최저 -52.231ms)도 숨기지 않고 기록했다.
Claim의 `Now`가 쿼리 전 계산돼, 대기 중에 삽입된 행의 `created_at`보다 빠를 수 있다.
따라서 queue 값을 정확한 wall-clock 대기 시간으로 해석하지 않는다.
권장 판단의 전체 완료 시간은 persisted terminal 관측값을 사용했다.

## 권장 판단과 설정

요청 접수만 요구하면 이 환경에서는 기본 10 Worker도 150건을 처리했다.
완료 시간을 줄이려는 목적이라면 **30 Worker를 실제 K3s 부하 검증의 첫 후보**로 잡는다.
작업이 일정하게 10초이고 다른 병목이 없는 모델에서 30개는 50.34초로,
1분 목표를 가정할 때 20개(80.61초)보다 여유가 있었다. 50개는 더 빨랐지만,
실제 target의 API·이미지·자원 예산 없이 운영 최적값으로 단정할 근거는 없다.
1분은 설명을 위한 가정이며 사용자와 확정한 SLA가 아니다.

```dotenv
# 실제 시험 target 검증 후 적용할 후보. 이번 실험에서는 운영 설정 변경 없음.
PROVISIONER_WORKERS=30
```

대략적인 queue drain 모델은 `ceil(150 / Worker 수) × 1회 실행 시간`이다.
실행 시간은 실제 warm/cold·다중 컨테이너 조건으로 다시 측정해야 한다.
Scheduler/Backend 상류 대기와 사용자에게 완료가 전달되는 polling 지연도 별도다.
현재 요청 실험의 150명은 서로 다른 팀/인스턴스의 생성 요청 1건씩을 뜻한다.
서비스 이용 동시 접속자 150명, VM/노드 150개, 매초 150건의 지속 부하는 측정하지 않았다.

`PROVISIONER_WORKER_CONCURRENCY`는 현재 코드에서 읽지 않는 과거 문서의 이름이다.
Worker 수만 비교할 때 `PROVISIONER_POLL_INTERVAL`을 함께 낮추지 않는다.
이 변수는 Worker 빈 큐 대기와 K3s Ready poll 양쪽을 바꾸기 때문이다.
명시하지 않으면 각각 200ms / 1초인 현재 기본값을 유지한다.

## 재현

Go 1.26와 PostgreSQL 16 환경에서 별도 loopback 전용 DB를 준비한다.
이 테스트는 해당 DB의 `runtime_operations`, `runtime_bindings`를 매 case 초기화한다.
URL과 `current_database()`가 모두 `provisioner_load_150`인지 확인하고,
loopback host / 명시적 opt-in / `sslmode=disable`만 허용한다.

```bash
createdb -h 127.0.0.1 -p 55439 -U workerload provisioner_load_150
export PROVISIONER_LOAD_DATABASE_URL='postgres://workerload@127.0.0.1:55439/provisioner_load_150?sslmode=disable'
export PROVISIONER_LOAD_ALLOW_TRUNCATE=1
bash scripts/run-worker-capacity-150.sh
```

별도 port를 사용하는 경우 URL과 `createdb`의 `-p`를 함께 변경한다. 인증은 해당
격리 DB 설정에 맞춘다. runner는 기본적으로 임시 결과 디렉터리를 만들며
`PROVISIONER_LOAD_OUTPUT`으로 지정할 수도 있다.
Linux cross-compiled test binary는 `PROVISIONER_LOAD_TEST_BINARY`로 지정한다.

개별 case는 `go test ./tests/workerload -v -run '^TestWorkerCapacity150$' -count=1`
에서 아래 환경 변수로 조절한다.

| 변수 | 기본값 | 의미 |
|---|---|---|
| `PROVISIONER_LOAD_WORKERS` | `10,20,30,50` | 비교할 실제 Worker 수 (각 1~150) |
| `PROVISIONER_LOAD_REPEATS` | `1` | 반복 수 (1~150) |
| `PROVISIONER_LOAD_EXECUTION` | `1s` | 통제 adapter의 1회 실행 시간 |
| `PROVISIONER_LOAD_RETRY_EVERY` | `0` | 0이면 실패 주입 없음; N이면 매 N번째 첫 실행 실패 |
| `PROVISIONER_LOAD_OUTPUT` | 필수 | raw JSON 저장 디렉터리 |

runner는 위의 고정된 18-case matrix를 실행하므로 execution/repeat/retry 설정을
단계별로 덮어쓴다. Worker 목록은 첫 두 profile에 적용하고 retry는 20/30을 사용한다.

## 운영 판단에 필요한 제약

Worker는 K3s 생성·Ready 확인과 결과 저장까지 슬롯을 점유한다.
HTTP 202 접수와 사용자 접속 가능 시점은 다르다. Ready timeout 기본 2분은
K3s resource apply 이후부터 계산하며, 큐 대기 및 apply 시간은 포함하지 않는다.
`WORKLOAD_NOT_READY`는 rollback 후 일반적으로 자동 재시도하지 않는다.

`internal/k3s/config.go`의 `KubeconfigClientFactory`는 QPS/Burst를 설정하지 않는다.
고정된 client-go v0.36.2의 기본값은 QPS 5 / burst 10이다. 현재 초기화 경로에서는
CoreV1 등 typed group/version별로 limiter가 생기며, 같은 target의 CoreV1 budget은
모든 Worker가 공유한다. Worker 수만 늘려도 같은 target의 이 budget은 늘지 않는다.
PostgreSQL pool 30은 Worker 상한 30을 의미하지 않는다. K3s 대기 중에는
DB connection을 계속 점유하지 않는다.

새 단일 컨테이너·단일 공개 Service·Secret 없는 정상 생성 경로에도 CoreV1 API
호출이 최소 22회 있다. 코드에서 센 하한이며 실제 API 측정치가 아니다.

| 경로 | 최소 CoreV1 호출 |
|---|---:|
| 이전 attempt Namespace 복구 확인 | 1 |
| Namespace / SA / Quota / LimitRange / Service preflight GET | 5 |
| Namespace GET + CREATE | 2 |
| SA / Quota / LimitRange 각각 GET + CREATE + 확인 GET | 9 |
| Service GET + CREATE + 확인 GET | 3 |
| 첫 Ready 확인의 Pod LIST | 1 |
| 최종 Namespace 검증 GET | 1 |
| 합계 | 22 |

모든 150건이 **한 target**에 몰리고 이 기본 limiter를 쓰면 CoreV1 호출만으로도
`(150 × 22 − 10) / 5 = 658초`의 이론적 하한이 나온다. 추가 Ready poll, 재시도,
다중 컨테이너, Secret, 상태 조회 경합은 더해진다. 실제 150건 K3s 결과나 SLA 예측치로
해석하면 안 된다. target 분산, 복수 Runtime 프로세스, 명시적인 client QPS 설정에 따라
계산이 달라진다. 현재 QPS 조절용 Provisioner 환경 변수는 없다.

운영 후보 Worker 수를 고른 뒤 실제 시험 target에서 warm/cold 이미지 및 다중
컨테이너 150건을 실행하고, 접수/큐/Ready p95, timeout/rollback, API throttle,
노드 CPU·메모리·disk·network를 함께 측정해야 운영 완료 시간을 확정할 수 있다.

## 검증 기록

- Opt-in 150건 matrix 18 case: 모두 PASS, raw JSON의 표본 수·중복 ID·요청별 시도 수·
  percentile을 독립적으로 다시 계산해 일치 확인
- 안전한 DB 선택 guard 및 percentile helper 테스트: PASS
- 기존 전체 Go 테스트 12 package: Linux 실행에서 `-p 1 -count=1`로 새로 PASS,
  같은 격리 DB를 사용해 PostgreSQL integration과 기존 500건 enqueue / 100건
  idempotency 테스트도 실행
- 실제 K3s network/recovery 테스트: 전용 target 설정이 없어 실행하지 않음
- runner `bash -n` 및 `git diff --check`: PASS

Windows cross-compile에는 Windows 소스 경로가 기록되므로 `runtime.Caller`로
문서를 읽는 기존 테스트가 처음에는 경로 오류를 냈다. 해당 package를 compile할 때
`-trimpath=<Windows repo>=>/mnt/c/<repo>`로 소스 경로를 매핑해 다시 실행했다.
제품 코드나 기존 테스트를 변경해서 우회하지 않았다. Linux에서 직접 Go를 실행하면
이 매핑은 필요 없다. PostgreSQL을 초기화하는 package 간 경합을 피하려고 `-p 1`을 썼다.

코드 근거:

- [실제 Worker 설정](../../cmd/provisioner/runtime_store_config.go),
  [app 설정과 Ready timeout](../../cmd/provisioner/main.go)
- [lease Worker 실행/재시도](../../internal/operations/worker.go),
  [접수 mutex와 결과 저장](../../internal/runtimeops/service.go)
- [PostgreSQL pool](../../internal/runtimepg/database.go),
  [K3s Client 초기화](../../internal/k3s/config.go),
  [K3s apply/Ready/API 호출](../../internal/k3s/adapter.go)
- 고정 dependency client-go v0.36.2의
  [기본 QPS와 REST limiter](https://github.com/kubernetes/client-go/blob/v0.36.2/rest/config.go),
  [Clientset limiter 생성 조건](https://github.com/kubernetes/client-go/blob/v0.36.2/kubernetes/clientset.go)
