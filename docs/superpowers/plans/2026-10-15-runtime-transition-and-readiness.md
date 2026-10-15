# Runtime 전환과 readiness 검증 계획

## 목표

현재 운영 서버의 FLAG 파일 계약을 유지하면서, PR #47의 새 `env`/`secret_ref` 계약을 별도 환경에서 검증한다. 생성 성공 판정은 실제 Pod IP와 Service 포트가 있는 EndpointSlice에만 의존하도록 보강한다.

## 작업

1. PR #47의 기존 Go 전체 테스트를 기준선으로 실행한다.
2. 잘못된 EndpointSlice 주소와 포트로도 readiness가 통과하는 사례를 실패 테스트로 재현한다.
3. EndpointSlice의 Ready Pod 주소와 Service targetPort를 확인하도록 최소한의 코드를 수정한다. 정상 EndpointSlice 테스트 fixture를 실제 포트와 맞춘다.
4. 해당 테스트, Go 전체 테스트, `go vet`을 다시 실행한다.
5. 운영 서비스와 DB를 건드리지 않는 별도 Runtime/DB/포트에서 정상·실패 healthcheck, 비밀값 주입, 삭제를 실제 K3s로 확인한다.
6. 배포 스크립트가 환경·정책 교체를 안전하게 다루고 폐기된 AWS 목적지를 사용하지 않도록 수정하고 테스트한다.

## 전환 게이트

Backend의 비밀값 조회 API와 저장 값, Scheduler의 `healthcheck-enabled`/`exposed-ports-enabled`, 현재 서버 정책 digest의 대조가 끝나기 전에는 운영 Runtime을 PR #47 바이너리로 교체하지 않는다. 현재 배포된 hotfix와 정책 파일은 유지한다.
