# Secure Provisioner

CTF 문제 인스턴스 공급과 런타임 컨테이너 격리를 담당하는 Go 서비스입니다.

## 현재 구현 범위

현재 브랜치는 Instance Scheduler의 문제 인스턴스 생성 계약을 제공합니다.

- Scheduler `snake_case` 생성 요청 수신
- UUID, 팀, 실행 대상, 이미지, 포트와 자원 제한 검증
- 생성 유스케이스 호출 경계
- `runtime_workload_id`, `service_url` 성공 응답
- 알 수 없는 JSON 필드와 복수 JSON 객체 거부
- 내부 오류 정보가 노출되지 않는 표준 오류 응답

실제 K3s workload 생성 Adapter는 이슈 #18에서 연결합니다. Adapter가 연결되기 전 실행 서버는 유효한 생성 요청에 `503 RUNTIME_UNAVAILABLE`을 반환하며, 생성 성공 계약은 주입 가능한 유스케이스와 HTTP 테스트로 검증합니다.

## 실행

```powershell
go run ./cmd/provisioner
```

기본 주소는 `127.0.0.1:8080`이며 `PROVISIONER_ADDR` 환경변수로 변경할 수 있습니다.

## 생성 API

```http
POST /internal/v1/instances
Content-Type: application/json
```

```json
{
  "request_id": "req-01",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": 1,
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "cluster-main"
  },
  "workload": {
    "image": "registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "container_port": 8080,
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

생성 유스케이스 성공 응답:

```json
{
  "runtime_workload_id": "cluster-main/ns-team-1/workload-abc",
  "service_url": "https://team-1.example.com"
}
```

## 검증

```powershell
go test ./...
go vet ./...
```
