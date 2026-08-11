# secure-provisioner

CTF 팀별 문제 인스턴스 공급과 런타임 컨테이너 격리를 담당한다.

## 문서

- [프로젝트 구현 규칙](AGENTS.md)

상세 설계와 개발 메모는 로컬 `docs/` 디렉터리에서 관리하며 Git 저장소에는 포함하지 않는다.

## 협업 원칙

- Scheduler가 인스턴스 lifecycle과 배치 결정을 소유하고, Provisioner는 승인된 요청만 실행한다.
- `team_id + challenge_id`마다 활성 문제 인스턴스를 하나로 제한한다.
- Provisioner는 승인된 image digest와 보안 프로필로만 Kubernetes 리소스를 생성한다.
- 실제 격리 효과는 mock이 아니라 K3s 통합 테스트로 검증한다.

## PostgreSQL 워커 MVP

로컬 PostgreSQL을 시작한다.

```powershell
docker compose -f .\compose.postgres.yaml up -d --wait
```

PostgreSQL 작업 큐와 Fake cluster를 사용해 Provisioner를 실행한다.

```powershell
$env:PROVISIONER_STORE_MODE = 'postgres'
$env:PROVISIONER_DATABASE_URL = 'postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable'
$env:PROVISIONER_CLUSTER_MODE = 'fake'
go run .\cmd\provisioner
```

기본 워커 수는 10개이고, 요청은 PostgreSQL에 먼저 커밋된 뒤 `202 Accepted`를 반환한다. 외부 JSON 계약은 `snake_case`를 사용하고 `team_id`는 number다.
