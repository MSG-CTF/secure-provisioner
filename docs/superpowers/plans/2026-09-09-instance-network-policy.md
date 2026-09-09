# 인스턴스 내부 통신 정책 구현 계획

> **For agentic workers:** `superpowers:executing-plans`로 현재 세션에서 순차 실행한다.

**Goal:** 신규 Runtime 계약에서 내부 연결 목록을 제거하고 인스턴스 경계의 기본 통신을 지원한다.

**Architecture:** HTTP 입력은 삭제 필드를 거부하고 resolver는 STANDARD@v2를 저장한다. builder는 저장된 버전에 따라 v2 인스턴스 허용 또는 v1 기존 연결 그래프를 생성한다.

**Tech Stack:** Go 1.26, client-go 0.36.2, PostgreSQL JSON snapshot, OpenAPI.

**Spec:** `docs/superpowers/specs/2026-09-09-instance-network-policy-design.md`

## 공통 제약

- 기존 사용자 작업과 운영 인스턴스는 보존한다.
- `main`/`dev` 직접 push 금지, `feat/40-instance-network-policy`에서 작업한다.
- 외부 egress `NONE`, 공개 포트 계약과 기존 보안 baseline 유지.
- fake 테스트를 실제 K3s 차단 증거로 기록하지 않는다.

## 작업 1: 새 계약과 버전별 정책

파일: `internal/httpapi/create.go`, `internal/isolation/profile.go`, `internal/isolation/static_resolver.go`, `internal/k3s/network_policies.go`, `internal/k3s/security_resources.go`, `internal/runtimebinding/binding.go` 및 해당 테스트.

- [ ] 아래 행위를 검증하는 테스트를 먼저 작성하고 실패를 확인한다.

```go
// 신규 정책은 v2이며, 연결 목록 없이 인스턴스 내부 통신을 허용해야 한다.
command := validMultiCreateCommand("aws-dev")
resources := buildNetworkPolicyResources(t, command)
if findNetworkPolicy(resources.NetworkPolicies, "allow-instance-internal") == nil {
    t.Fatal("same-instance communication is not allowed")
}
```

- [ ] API의 `RuntimeWorkload.InternalConnections`와 변환을 제거하고 삭제 필드 거절을 검증한다.
- [ ] resolver에 `STANDARD@v2`를 적용한다. snapshot의 legacy 배열에는 `json:",omitempty"`를 추가하고 신규 resolver에서 비어 있지 않은 legacy 입력도 거부한다.
- [ ] builder는 아래 형태의 v2 정책을 생성한다. v1은 기존 builder 경로를 유지한다.

```go
peer := networkingv1.NetworkPolicyPeer{
    PodSelector: &metav1.LabelSelector{MatchLabels: copyLabels(ownerLabels)},
}
spec := networkingv1.NetworkPolicySpec{
    PodSelector: metav1.LabelSelector{MatchLabels: copyLabels(ownerLabels)},
    PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
    Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{peer}}},
    Egress: []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{peer}}},
}
```

- [ ] 미지원 버전, v2+legacy 혼합, v1 재생을 검사한다.
- [ ] `go test ./internal/httpapi ./internal/isolation ./internal/k3s ./internal/runtimepg ./internal/runtimeops ./internal/operations ./internal/runtimebinding`을 통과시킨다.

## 작업 2: 명세와 회귀 검사

파일: `docs/api/runtime-operations.md`, `docs/api/secure-provisioner.openapi.yaml`, `examples/requests/create-multi-container.json`.

- [ ] 현재 계약 문서와 JSON/OpenAPI 예제에서 삭제 필드를 제거한다.
- [ ] v2 내부 통신, v1 snapshot 보존, caller 전환 및 기존 작업 조회 절차를 문서화한다.
- [ ] `go test ./...`, `go vet ./...`, `go build ./...`, 관련 race 검사를 수행한다.
- [ ] 변경을 검토하고 `Feat: 인스턴스 내부 통신 기본 정책 적용`으로 커밋한다.
- [ ] 이슈별 구현 결과와 남은 실환경 검증을 구분한 PR을 `dev` 대상으로 준비한다.
