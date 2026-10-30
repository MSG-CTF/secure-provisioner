# Workload Network Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an operator-only exact-digest TCP graph to Runtime while preserving the existing Create JSON and default `STANDARD@v2` behavior.

**Architecture:** Parse and validate graph entries alongside image policies, attach a trusted graph snapshot during admission, carry it through resolver and durable commands, and render exact Kubernetes ingress and egress. Reject Namespace NetworkPolicies outside the graph's desired set before Pod deployment.

**Tech Stack:** Go, Kubernetes client-go NetworkPolicy, PostgreSQL JSON snapshots.

**Spec:** `docs/superpowers/specs/2026-10-16-workload-network-graph-design.md`

## Global Constraints

- Keep `internal_connections` rejected on new Create JSON.
- Default `STANDARD@v2` full mesh and legacy v1 snapshots are unchanged.
- Do not enable unapproved Afterimage edges or unknown digests in checked-in config.
- `NODE_PORT` publicly permits portal ingress, while same-instance Pods still require a source egress edge; live tests must deny unauthorized PodIP and nodeIP:NodePort paths.

## Review Focus

- Partial or mixed image set must fail admission, not fall back to full mesh.
- Changed operator graph must conflict on a duplicate request ID.
- Old queued operation must replay its stored graph after policy-file changes.
- A stale broad NetworkPolicy must prevent Deployment creation.
- NetworkPolicy readback/list failures must use existing rollback and cleanup path.

---

### Task 1: Policy contract and trusted admission

**Files:** `internal/isolation/profile.go`, `internal/isolation/static_resolver.go`, `internal/httpapi/image_policy.go`, `internal/httpapi/create.go`, related tests.

- [ ] Write tests for valid graph, malformed graph, incomplete image set, JSON injection, and deep-copy snapshot.
- [ ] Run targeted tests and confirm red.
- [ ] Implement schema 2 parsing, identity/edge validation, exact-set selection, internal snapshot and resolver copy.
- [ ] Run targeted tests and confirm green.

### Task 2: Durable snapshots and idempotency

**Files:** `internal/operations/operation.go`, `internal/runtimebinding/binding.go`, `internal/runtimeops/service.go`, related tests.

- [ ] Write tests for operation/binding copy, duplicate drift conflict and DB serialization replay.
- [ ] Run targeted tests and confirm red.
- [ ] Carry the graph through durable operation and binding snapshots.
- [ ] Run targeted tests and confirm green.

### Task 3: Kubernetes exact rules and fail closed application

**Files:** `internal/k3s/network_policies.go`, `internal/k3s/security_resources.go`, `internal/k3s/resources.go`, `internal/k3s/adapter.go`, related tests.

- [ ] Write tests for exact bidirectional private rules, unchanged v2/v1 behavior, the NodePort public ingress exception, unexpected NetworkPolicy rejection and no Deployment write.
- [ ] Run targeted tests and confirm red.
- [ ] Build graph rules, validate the saved image set, and list Namespace NetworkPolicies before Deployment and before successful return.
- [ ] Run targeted tests and confirm green.

### Task 4: Operator documentation and final verification

**Files:** `docs/operations/workload-network-policies.md`, `README.md` if needed.

- [ ] Document exact schema and an Afterimage template with digest and edge placeholders clearly unapproved.
- [ ] Run `gofmt`, focused Go tests and `go test ./...` with an isolated temporary directory.
- [ ] Review diff for live policy enablement, commit, and create an independent PR based on PR #47 head.
