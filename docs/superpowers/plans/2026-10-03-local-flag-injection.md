# Local FLAG Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Provisioner load operator-owned, per-image FLAG values from a local VM file and inject them into each new instance's Kubernetes Secret without putting values in API requests or operation storage.

**Architecture:** A separate JSON file maps immutable image digests to FLAG values. The worker loads it at startup, builds a namespace-owned Secret for matching containers, connects the container `FLAG` variable through `secretKeyRef`, and creates the Secret before Deployments. The existing image policy can mark a digest as requiring FLAG so startup or creation fails closed when its value is absent.

**Tech Stack:** Go, Kubernetes client-go, K3s, systemd.

**Spec:** Operator decision in this conversation: store FLAG values on the Provisioner VM, separate from Git and image policy, and inject at instance creation.

## Global Constraints

- Do not put FLAG plaintext in Git, API requests, operation records, logs, Deployment specs, or error messages.
- Keep the existing no-Secret quota for instances without FLAG injection.
- Fail before creating Deployments if a required FLAG is missing or Secret creation fails.
- Namespace deletion must remove the Secret.

## Review Focus

- Malformed or world-readable local file must fail startup without printing values.
- An unknown image digest must never receive another image's FLAG.
- Multi-container workloads must give FLAG only to its mapped container.
- Secret quota must allow exactly one Secret when needed.
- Kubernetes create uncertainty must trigger namespace rollback, not adoption.

---

### Task 1: Local catalog and policy requirement

**Files:** `internal/k3s/flag_catalog.go`, `internal/k3s/flag_catalog_test.go`, `internal/httpapi/image_policy.go`, `internal/httpapi/image_policy_test.go`, `cmd/provisioner/main.go`, `cmd/provisioner/main_test.go`

- [x] Add failing tests for strict parsing, file privacy, exact digest mapping, and required FLAG startup validation.
- [x] Run focused tests and verify they fail for missing behavior.
- [x] Implement catalog loading and `PROVISIONER_FLAG_FILE` startup wiring.
- [x] Run focused tests until green.

### Task 2: Kubernetes Secret injection and rollback

**Files:** `internal/k3s/flag_resources.go`, `internal/k3s/flag_resources_test.go`, `internal/k3s/resources.go`, `internal/k3s/adapter.go`, `internal/k3s/adapter_test.go`

- [x] Add failing tests for `FLAG` secretKeyRef, one-Secret quota, unflagged baseline, and Secret-before-Deployment failure handling.
- [x] Run focused tests and verify they fail for missing behavior.
- [x] Implement Secret rendering, apply, readback, and rollback integration.
- [x] Run focused and full test suites.

### Task 3: Operator handoff and test deployment

**Files:** `docs/operations/web-image-policy-catalog.md`, `config/web-image-policies.json`, test VM configuration only if a verified FLAG value is available.

- [x] Document file format, ownership, deployment, rotation, backend hash alignment, and limitations of hard-coded flags.
- [x] Mark images requiring FLAG without committing values.
- [x] Verify code, build, and deploy a test binary; create, inspect, and delete an instance with a disposable FLAG, then restore the test policy and empty FLAG file.
