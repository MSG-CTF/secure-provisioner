# Broker target synchronization implementation plan

> **For agentic workers:** Use superpowers:executing-plans for inline
> implementation. Follow test-driven-development and verify before completion.

**Goal:** Check Broker K3s credentials hourly and register only new VM targets.

**Architecture:** Add an opt-in, persistent Broker registry controller to the
Go Runtime. Keep file targets and share the existing registry and Gateway
lookup across the controller and operation workers.

**Tech Stack:** Go 1.26, client-go, standard HTTPS/JSON/x509, existing tests.

**Spec:** `docs/superpowers/specs/2026-10-27-broker-target-sync-design.md`

## Global constraints

- Node UID is lifecycle target ID; Broker resource ID is credential identity.
- Fleet capabilities require an explicit policy; no hardcoded VM addresses.
- Preserve all existing credentials, clients, policy and eligibility across checks.
- Failed pagination publishes nothing; private credentials never enter logs.

## Review focus

- A second page fails after a successful first page: no partial publication.
- A known node disappears or is replaced: existing registrations remain unchanged.
- A manually disabled target reappears in Broker: it stays disabled.
- A restarted Runtime must retain clients and eligibility from private state.
- Concurrent create/status/delete and Gateway lookups see complete snapshots.

### Task 1: Broker discovery and persistence

Files: `internal/k3s/broker*.go`, `internal/k3s/registry.go`,
`internal/k3s/config.go`.

- [x] Write behavior tests for the cases in the spec and Review focus.
- [x] Run `go test ./internal/k3s -run Broker -count=1`; observe RED.
- [x] Implement verified paginated discovery, atomic private cache and
      registry snapshots under a mutex, adding only unregistered VMs.
- [x] Run those tests and the existing K3s suite; observe GREEN.

### Task 2: Runtime lifecycle and configuration

Files: `cmd/provisioner/broker_config.go`, `cmd/provisioner/main.go`,
`cmd/provisioner/broker_config_test.go`.

- [x] Test opt-in configuration, incomplete settings, startup registration
      and controller cancellation; run tests and observe RED.
- [x] Wire initial discovery and periodic synchronization into the worker
      lifecycle; keep API-only deployment bridges passive.
- [x] Run `go test ./cmd/provisioner ./internal/k3s` and fix failures.

### Task 3: Operator setup and review

Files: `deploy/broker-target-policy.example.json`, `README.md`,
`docs/operations/broker-k3s-credentials.md`.

- [x] Document the one-time fleet configuration, identity, cache permissions,
      hourly add-only behavior, Gateway prerequisites and rollout.
- [x] Run `go test ./...`, relevant `go test -race`, `go vet ./...`, and
      deployment tests. Record baseline/environment failures separately.
- [x] Review the complete diff and address correctness findings with tests.
- [x] Commit the change and prepare a reviewable PR if repository access
      permits; production deployment remains a separate activation.

## Execution evidence

- User refinement supersedes the original one-minute reconciliation behavior:
  check every hour and add new VMs only. Added tests first reproduced six
  differences: default interval, known-credential mutation, disappearance,
  restart eligibility, file-target mutation and known-resource replacement.
- After refinement: full Linux suite, vet and race tests passed. A second
  read-only review found no actionable defect; file/cache collision and Node UID
  deduplication coverage were added and the Broker suite passed again.

- Base: `82a97617d7ac2b738faff4d77c11a23b5516e1c0` (origin/dev).
- Initial Broker and command tests failed for the absent discovery feature;
  the implementations then passed those tests and existing K3s/command tests.
- Full Linux Go suite, relevant race tests and vet passed before review.
  Deployment Python tests passed: 92 tests, 4 environment-dependent skips.
- Windows baseline already failed `TestClientIdempotentPUTAndDELETE` and
  `TestClientClassifiesHTTPAndProxyErrorsWithoutLeakingBody` with TLS errors.
  Both passed on Linux; deployment and final verification use Linux.
- Independent review found two P2 issues. Regression tests reproduced both:
  fleet Gateway defaults overwrote saved opt-outs, and two malformed resource
  IDs aborted healthy enrollment. Both regression groups passed after fixes.
- Additional release check found API-only bridges must avoid creating their
  state directory under ProtectSystem=strict. Added an explicit read-only
  restore mode and verified missing-directory and cached-client behavior.
- Startup integration verifies enrollment/cache warming before workers and
  maintenance-capable initialization during a later Broker outage.
- Final verification after review fixes: full Linux Go suite, race tests for
  K3s/command/Gateway, vet and build passed. All 92 deployment tests passed
  (4 environment-dependent skips); shell deployment/rollback tests passed
  using LF-normalized temporary copies of the Windows checkout's scripts.
