# Gateway TCP Owner Draft Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prepare opt-in transport/owner requests and safe error recovery, verified locally without production mutation.

**Architecture:** Default v1 wire requests stay unchanged. New opt-in TCP requests carry trusted team ownership and explicit public transport, stored in the immutable Gateway journal. The client validates mode/owner/enforcement acknowledgements; draft errors feed existing held retry and cleanup paths.

**Tech Stack:** Go, httptest TLS servers, fake Kubernetes, local PostgreSQL.

**Spec:** `docs/api/gateway-tcp-owner-draft.md` (proposal, awaiting administrator agreement).

## Global Constraints

- User authorized implementation and local testing; preserve prior commit-only instruction, no PR/merge/deploy.
- Default `PROVISIONER_GATEWAY_TCP_TRANSPORT=legacy`; HTTP and saved legacy intents keep the old body.
- No new dependencies, public port allocator, Gateway listener, VPN, or actual data-plane access control.
- No automatic fallback or transport downgrade when the draft request is unsupported.

## Review Focus

- Missing/foreign owner, wrong mode, missing owner enforcement acknowledgement must fail closed.
- Changing configuration after a lost response must not change the saved PUT body.
- Public allocator contention must not be confused with a foreign backend/owner conflict.
- Cleanup uncertainty must preserve Service/NodePort and must not report success.
- PostgreSQL must reject owner/transport mutation on an existing intent, including legacy-to-draft changes.

### Task 1: Opt-in request and response contract

**Files:** `cmd/provisioner/main.go`, `gateway_config_test.go`, `internal/gateway/client.go`, new `contract.go`, `k3s_backend.go`, and tests.

**Interfaces:** Optional Destination/Route `public_transport`, `owner_team_id`; response `owner_access_enforced`; environment setting selecting new intents only.

- [x] Test invalid config and unchanged default request; observe failure for unsupported option handling.
- [x] Test draft wire fields and response validation; observe missing functionality fail.
- [x] Implement configuration, trusted owner stamping, and strict request/response checks.
- [x] Run `go test ./cmd/provisioner ./internal/gateway`; expect pass.

### Task 2: Error recovery and persisted immutability

**Files:** `internal/gateway/client.go`, `adapter.go`, contract/lifecycle tests, `internal/runtimepg/gateway_journal.go` and tests.

**Interfaces:** Draft API error codes mapped into held retry, conflict hold, or cleanup; saved Destination remains authoritative.

- [x] Add failing lifecycle tests for pool contention, owner conflict, unsupported mode, cleanup uncertainty, and changed-config replay.
- [x] Add PostgreSQL tests rejecting owner/transport rewrites.
- [x] Implement the smallest error classification and immutable snapshot checks that satisfy these tests.
- [x] Run full Go suite with isolated PostgreSQL, relevant race tests, vet, and build; expect pass.
- [x] Obtain independent review, fix material findings, commit and push the existing feature branch only.

## Verification and review

- `go test -p 1 -count=1 ./...` passed with a dedicated local PostgreSQL 16 database.
- `go test -race -p 1 -count=1 ./cmd/provisioner ./internal/gateway ./internal/runtimepg` passed with the same isolated database.
- `go vet -buildvcs=false ./...`, Linux binary build, and diff whitespace check passed.
- Wire/response, lifecycle, and database regressions were observed failing before their fixes.
- Review found that rejected successful acknowledgements left workloads active; regressions now verify quiescence and conflict hold for bad owner/enforcement/mode, malformed bodies, and unexpected HTTP 202/204. Follow-up review found no actionable issues.
- Ruling: ordinary lost network responses use immutable replay under the proposed Gateway atomic-enforcement guarantee. Owner acknowledgement is not independent proof of VPN/mTLS; infrastructure verification and administrator approval remain required. No deferred minor findings.
