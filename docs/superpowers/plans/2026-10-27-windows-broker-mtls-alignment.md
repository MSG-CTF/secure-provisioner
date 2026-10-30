# Windows Broker mTLS Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make PR #97's Runtime use the deployed Broker certificate and VM mTLS contract while preserving its static HTTPS mode.

**Architecture:** Add an alternate `https_executor` configuration with a client certificate/key and Broker-discovered targets. Persist the Broker server certificate in the existing connection record. Validate it before `started`, then pin it and present the client certificate during VM PUT/GET/DELETE.

**Tech Stack:** Go standard library TLS/HTTP, PostgreSQL-backed Windows execution store, Go tests.

**Spec:** `docs/superpowers/specs/2026-10-27-windows-broker-mtls-alignment.md`

## Global Constraints

- Never send a Broker or Backend token to the VM in mTLS mode.
- Never use unverified TLS for execution; the unverified handshake was diagnostic only.
- Preserve static HTTPS and RDP behavior.
- `started` must be confirmed before VM use; correlated `finished` must be durable before Backend `RESULT`.

## Review Focus

- A malformed or mismatched Broker certificate must prevent `started` and VM upload.
- A server certificate change after a job starts must prevent recovery from trusting the new server.
- A Broker READY list race must not permit upload after a 409 `started`.
- A missing client key must fail startup without leaking path or key contents.
- Dynamic target selection must still require Broker discovery and a canonical target ID.

---

### Task 1: Broker certificate and configuration

**Files:** `internal/windowsruntime/types.go`, `broker.go`, `config.go`, `executor_transport.go`, corresponding tests.

**Interfaces:** Connection gains `ExecutorCertificatePEM`; HTTPSExecutorConfig gains client certificate/key paths and a dynamic-mode predicate.

- [x] Add failing tests for Broker PEM parsing and mTLS configuration validation.
- [x] Run targeted tests and confirm failure.
- [x] Implement the fields and validation; run targeted tests green.
- [x] Commit.

### Task 2: VM mTLS transport and pre-start validation

**Files:** `internal/windowsruntime/executor_transport.go`, `service.go`, corresponding tests.

**Interfaces:** `ValidateConnection(Connection) error` verifies Broker certificate before `started`; transport uses mTLS and exact pinning for the persisted connection.

- [x] Add failing mTLS execution and invalid-certificate-before-start tests.
- [x] Run targeted tests and confirm failure.
- [x] Implement the mTLS branch and service preflight; run targeted tests green.
- [x] Commit.

### Task 3: Dynamic Broker pool and integration

**Files:** `internal/windowsruntime/service.go`, `checker.go`, `cmd/provisioner/windows.go`, config/example docs, corresponding tests.

**Interfaces:** `SetPoolAnyTargets()` selects Broker READY targets in mTLS mode; static mode retains its allowlist.

- [x] Add failing dynamic-pool checker tests.
- [x] Run targeted tests and confirm failure.
- [x] Implement pool selection and startup wiring; update operations/config docs.
- [x] Run relevant Go tests, inspect diff, and commit/push PR #97.
