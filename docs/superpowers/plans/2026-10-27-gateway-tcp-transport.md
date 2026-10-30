# Gateway TCP Transport Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Consume Gateway-assigned TCP ports without changing existing HTTPS/TLS routes or deploying infrastructure.

**Architecture:** Gateway remains the owner of public port allocation. Runtime validates its returned transport, journals it, and preserves that transport in participant-facing endpoints. The current request contract remains unchanged.

**Tech Stack:** Go, Kubernetes, PostgreSQL journal, OpenAPI 3.1.

**Spec:** Accepted scope below, authorized in the conversation on 2026-10-27.

## Accepted scope

- Keep the instance-specific subdomain under `gate.msgctf.kr`; do not accept arbitrary hosts or fabricate public ports from NodePorts.
- Preserve current HTTP behavior: HTTPS URL, TLS, port 443. TCP may return a validated port from 1 through 65535 and explicit TLS true or false.
- Reject missing/null TLS metadata rather than silently downgrading a route to plaintext.
- Use `tls://` plus SNI for encrypted TCP and `tcp://` without SNI for plaintext TCP. Keep the container's `port` separate from `connection_port`.
- Preserve explicit `tls=false` on the HTTP API while keeping transport metadata absent for legacy endpoints.
- Do not implement Gateway listeners, allocation, firewall, VPN, ownership enforcement, deployment, or merge. Leave completed work in commits.

## Global Constraints

- No new dependencies or changes to the authenticated HTTPS management channel.
- Existing Gateway lifecycle, immutable upstream intent, and cleanup proofs remain unchanged.

## Review Focus

- Missing/null TLS must fail validation; it must not become an nc-compatible endpoint accidentally.
- HTTP cannot become plaintext or acquire an arbitrary public port.
- Recovered journal records must retain public ports and clear plaintext SNI.
- Legacy endpoints must not gain a misleading TLS flag.
- Invalid domains, protocol mismatches, ports outside 1..65535, and TCP URL payloads remain rejected.

### Task 1: Gateway validation and endpoint recovery

**Files:** `internal/gateway/client.go`, `client_test.go`, `adapter.go`, `adapter_test.go`.

**Interfaces:** Existing `Destination` request and `Route` response; output `provisioner.WorkloadEndpoint` with actual hostname/connection port/TLS.

- [x] Add tests for dynamic plaintext/encrypted TCP responses, malformed metadata, HTTP invariants, and journal recovery.
- [x] Run `go test ./internal/gateway` and observe the new behavior fail.
- [x] Validate explicit TLS and port bounds; derive public endpoint transport from the saved Route.
- [x] Run the Gateway suite and full Go suite. Expected: pass.

### Task 2: Wire contract and operations documentation

**Files:** `internal/httpapi/runtime.go`, `gateway_transport_test.go`, `docs/api/secure-provisioner.openapi.yaml`, `docs/operations/gateway-v1.md`.

**Interfaces:** Runtime JSON endpoints consumed by Scheduler/Backend; explicit boolean false and optional SNI.

- [x] Add a JSON serialization test for plaintext false, encrypted true, and legacy omission; observe failure.
- [x] Preserve boolean presence at the API boundary and update the schema/examples.
- [x] Run full Go tests, relevant race tests, and vet. Expected: pass.
- [x] Review the diff and commit the complete Runtime change without merging or deploying.

## Verification

- Linux `go test ./...`, `go test -race ./internal/gateway ./internal/httpapi`, and `go vet -buildvcs=false ./...` passed.
- `go build -buildvcs=false ./cmd/provisioner` passed; OpenAPI YAML parsed successfully.
- Existing Backend `GatewayEndpointNormalizationTests` passed (5 tests).
- Independent review found no actionable Runtime issues. Gateway deployment and external plaintext connectivity remain outside this change.
