# Gateway Public TCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Allocate persistent public Gateway ports for new TCP instances and return usable nc connection metadata while preserving web routes.

**Architecture:** Extend the inspected Python Gateway controller and FastAPI schema in a standalone deployment bundle. Keep the existing three-field Runtime request and default-off Gateway configuration. Use the existing durable registry lock/journal, actual listener checks and per-port TCP connection shutdown.

**Tech Stack:** Python 3.12+, FastAPI/Pydantic, Linux iproute2 ss, NGINX stream, existing Go Runtime and frontend consumers.

**Spec:** `docs/superpowers/specs/2026-10-27-gateway-public-tcp-design.md`

## Global Constraints

- TCP behavior follows protocol, not challenge category; HTTP remains TLS/443.
- Public nc has no team authentication; no false owner-enforcement acknowledgement.
- Existing TLS routes and the three-field PUT contract remain compatible.
- No secrets or live route records in the repository.
- Commit/push only; no PR, merge, deployment or production route mutation.

## Review Focus

- Pool exhaustion, occupied host sockets and concurrent allocations cannot duplicate ports.
- Replayed legacy routes retain TLS even after pool activation; saved plaintext ports survive restart/config changes.
- NGINX asynchronous reload failure cannot be mistaken for listener readiness.
- Delete cannot recycle a port while old listeners/connections survive; failure retains ownership.
- Plaintext TCP forwards unmodified bytes while HTTP and TLS paths still work.

### Task 1: Import baseline and extend durable allocation

**Files:** `deploy/gateway/gateway/{__init__,controller,main}.py`, `requirements.txt`, provenance and `tests/test_controller.py`.

**Interfaces:** existing `dispatch(request) -> (status, body)` and `parse_registry/render`; new optional `tcp_public_ports` configuration and persisted per-route `public_port`.

- [x] Import verified baseline and characterize unchanged HTTP, TLS TCP, authentication, replay and deletion.
- [x] Add failing tests for new TCP pool allocation, occupancy, exhaustion, replay/restart, concurrent calls and malformed registry records; observe failures.
- [x] Implement allocator/registry/render/response schema with minimal changes; run full Gateway suite.

### Task 2: Listener and connection cleanup proof

**Files:** `deploy/gateway/gateway/controller.py`, `tests/test_tcp_ports.py`, `tests/test_nginx_integration.py`.

**Interfaces:** listener readiness/absence checks, per-port accepted-socket destruction and no-active-connection verification; failures raise controller errors before ownership is released.

- [x] Add failing behavioral tests for reload not taking effect, failed deletion/rollback and retained active sockets.
- [x] Implement Linux socket inspection and cleanup under the existing controller lock and rollback journal.
- [x] Run actual isolated NGINX + backend + nc tests: routing bytes, public metadata, active-client disconnection, port reuse and unchanged TLS/HTTP route.

### Task 3: Contract verification, operations and review

**Files:** `deploy/gateway/README.md`, systemd/config examples, `docs/operations/gateway-v1.md` and this plan.

- [x] Document installation prerequisites, dedicated/reserved port pool, firewall scope, lifecycle and safe upgrade/rollback without applying anything remotely.
- [x] Run existing Go Gateway/API tests and frontend command tests, Gateway full suite, compile checks and diff checks.
- [x] Request independent review, fix actionable findings with regression tests and record results.
- [x] Commit and push the feature branch; verify remote SHA and clean working tree. No production changes.

## Verification and review record

- Local Python full discovery: 25 tests passed, 3 explicit privileged integration
  tests skipped. FastAPI tests exercised real HTTP request/response validation
  and management authentication with synthetic credentials.
- The skipped integration tests and controller/socket tests ran inside a fresh
  network namespace on the Gateway host with loopback only, sanitized environment,
  private temporary source/config/state and a separate NGINX prefix: **25 passed**.
  These two runs cover all **28 distinct tests** without any production route,
  source, service or firewall mutation.
- Actual nc binary data/EOF, accepted connection termination, same-port reuse,
  retained HTTPS connection, existing TCP/TLS across activation, and asynchronous
  NGINX bind/reload failure were exercised. Twelve concurrent creates received
  twelve distinct durable ports. Repeated cleanup failure and crash recovery
  retained allocation ownership.
- Existing Go packages `internal/gateway`, `internal/httpapi`, `cmd/provisioner`
  passed; frontend connection-command tests passed 5/5. No Go/frontend product
  code changed in this iteration. Python compilation and whitespace checks passed.
- A fresh independent review identified one P1: failed recovery could forget
  cleanup ports after restoring the registry. Regression tests reproduced it;
  the journal now persists/validates `rollback_ports` before registry restoration,
  including upgrades of interrupted old journals. Full suites passed after the fix.
  Review also requested the real TLS/reload-failure cases above; both passed.
  No minor findings were deferred. No second review was dispatched.
- Production audit: original source hashes unchanged, original service PID active,
  new pool setting absent; its service bounding set includes CAP_NET_ADMIN.

## Decisions and practical limits

1. Public access without owner authentication is the user's explicit scope.
   Anyone who learns the hostname/port can connect; no owner acknowledgement is sent.
2. Store the inspected Gateway implementation in the writable Runtime repository
   as a standalone deployment bundle with baseline hashes. The operator must
   separately deploy that bundle; Runtime deployment does not install it.
3. Preserve existing three-field requests and all legacy assignments. Activating
   the Gateway pool affects only new TCP routes, so existing TLS instances require
   recreation to receive an nc endpoint.
4. Keep privileged helpers in the existing root-owned controller to preserve the
   isolated Python invocation. Its code/parent directories must stay unwritable
   to the API service user.
5. Use the existing NGINX and per-port Linux socket cleanup, not a new proxy daemon
   or global worker shutdown. Reserved dedicated ranges and kernel/service
   capabilities are mandatory; unsupported cleanup holds ownership instead of
   recycling ports.
6. WSL cannot destroy TCP sockets with its current kernel. Root integration tests
   used a separate server network namespace and fake data, not the production
   namespace. This does not verify cloud ingress or a deployed participant flow.
7. Keep the existing isolated feature branch; retain the owner draft disabled.
   No PR/merge/deployment is authorized in this iteration.

Review exclusions ruled on: team authentication remains out of scope by user
choice; production firewall/DNS/rollout requires a separate deployment action;
preexisting HTTP/TLS reload acknowledgement behavior is preserved, while real
legacy connectivity is covered; Runtime/frontend were verified with their
existing consumer tests, without claiming a deployed end-to-end test.
