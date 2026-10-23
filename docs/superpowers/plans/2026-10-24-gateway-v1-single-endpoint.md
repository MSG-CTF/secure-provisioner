# Gateway v1 Single Endpoint Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; parent performs the final review.

**Goal:** Add opt-in Gateway v1 routing for K3s NodePort workloads with exactly one public endpoint and private sidecars.

**Architecture:** A Gateway adapter wraps K3s create/delete/cleanup, persists immutable route intent before PUT, and replays the original tuple after interruption. PostgreSQL journal locks serialize per-instance mutations; DELETE tombstones precede namespace/port release. Existing async admission, security, worker checkpoints and Binding finalize remain in place.

**Tech Stack:** Go, net/http, PostgreSQL via existing runtimepg database/sql, fake TLS Gateway and fake Kubernetes, WSL test execution.

**Spec:** User-supplied Runtime → Gateway API v1.0.0; accepted scope: private sidecars, one public endpoint, opt-in K3s NodePort only, default off. Design rationale: docs PR #74.

## Global Constraints

- No production Gateway calls, tokens, configuration, or services changed.
- HTTPS verification and token file required; request timeout >=75s (default90s).
- Public upstream IP is explicit; target port is Kubernetes allocated NodePort.
- PUT/DELETE only in worker execution, never HTTP admission/enqueue mutex.
- Durable immutable intent before HTTP; DELETE204 before actual port release; original instance ID never changed by retry.
- Preserve policy, isolation, architecture and readiness of every container.
- Gateway 2xx means control plane applied, not verified DNS/TLS/service availability.

## Review Focus

- Crash after PUT/before local checkpoint reuses tuple; GET200 does not prove destination.
- GET404 is not tombstone; timeout/exhaustion cannot free NodePort.
- Binding finalize failure uses Gateway-aware cleanup.
- Lease reclaim/concurrent replica must not release a port while a stale PUT can succeed.
- TCP TLS/SNI metadata must survive DB/API; current Scheduler forwarding is separate work.

## Tasks

- [x] HTTP client: TLS token injection, identical retry, limited response/error decoding, 204, redirect rejection, validation.
- [x] Domain/config/admission: target opt-in with public IP, NodePort requirement, exactly one exposed port at admission/replay; missing Postgres/client fails startup.
- [x] Durable journal: immutable route identity/generation and result; PostgreSQL session advisory lock + memory test store; restart-safe replay and tombstone phase.
- [x] Adapter: journal before PUT, replay result, Gateway-aware delete/failed-create cleanup, Service retained until204, held retry semantics on uncertain remote state.
- [x] Wiring and TCP metadata: hostname, connection_port, tls, server_name copied through create/checkpoint/Binding/API; operator configuration and Scheduler cleanup contract docs.
- [x] Focused RED→GREEN tests, PostgreSQL recovery tests, current-source Linux full suite and OpenAPI validation.
- [ ] Final vet/diff evidence, commit and draft implementation PR.

## Execution ledger

- Scope A confirmed by user; docs #74 updated separately. No Compose VM Gateway support in first release.
- Ruling: scale owned Deployments to zero while preserving Service objects; retry namespace deletion after Gateway DELETE204. A pod-stop error must not prevent removing a stale public route; it leaves cleanup pending. Existing connections are only considered terminated after actual namespace/workload absence, not merely after route deletion.
- HTTP client RED (missing types) → GREEN5 Gateway client/adapter tests; held retry RED → GREEN1 worker test. PG journal RED → GREEN2 real DB tests; service status/DTO regressions RED identified and repaired missing cleanup_pending mapping and recovery binding scope.
- Ruling: use a separate 8-connection lock pool and nonblocking lifecycle admission, preserving the 30-connection operation/lease pool. A real PG regression first exhausted a shared one-connection pool, then passed with separate pools. Eight is a fixed safety bound, not a measured optimum.
- Independent parent review repaired backend runtime-error/cleanup-proof classification and foreign-route TARGET_IN_USE ownership: durable CONFLICT_HOLD, quiesce, immutable same-tuple PUT positive proof, DELETE204, then actual deletion. No foreign ID guessing/deletion. Crash/commit and SQL phase-regression tests pin this behavior.
- Final current-source `GOOS=linux CGO_ENABLED=0 go test -exec <WSL wrapper> -gcflags=all=-trimpath=<Windows repo>=><WSL repo> -p 1 ./... -count=1 -timeout 5m`: 13 packages passed, including real dedicated local PostgreSQL integration. Fake TLS Gateway and fake Kubernetes only; no production Gateway calls or real K3s test.
