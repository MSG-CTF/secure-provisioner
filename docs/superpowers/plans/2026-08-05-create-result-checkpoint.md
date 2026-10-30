# Create Result Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist a successful Kubernetes create result before Runtime Binding finalization so in-process retries never invoke Kubernetes create twice.

**Architecture:** Store a validated, immutable create checkpoint separately from terminal `Operation.Result`. Worker checkpoints a fresh create result, resumes finalization from that checkpoint on retries, and promotes it only after the optional finalizer succeeds. Runtimeops separates K3s creation from UID-bound Binding save/cleanup finalization.

**Tech Stack:** Go, existing in-memory Operation/Binding stores, existing Worker and K3s executor abstractions, OpenAPI YAML.

## Global Constraints

- Keep Namespace adoption prohibited.
- Require nonblank `RuntimeWorkloadID` and `NamespaceUID` in a create checkpoint; do not add Namespace resourceVersion.
- Do not expose checkpoint or Namespace UID through HTTP or OpenAPI.
- Preserve DELETE and generic executor behavior.
- The MemoryStore checkpoint closes only in-process retries; document that restart recovery still requires a persistent Store.
- Stop and report before a second architectural approach.

---

### Task 1: Immutable Operation create checkpoint

**Files:**
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/store.go`
- Modify: `internal/operations/memory_store.go`
- Test: `internal/operations/memory_store_test.go`

**Interfaces:**
- Produces: `Operation.CreateCheckpoint *provisioner.CreateWorkloadResult`
- Produces: `Store.CheckpointCreateResult(string, provisioner.CreateWorkloadResult) (Operation, error)`
- Produces: `ErrCreateCheckpointConflict`

- [ ] **Step 1: Write failing MemoryStore tests**

Cover RUNNING CREATE acceptance, deep-copy isolation, exact idempotency, conflicting mutation rejection with stored-value preservation, invalid missing workload ID/UID, invalid state/type, and `MarkSucceeded` requiring an exact supplied result before promoting it to `Result` and clearing the checkpoint.

- [ ] **Step 2: Run focused RED**

Run: `go test ./internal/operations -run 'TestMemoryStore(CreateCheckpoint|PromotesCreateCheckpoint)' -count=1`

Expected: compilation fails because checkpoint fields/methods do not exist.

- [ ] **Step 3: Implement minimal Store state**

Add the checkpoint field, defensive result copy/equality/validation helpers, the Store method, and create-specific `MarkSucceeded` promotion. Keep DELETE `MarkSucceeded` unchanged.

- [ ] **Step 4: Run focused GREEN**

Run: `go test ./internal/operations -run 'TestMemoryStore(CreateCheckpoint|PromotesCreateCheckpoint)' -count=1`

Expected: PASS.

### Task 2: Worker checkpoint and resume flow

**Files:**
- Modify: `internal/operations/executor.go`
- Modify: `internal/operations/worker.go`
- Test: `internal/operations/worker_test.go`

**Interfaces:**
- Produces: optional `CreateResultFinalizer.FinalizeCreate(context.Context, Operation, provisioner.CreateWorkloadResult) error`
- Consumes: Task 1 checkpoint method and field.

- [ ] **Step 1: Write failing Worker tests**

Use the real MemoryStore with controlled executor/finalizer doubles to prove fresh CREATE order (`Execute`, checkpoint, finalize, success), retry from a retained checkpoint without a second Execute, cancellation immediately after checkpoint followed by requeue/resume, retryable finalizer max-attempt behavior, non-retryable finalizer failure, and success only after finalizer completion. Keep DELETE regression coverage unchanged.

- [ ] **Step 2: Run focused RED**

Run: `go test ./internal/operations -run 'TestWorker(CreateCheckpoint|ResumesCreate|RequeuesCheckpoint|FinalizesCreate)' -count=1`

Expected: tests fail because Worker executes again and has no finalizer stage.

- [ ] **Step 3: Implement the single checkpoint architecture**

For CREATE, use an existing checkpoint or execute and checkpoint a fresh valid result. Check cancellation only after persistence, invoke the optional finalizer, route errors through existing retry classification, and call `MarkSucceeded` only with the exact checkpoint. Leave DELETE execution on the current path.

- [ ] **Step 4: Run focused GREEN and operations regression**

Run: `go test ./internal/operations -count=1`

Expected: PASS.

### Task 3: Runtime Binding finalizer integration

**Files:**
- Modify: `internal/k3s/executor.go`
- Test: `internal/k3s/executor_test.go`
- Modify: `internal/runtimeops/service.go`
- Test: `internal/runtimeops/service_test.go`

**Interfaces:**
- Produces: K3s executor delegation from the operations finalizer to an optional create-adapter finalizer.
- Produces: runtimeops create adapter whose create stage invokes only K3s and whose finalizer invokes `createdBindingRecorder.Save`.

- [ ] **Step 1: Write failing executor/runtimeops tests**

Prove finalizer errors retain runtime error classification. At Service Worker level, script first Binding save failure plus retryable cleanup failure, then successful Binding save: operation succeeds on attempt two, the exact UID checkpoint is used, cleanup is invoked once, and underlying create count stays one. Add cleanup-success and non-retryable-cleanup terminal cases, retained checkpoint/max-attempt assertions, and a binding-save gate proving the operation remains RUNNING with no terminal result until commit completes.

- [ ] **Step 2: Run focused RED**

Run: `go test ./internal/k3s ./internal/runtimeops -run 'TestExecutorFinalizesCreate|TestServiceWorker(CreateCheckpoint|DoesNotRecreate|WaitsForBinding)' -count=1`

Expected: tests fail because Binding save still occurs inside initial Execute and retries rerun create.

- [ ] **Step 3: Split create and finalization**

Make runtimeops `CreateWorkload` call only the inner adapter and add finalization that calls the existing recorder. Delegate through K3s executor and preserve its stable error classification. Keep direct synchronous `Service.CreateWorkload` behavior unchanged.

- [ ] **Step 4: Run focused GREEN and package regressions**

Run: `go test ./internal/k3s ./internal/runtimeops -count=1`

Expected: PASS.

### Task 4: Public contract and durability documentation

**Files:**
- Test: `internal/httpapi/runtime_test.go`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `docs/api/runtime-operations.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: checkpoint remains separate from `Operation.Result`.
- Produces: complete OpenAPI 409 identity/ownership examples with no UID values.

- [ ] **Step 1: Write failing HTTP non-exposure test**

Construct a RETRYING create Operation containing a checkpoint and assert the serialized response has no `result`, `namespace_uid`, or checkpoint field. Retain the SUCCEEDED Namespace UID non-exposure regression.

- [ ] **Step 2: Run RED/GREEN around public mapping**

Run before implementation changes: `go test ./internal/httpapi -run 'TestGetOperation.*Checkpoint' -count=1`

Expected RED: compilation fails because `CreateCheckpoint` does not exist. After Task 1, rerun and expect PASS because status-gated mapping ignores the checkpoint.

- [ ] **Step 3: Update OpenAPI and durability prose**

Describe runtime-status 409 as identity or ownership mismatch and add `RuntimeIdentityMismatch` with only code/message. Document checkpoint ordering and the MemoryStore process-restart limitation without claiming durable restart recovery.

### Task 5: Full verification and implementation commit

**Files:**
- Append ignored report: `.superpowers/sdd/2026-08-05-runtime-isolation-policy-mvp/task-12-provisioner-fix.md`

- [ ] **Step 1: Run focused checkpoint/security tests**

Run the exact focused commands from Tasks 1-4 plus the existing Namespace adoption/UID/delete focused tests.

- [ ] **Step 2: Run full verification**

Run:

```text
go test ./... -count=1 -timeout=120s
go test -race ./... -count=1 -timeout=180s
go vet ./...
go build -buildvcs=false ./...
go test ./internal/k3s -run '^TestK3sIntegration' -count=1 -v -timeout=30s
git diff --check a802623..HEAD
```

- [ ] **Step 3: Commit the implementation**

Commit the code/tests/docs separately from the design and plan commits with a message scoped to create-result checkpointing.

- [ ] **Step 4: Append the ignored Round 2 report**

Record RED/GREEN evidence, final commands, commit IDs, clean status, integration skips, MemoryStore restart boundary, and that no live K3s enforcement was attested.
