# Create Result Checkpoint Design

## Goal

Prevent an in-process CREATE retry from invoking Kubernetes creation again after Kubernetes already returned a successful, UID-bound result but Runtime Binding finalization failed.

## State model

`operations.Operation` gains an internal `CreateCheckpoint` field separate from its terminal `Result`. The checkpoint contains the complete `provisioner.CreateWorkloadResult`, including the internal Namespace UID. It is stored only for a RUNNING CREATE operation after the underlying executor succeeds and before Runtime Binding finalization begins.

`Store.CheckpointCreateResult` validates that the result has a nonblank runtime workload ID and Namespace UID. It deep-copies endpoint slices, accepts an identical repeated checkpoint idempotently, and rejects a different checkpoint without changing the stored value. Queued, retrying, terminal, and DELETE operations cannot create or mutate a checkpoint.

The MemoryStore is the current persistence boundary. This closes in-process retries and cancellation/requeue, but it does not survive process restart. A production persistent Store must persist the same checkpoint atomically with its operation state.

## Worker flow

For a fresh CREATE attempt, Worker calls the executor once, validates and checkpoints the successful result, checks cancellation, invokes an optional create-result finalizer, and marks the operation succeeded only after finalization succeeds. `MarkSucceeded` promotes the checkpoint into the terminal public `Result` and clears the checkpoint.

For a retried CREATE with a checkpoint, Worker skips `Execute`, invokes the finalizer with the checkpointed result, and promotes it on success. Retryable finalizer failures retain the checkpoint through `RETRYING` and `QUEUED`. Non-retryable failures and max-attempt exhaustion mark the operation failed without exposing a result.

DELETE and generic executors keep their existing behavior. An executor that does not implement the optional finalizer treats checkpointing as the only CREATE finalization step.

## Runtime binding boundary

The runtimeops create adapter is split into two responsibilities. `CreateWorkload` calls only the underlying K3s adapter. Its optional finalizer calls `createdBindingRecorder.Save`, which either commits the UID-bearing Binding or performs the existing independent-context, UID-bound cleanup after a save failure.

If save plus cleanup fails retryably, the next Worker attempt reuses the checkpoint and never invokes K3s create again. Cleanup success or a non-retryable cleanup failure follows the existing non-retryable operation-failure classification.

## Public contract

Checkpoint state is internal. QUEUED, RUNNING, RETRYING, and FAILED operation responses never contain the checkpoint or a partial create result. Only SUCCEEDED exposes the promoted result, and Namespace UID remains omitted.

The runtime-status OpenAPI 409 response documents both ownership and identity mismatch examples. The identity example contains only the stable code and generic message, never either expected or observed UID.

## Verification

Tests cover checkpoint validation, deep-copy isolation, idempotency, immutability, conflict, cancellation/requeue, skip-execute retry, finalizer ordering, retry/max-attempt behavior, cleanup outcomes, and public non-exposure. Full Go unit, race, vet, build, integration-skip, and diff checks remain required.
