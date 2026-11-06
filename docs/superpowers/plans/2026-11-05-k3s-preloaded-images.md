# K3s preloaded images implementation plan

> **For agentic workers:** Execute inline in this isolated worktree using TDD.

**Goal:** New K3s challenge instances start only from approved images already on
the selected execution node, preserving existing isolation and lifecycle.

**Architecture:** Reuse image preparation observations plus current node identity;
gate creation before Namespace mutation, require cache-ready node placement, and
render Kubernetes `Never`. Keep API image identities and existing resource layers.

**Tech stack:** Existing Go/Kubernetes clients, imageprep store and trusted agents.

## Failure cases to pin

- No callback, preparation disabled, stale/unavailable evidence: IMAGE_NOT_READY,
  no Namespace or child-resource mutations.
- Replaced, rebooted, cordoned or wrong-platform node: old evidence cannot place
  a new instance there.
- Multi-container graph with one missing image: no partial workload creation.
- Cache loss after observation or pull-policy drift: no registry fallback.
- Existing instances and platform/affinity restrictions: preserve lifecycle and
  placement constraints.

## Task 1: Local-only rendering and placement

Files: `internal/k3s/resources.go`, `internal/k3s/imageprep.go`, their tests.
Write failing tests for `Never` and required prepared-node affinity; implement the
minimal rendering change and AND node-name restrictions into existing terms.
Keep API-default normalization faithful to Kubernetes (`IfNotPresent` for an
omitted pull policy), so an omitted or changed `Never` cannot pass verification.

## Task 2: Prepared-node evidence and create gate

Files: `internal/imageprep/service.go`, its tests; `internal/k3s/adapter.go`, adapter
fixtures and tests; `cmd/provisioner/main.go` only if its wiring needs adjustment.
Keep `ReadyNodes(ctx, target, arch, images) []string`; filter existing complete,
fresh evidence against `Inventory.Nodes` before returning names. Before any new
Namespace, treat no prepared names as retryable IMAGE_NOT_READY and preserve
cleanup proof through the existing fail-before-Namespace path. Use a bounded
five-second readiness lookup. Update real callers and controlled test fixtures.

## Task 3: Rollout contract and verification

Files: existing image-preparation operations docs and Runtime API error guidance.
Document the preparation prerequisite, exact containerd store/reference identity,
strict miss behavior, node replacement/GC and ordering. Run focused red/green
tests, then the complete Go suite on Linux and diff checks. Review the final diff
before proposing the change. Live canary/deployment follows verified image-node
readiness; it is not replaced by unit tests.
