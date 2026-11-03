# Image Prefetch Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare approved Broker-backed enrollment, durable registration receipts and read-only preparation evidence collection.

**Architecture:** Extend the existing protected Python enrollment CLI without changing defaults. Add a separate evidence CLI and local receipt contract; reuse current Runtime APIs and agent protocol.

**Tech Stack:** Python 3.10+ standard library, existing kubectl/K3s, unittest, systemd examples. No new dependency or service authentication.

**Spec:** docs/superpowers/specs/2026-10-28-image-prefetch-lifecycle-design.md

## Global Constraints

- Only approved resources/machine/provider/name/architecture/agent bindings may be enrolled. No arbitrary target discovery or implicit machine replacement.
- Default behavior and static-registry callers remain compatible. No live consumer settings, workload, cache deletion, image pull, new preparation/retry or release activation.
- Freeze and validate credentials before node calls; keep tokens, raw configs, env and flags out of all output.
- Preserve complete previous registration on failure, and distinguish historical operation completion from current readiness.

## Review Focus

- Stale, duplicate, mismatched or disabled Broker entries must not silently replace trusted static targets.
- Credential plugins/file references and concurrent source edits must never reach an executable root request path.
- Dry runs and failed publication must not emit successful receipts; replay/crash recovery must not duplicate or lose the current generation.
- An API operation with the wrong release, image set, target or request must be rejected before collecting a misleading result.
- Cached content and inspection/poll timing must not be represented as measured cold-pull telemetry.

### Task 1: Broker-backed enrollment snapshots

**Files:** deploy/image_prefetch_enroll.py; deploy/test_image_prefetch_enroll.py

**Interfaces:** `reconcile(..., broker_state_path=None, events_dir=None)`; optional policy resource binding and target rotation flag; protected temporary inventory context.

- [ ] Add behavioral tests for a target present only in admitted Broker state, explicit canonical rotation and unchanged machine/provider pins. Run and observe RED.
- [ ] Implement bounded protected state lookup/materialization and CLI flags, retaining existing defaults. Observe GREEN.
- [ ] Add negative tests for ambiguity, disabled/identity/platform/collision cases, unsafe credentials and source cleanup. Run existing enrollment suite on Windows and Linux.

### Task 2: Durable registration receipts and integration examples

**Files:** deploy/image_prefetch_enroll.py; deploy/test_image_prefetch_enroll.py; deploy/image-prefetch-enroll.service; deploy/image-prefetch-provisioned-hook.example.sh; deploy/image-prefetch-enrollment.example.json; docs/operations/image-prefetch-enrollment.md

**Interfaces:** immutable version1 generation receipt under `--events-dir`, no credential or job side effects.

- [ ] Test no event before successful apply, duplicate ticks, changed boot, immutable conflict, unsafe output, dry-run and recovery after nodes publication. Observe RED.
- [ ] Implement bounded atomic event emission and integrate shared revision/lock checks. Observe GREEN.
- [ ] Document/example the optional Broker inventory and event contract, approved operating timer setup, provider approval and Backend dedup/new-request responsibility. Keep new options opt-in.

### Task 3: Preparation evidence collector

**Files:** deploy/image_preparation_evidence.py; deploy/test_image_preparation_evidence.py; deploy/image_prefetch_enroll.py; docs/operations/image-preparation.md

**Interfaces:** read-only snapshot/collect CLI; protected manager token; explicit expected operation scope; optional validated cache snapshots.

- [ ] Test valid and mismatched operation/readiness scope, current observation timestamps, exact image identities, and warm/unknown telemetry classification. Observe RED.
- [ ] Implement bounded no-redirect HTTPS reads, sanitized reports, explicit no-pull cache capture and safe output handling. Observe GREEN.
- [ ] Test malformed/oversized/redirect/error responses and no sensitive data in output; ensure no create/retry/pull endpoints are called.

### Task 4: Verify and publish

- [ ] Run focused suites and full deployment Python regressions; run appropriate syntax/vet/build checks and report skips honestly.
- [ ] Obtain a fresh independent whole-change review and fix important findings with red/green verification.
- [ ] Perform a bounded operating enrollment dry-run if current approved inputs support it; no live activation.
- [ ] Commit/push a new feature branch, open/attach a PR, verify exact-head CI and leave activation/Backend integration boundaries explicit.
