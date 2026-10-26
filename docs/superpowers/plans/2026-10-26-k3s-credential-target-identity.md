# K3s Credential Target Identity Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Make certificate imports automatically register the lifecycle target ID used by Scheduler.

**Architecture:** Broker adds current `target_id` to existing credential responses. A Runtime import command verifies the node UID and native registry parser before preparing its private kubeconfig and a separate immutable registry candidate; existing API identities and security approvals remain separate.

**Tech Stack:** Python 3.12, FastAPI/Pydantic/SQLAlchemy, PostgreSQL, Python unittest, kubectl and OpenSSL.

**Spec:** ../specs/2026-10-26-k3s-credential-target-identity-design.md

## Global Constraints

- No token, kubeconfig private key or FLAG in logs/output.
- Keep credential lookup keyed by resource_target_id and Scheduler lifecycle requests keyed by target_id.
- Do not restart services, create workloads or clean production state during import.
- Never guess a missing node ID or overwrite an unrelated registry entry.

## Review Focus

- Missing/stale node identity must prevent registration.
- Credential responses and kubeconfig endpoints/certificate fingerprints must agree.
- An old registry ID may still own cleanup operations; preserve it or reject migration.
- Failed validation must leave the existing registry and credentials usable.
- Re-import and concurrent registry changes must not duplicate targets or lose updates.

### Task 1: Expose the Broker lifecycle target ID

**Files:** Broker app/schemas/k3s_credential.py, app/services/k3s_credential_service.py, app/api/runtime_k3s_credentials.py, tests/api/test_k3s_credential_pull.py, docs/RUNTIME_K3S_CREDENTIAL_API.md and its OpenAPI file.

**Interfaces:** Produces `target_id: str | None` on credential list and detail items; consumes current Kubernetes resource observation.

- [x] Add assertions for distinct resource/node IDs on list/detail, changed node UID, and missing node ID; run and observe the missing-field failure.
- [x] Add the response/service field and read it from the existing resource relation; keep non-Kubernetes/missing identities null.
- [x] Run focused and full Broker pytest against an isolated database; update both API documents.

### Task 2: Import verified identity into Runtime registry

**Files:** deploy/import_broker_k3s_credentials.py, deploy/test_import_broker_k3s_credentials.py, docs/operations/broker-k3s-credentials.md.

**Interfaces:** Consumes the Broker response, a policy-approved cluster template and registry JSON. Produces private credential file, canonical target registry entry and non-secret stdout metadata.

- [x] Write importer tests covering the spec and review-focus cases; run before implementation.
- [x] Implement fetch/validate/observe/atomic-import functions and CLI using standard library plus installed kubectl/OpenSSL.
- [ ] Run focused importer tests and full deploy unittest suite on Linux, plus existing Runtime Go suite when dependencies are available.
- [x] Document commands, old-Broker failure, bootstrap-before-observation retry, migration and restart boundaries.

Ruling after review: use the real Runtime registry validator, not a partial
Python copy of configuration rules. Produce a candidate instead of replacing
the live registry; arbitrary non-cooperating writers cannot be protected by an
advisory lock. This preserves live edits and moves activation to the existing
deployment exclusion boundary. Both findings have RED-to-GREEN regressions.

### Task 3: Review and deliver

**Interfaces:** Both changes remain additive and independently reviewable; consumer import requires the new advertised field.

- [ ] Review both diffs together and obtain a fresh code review; address material findings with regression tests.
- [ ] Commit tested changes on feature branches; provide reviewable PRs where repository permissions allow.
- [ ] Report actual validation, production deployment state and remaining rollout steps.
