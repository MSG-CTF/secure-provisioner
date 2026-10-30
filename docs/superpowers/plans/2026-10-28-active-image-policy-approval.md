# Exact Active Image Policy Approval Plan

> **For agentic workers:** Use the existing TDD and verification workflows. Independent source/Backend and Cashout lifecycle tasks may be delegated; live mutations remain coordinated by the parent.

**Goal:** Complete the four exact active-image execution checks and promote only verified entries into the operating allowlist, preserving active release pointers and AFTERIMAGE hold.

**Architecture:** Preserve the existing27 entries. Test original Backend container-ID secret resolution without revealing values, use an isolated temporary Runtime database schema and loopback API for full Runtime/real-node/Gateway trials, and promote verified policy entries through normal reviewed deployment. Cashout needs an operator-owned fixed Python SIGINT preStop strategy because its immutable PID1 ignores SIGTERM. OSINT needs a root HTTPS navigation origin; its URL-shaped record is a honeypot and its real scoring answer is a separate source constant.

**Tech Stack:** Go1.26, existing PostgreSQL Runtime store, verified Broker TLS kubeconfig, K3s, existing Backend secret resolver, Gateway v1.

**Spec:** User explicitly asks to finish the remaining checks and place passed images into the allowlist. Prior constraints: no Backend active changes, no activation, no automatic/persistent Backend timer enablement, no AFTERIMAGE preparation, no raw secret disclosure.

## Global Constraints

- Immutable image/source bindings come from `outputs/active-image-preflight-20261028.json` and original 08:43 packet; Logout is revision552.
- Use only existing approved credentials and exact known references. No credential discovery outside the relevant configured services.
- Real flags stay in trusted server memory/namespace Secrets and are compared as booleans. Never print values or save them in local reports.
- Temporary Runtime trials use an isolated PostgreSQL schema, loopback-only API, distinct state directory and test-owned instance IDs; existing operations and participant workloads must remain untouched.
- Public Gateway tests create only short-lived test routes; delete through the owning control path and verify namespace and route removal.
- Backend current-active and static scoring metadata are authoritative external checks. If unavailable, keep affected entries withheld and request the existing operator route; do not infer success from source alone.
- Promote only narrow additions with compare-and-swap against the actual live policy hash; preserve all existing entries and current flags/target/worker settings.

## Review Focus

- Native K8s StopSignal can be silently dropped/degraded when alpha feature gates/CRI support are absent; use a fixed preStop strategy with actual exit-code evidence.
- Public clients must not supply the operator shutdown strategy or arbitrary lifecycle command.
- Propagate optional strategy through immutable resolved policy, persisted command hash and legacy equality, and verify readback catches drift.
- OSINT PUBLIC_ORIGIN is navigation configuration, not its final scoring answer; do not disable production validation merely to pass startup.
- Synthetic tests do not replace actual Backend resolution/scoring or public Gateway verification.

### Task1: Backend bindings and immutable scoring evidence

- [x] Resolve original Nerves and Logout container IDs with existing Runtime credential. Both SUCCESS with FLAG; the deployed unchanged Backend handler enforces actual scoring equality.
- [x] Confirm Cashout source answer equals its publication info answer and OSINT checker answer equals its publication info answer, without printing values.
- [x] Use the user-authorized Backend administrator session: all four active IDs/revisions/digest graphs match the original; Cashout/OSINT current scoring answers equal their immutable original info.yaml answers. Store booleans only.

### Task2: Cashout immutable-image shutdown

- [x] Add regression tests for the fixed operator shutdown strategy: catalog parsing/override, public request rejection, resolved-policy propagation, exact generated preStop and no accidental hooks on legacy images, deployment lifecycle drift, legacy command equality.
- [x] Observe RED against current code.
- [x] Implement the smallest `python_sigint_pid1` enum path; no arbitrary executable/argument input and no image rebuild.
- [x] Observe GREEN and run affected integration/unit suites. Independent review found and verified a fix for unchecked extra/duplicate/profile-mismatched persisted requirements; eight additional regressions observed RED/GREEN.
- [x] Prove the exact live-node image exits0 under the hook within its grace period, using an owned finalizer to retain terminal status before deletion; remove all test resources. Runtime-generated Deployment proof: two exits0 in0.864s/1.258s, restart and public health pass.

### Task3: Real Runtime and public Gateway trials

- [x] Start the existing verified Runtime artifact in an isolated schema/state directory and loopback port with a narrow candidate policy; repeat remaining cases with the candidate shutdown binary.
- [x] Nerves/Logout: send official create through the isolated API using real approved Backend secret references, verify Pod projected secret equality privately, public HTTPS health/function, Logout intended flow and9090 non-exposure, then official delete and cleanup proof.
- [x] OSINT: inspect and test the actual Backend environment without changing it. It is development/auto and restores an HTTP hidden URL through the TLS Gateway, failing the same-origin HTTPS solver contract. Keep this digest explicitly blocked. Production origin-before-start coordination is a required follow-up for author/Backend/Runtime; do not substitute a synthetic production setting to claim current-release readiness.
- [x] Cashout: prove fixed answer/scoring agreement and full generated lifecycle behavior.

### Task4: Reviewed promotion and final evidence

- [x] Prepare a candidate preserving current policy27 entries, adding three verified enabled records and one explicit OSINT blocked record with exact UID/profile/ports/readiness/secret/shutdown settings. Offline policy admission confirms3/4; OSINT remains denied for both create and preparation.
- [ ] Fresh independent review, targeted tests, full native Linux CI and standard deployment checks for code changes.
- [ ] Apply the reviewed policy atomically with rollback, verify loaded behavior and state/target/auth preservation, and synchronize encrypted deployment configuration without exporting secrets.
- [ ] Record per-image approval result and any externally blocked checks; retain cached images and original FAILED operation history.
