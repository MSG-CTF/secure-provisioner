# Challenge Network Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Preserve challenge-specific network boundaries without changing caller network permissions or bypassing Backend Secret approval.

**Architecture:** Reuse the existing PR #49 snapshot pipeline on dev. Add Compose membership groups, exact-host TCP egress exceptions and persistent repository requirements in operator policy; ship inactive challenge contracts until activation prerequisites are satisfied.

**Tech Stack:** Go, Kubernetes NetworkPolicy, existing PostgreSQL JSON snapshots, Python diagnostics.

**Spec:** `docs/superpowers/specs/2026-10-23-challenge-networks-design.md`

## Global Constraints

- Public Create JSON remains unchanged; internal_connections stays rejected.
- Ordinary STANDARD@v2 and legacy v1 behavior remain compatible.
- Existing operation replay preserves accepted snapshots.
- Do not deploy candidate graphs, unapproved images or placeholder addresses to production.
- Keep Secret values and authentication tokens out of output and version control.

## Review Focus

- Graph removal plus digest rotation must not restore full mesh for network-required repositories.
- A known source container must not gain egress to broad, reserved or invalid address ranges.
- Overlapping groups must not create transitive reachability through a middle peer.
- Fingerprinted HTTP replay after catalog changes must retain the original saved graph.
- Live CNI behavior and NodePort exceptions must be distinguished from generated manifest assertions.

## Task 1: Recover current Secret references

- [x] Resolve all distinct recorded image/container/reference combinations without printing values.
- [ ] Obtain Backend administrator access or current release metadata; repair actual release Secret bindings through supported Backend controls.
- [ ] Retry only exact approved images with valid references, observe normal service behavior and verify deletion.

## Task 2: Extend the operator network implementation

Files: `internal/isolation/workload_network*.go`, `internal/httpapi/image_policy.go`, associated HTTP tests, `internal/k3s/network_policies.go` and network tests; existing snapshot/storage tests.

- [x] Preserve an old branch reference; merge current origin/dev into the existing isolated PR #49 worktree.
- [x] Add failing tests for PEER_GROUPS_V1, nontransitive membership, exact-host egress validation, deep clone and explicit network_required_repositories.
- [x] Implement minimal additions and generated Kubernetes policies; preserve exact-policy readback and current fingerprint replay.
- [x] Add a real HTTP fingerprint replay test after graph change/removal and reject caller policy fields.
- [x] Run targeted packages, full Go suite and diff checks.

## Task 3: Configure challenge contracts and verify CNI

Files: `config/challenge-networks/`, `docs/operations/workload-network-policies.md`, scoped diagnostic script outside the production catalog.

- [x] Record official Afterimage groups and each KOTH directed edge/external requirement with source commit and explicit activation blockers.
- [ ] Generate candidate policies only from approved images and concrete destinations; reject placeholders rather than enabling them.
- [x] Exercise allowed group peers, denied nonpeers, DNS, allowed exact egress and denied other egress in disposable K3s namespaces, then verify cleanup.
- [x] Review the implementation independently and report exact deployed versus candidate status.

Secret recovery is blocked on Backend administrator access/current release metadata. All 88 recorded reference combinations were checked; no replacement references were found for the seven blocked problems. The production binary and image catalog remain unchanged. Actual graph activation remains blocked on reviewed image sets, valid release references and real operator destination addresses. See `docs/testing/challenge-networks-20261023.md` for the 145-check live diagnostic evidence and limits.
