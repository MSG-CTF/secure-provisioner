# Scoped enrollment retention plan

Spec: docs/superpowers/specs/2026-10-28-scoped-enrollment-retention.md

1. Add RED tests for unchanged unrelated entries, owned-target replacement,
   failed managed validation, unsafe/duplicate retained entries and Broker rotation.
2. Add the opt-in CLI/reconcile flag with bounded validation; run GREEN focused
   Windows/Linux tests and full Linux deployment regression.
3. Obtain one independent read-only review, fix important issues with regressions,
   publish/attach a follow-up PR and merge after exact-head CI.
4. Install pinned merged CLI/collector and an operating-only policy using the
   shared current output. Configure real user/group/paths and scope preservation.
   Apply once, validate current readiness, enable timer, verify deduplicated receipt
   over repeated ticks and managed failure preservation in a separate test output.
   Keep Backend consumer disabled/unconnected and create no preparation/workload.
