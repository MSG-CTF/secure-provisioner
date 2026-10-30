# 150 concurrent requests worker capacity experiment

Goal: measure HTTP admission, durable leased-worker queueing, completion, and failure rates for a 150-request burst at 10/20/30/50 workers; do not alter a live service.

Scope: real HTTP handler/service, PostgreSQL 16, production lease/checkpoint/binding path. The workload adapter has explicitly controlled latency, so these are worker/queue results, not a claim that 150 actual challenge containers fit or start in that time. Audit actual Kubernetes rate limits separately.

- [x] Audit active configuration, slot occupancy, DB pool, leases, admission, Kubernetes client throttling, and existing load test gaps.
- [x] Create isolated test branch/worktree from dev a4c1f47; preserve B contract PR.
- [x] Start disposable loopback-only PostgreSQL with a dedicated database; never run the truncating load tests against an operational DB.
- [x] Add an opt-in 150-client barrier test using the real HTTP service and leased worker; capture acceptance, queue wait, terminal completion, active peak, failure/attempt counts, raw per-request samples.
- [x] Test short and longer controlled execution profiles across worker counts; add a controlled retry case. Repeat useful cases and record host/runtime/database versions.
- [x] Independently validate harness accounting and safety guards, then run opt-in integration and baseline tests in Linux to avoid the observed Windows test-executable issue.
- [x] Report measured results separately from actual K3s/registry/node capacity and downstream API rate-budget inference. Recommend a candidate conditional on observed execution/SLO, without asserting an unmeasured production optimum.

Rulings: use 150 unique user/team/instance IDs rather than 150 HTTP requests collapsed by idempotency or team policy. Start workers before the barrier burst. Simulated adapter is deliberate and must appear in every result. Completion is terminal store persistence, not HTTP 202 or adapter return. Probe polling must not dominate database load. Use production WorkerID/lease defaults and actual PostgreSQL pool settings.
