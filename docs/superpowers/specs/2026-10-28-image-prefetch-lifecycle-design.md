# Approved image-agent lifecycle and evidence collection

The preparation API and agents already exist. The operating Broker target was enrolled once by hand because Runtime's admitted Broker targets live in protected state, while the enrollment CLI only reads the static registry file. Repeating a manual credential materialization after every change is fragile. The current Backend-led Daily Point test and its existing settings must continue unchanged.

The user asked to prepare follow-up automation now and previously chose autonomous execution. This design records implementation decisions for that authorized work; no additional confirmation loop is needed.

## Goals and boundaries

- Reuse the Python enrollment CLI and its protected policy, path ownership checks, frozen static credentials and shared output lock.
- Resolve only explicitly approved Broker resource IDs from Runtime's already-admitted state. Pin Node name, machine, provider, architecture and agent image as before. Do not discover arbitrary resources or approve replacement machines.
- Default to the configured canonical target ID. Allow canonical ID rotation only through an explicit operator policy flag, the same approved resource/machine/provider, and an already-admitted Runtime state entry.
- Emit a durable, deduplicated metadata receipt for a successfully published node generation, including boot identity. The receipt does not authorize images, create a preparation job or activate a release.
- Supply a timer configuration and provisioning hook example for this path. New VM creation, initial agent installation and external provider/Backend wiring remain explicit integrations; the tool verifies an installed agent rather than granting itself a new installation scope.
- Collect operation/readiness and optional before/after node-cache evidence without creating/retrying jobs, pulling images, deleting caches or creating workloads. Legacy agents without pull telemetry must not be described as proven cold pulls or zero-pull runs.
- Keep credentials, full environment files and challenge secrets out of events, reports, logs and source control.

## Approaches

Extending the existing host-side CLI keeps the current trust and deployment model and has a small blast radius. Adding a new in-process Go controller would require a new lifecycle and root/CRI boundary inside the API server. A separate service with new HTTP callbacks would add authentication and ownership contracts before the first Backend test is complete. The implementation uses the existing CLI, local metadata outbox and a separate read-only evidence collector.

## Enrollment inputs

`reconcile` and `accept-provisioned` retain their existing behavior when new flags are absent. Optional `--broker-state` reads the protected `targets.json` produced by Runtime. A policy entry may add `broker_resource_target_id` and `allow_target_rotation` (default false). Exactly one admitted entry must match the approved resource. Its config/credential canonical IDs, resource ID, enabled state, architecture and HTTPS server must agree. Static-registry collisions must not silently override another resource or policy.

Materialize selected embedded credentials only in a private temporary directory; existing KubernetesClient validation rejects plugins, file references, proxy/insecure TLS and other executable inputs before network calls. The actual Node UID must equal the admitted canonical ID. Machine/provider/name pins still come from the operator policy. Temporary credentials are removed on all paths, and upstream error text is never emitted.

All approved slots are validated before publication. Unreachable or mismatched slots preserve the previous complete agent output. This intentionally retains the existing all-or-nothing semantics; operators should use a dedicated operating policy rather than mix disposable QA slots into it.

## Registration receipts and recovery

Optional `--events-dir` publishes one immutable JSON receipt per identity generation after successful `--apply`. The event ID hashes canonical identity and agent binding, excluding observation time, so duplicate ticks produce one event while a reboot or approved identity change produces a new event. Include schema version, event ID, timestamp, target/resource ID, Node UID/name, machine/boot identity, architecture and pinned agent binding. No credential data or image approval is included.

Use the same output lock as enrollment/policy publication. Validate the policy revision before emitting. Atomically link a complete private temporary file into its immutable name; reject conflicting or unsafe existing files. On a crash after nodes publication but before the event, the next reconciliation backfills the same event even if nodes.json is unchanged. Dry runs emit nothing. Bound event size/count and fail visibly rather than deleting unacknowledged events.

Backend consumption is a follow-up contract: deduplicate event ID, select currently approved releases and allowed targets, and issue a new request ID for the new generation. No consumer or job is enabled by this change. Rotated provider/resource IDs or replacement machines still require trusted provisioning approval and normal Runtime target/client admission.

## Read-only evidence collector

Provide a Python CLI for a cache snapshot and for collecting one already-accepted operation. Explicit expected release, request (optional), architecture, image set and target scope prevent mixing ordinary creation operations, an old trial or a different release. Use verified HTTPS, no redirects, bounded JSON, a protected manager token file and sanitized failures.

Reports distinguish operation history from current readiness and retain observed_at/valid_until unchanged. Node cache inspection uses the same approved inventory/agent binding, fixed CRI commands and `pull:false`. Preserve repository/index digest, resolved manifest digest and CRI config image ID as distinct values. Before-cached content is not a cold pull; missing telemetry remains unknown. Record local observation/poll duration separately from actual pull duration.

## Rollout and completion

Ship tested code, examples, contract and a PR first. Validate the new enrollment path in dry-run against the approved operating node if its current protected inputs remain valid. Do not switch the live test registration path, enable a new timer, change consumer secrets or create a preparation operation during this development task. Provide concrete activation steps after review. Completion requires meaningful red/green tests, the existing enrollment regression suite, deployment Python checks, a fresh independent review and exact-head CI.
