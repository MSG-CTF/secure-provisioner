# Preserve unrelated registrations during scoped enrollment

The operating target passes live verification; an unrelated existing QA target
times out. The shared agent file contains both. Keeping the QA trust entry intact
must not require claiming that its old identity was freshly verified.

Add opt-in `--preserve-other-targets` to the trusted enrollment CLI. A scoped
policy owns every entry of its configured target IDs and resolved canonical IDs.
Validate every managed slot normally, then atomically publish those entries plus
unchanged existing Kubernetes entries belonging to other targets. Never fall back
to a previous entry for a failed managed target. Never emit receipts or readiness
claims for retained targets. Default whole-file replacement remains unchanged.

Require a bounded, protected, structurally valid Kubernetes-only previous file;
reject duplicate target/name keys, unsupported fields/modes and malformed bindings.
Use the existing shared output lock and policy revision checks. Rotation removes
both previous approved and resolved target IDs from the retained set. Explicit
revocation of a retained target requires its owning policy/operator, not this flag.

The user authorized merging and operational tests through the Backend integration
boundary. This small compatibility follow-up is needed to retain the existing QA
entry while activating the already approved operating target. Backend consumption,
new pulls, VM replacement and active changes remain outside this execution.
