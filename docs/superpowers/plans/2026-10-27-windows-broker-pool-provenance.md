# Windows broker pool provenance implementation

## Approach

Remove mandatory image/driver digest pins only for `broker_pool`. Broker can
alternatively provide per-VM evidence later; making up static values is not a
valid test setup. The fixed-VM contract stays strict.

## Task 1: Runtime request and RESULT

Files: `internal/windowsruntime/checker.go`,
`internal/windowsruntime/checker_events.go`, `internal/httpapi/windows_checker.go`,
related Go tests.

1. Add tests: broker-pool submission with omitted digests succeeds; supplied
   digest fields are rejected; fixed-VM submission without digests fails;
   broker-pool RESULT omits digest keys while fixed-VM RESULT keeps them;
   HTTP decoding rejects digest keys even when their values are empty or null.
2. Run the focused Go tests and observe contract failures.
3. Allow an all-empty digest pair in checker config; branch request validation
   by selection mode; conditionally include digest keys in RESULT.
4. Run focused and package Go tests.

## Task 2: Backend request and event validation

Files: `apps/challenge/checker_auth.py`, `checker_events.py`, corresponding
Django tests and operations docs.

1. Add tests: direct Runtime checker config omits digest pins; direct request
   omits digest keys; broker-pool RESULT without digests is accepted and stored
   with null columns; broker-pool event with digests is rejected; fixed-VM
   config and event still require digests.
2. Run focused Django tests and observe the expected failures.
3. Change checker config and event validation for broker-pool only, preserving
   existing fixed-VM behavior.
4. Run focused Django tests and system checks.

## Task 3: Cross-component verification

1. Compare the two JSON contracts and config examples.
2. Run Go tests and Django tests relevant to checker submissions.
3. Inspect diffs to ensure no Broker files or unrelated paths changed.
