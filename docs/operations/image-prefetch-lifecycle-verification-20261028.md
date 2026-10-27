# Image-agent lifecycle follow-up verification

The opt-in follow-up adds approved Broker-state inventory resolution, immutable
registration-generation receipts and a read-only preparation evidence collector.
Existing installation defaults are unchanged.

## Verification

- Focused Windows deployment suites: 64 tests, OK, 10 platform skips.
- Full Linux deployment regression: 169 tests, OK, 7 conditional integration skips,
  using a freshly compiled Linux Runtime registry validator (Go 1.26.5).
- Linux validator built with `-buildvcs=false` because local Windows linked-worktree
  VCS stamping was unavailable. CI performs the normal clean-checkout build.
- Full Windows regression has existing Linux-only failures: six errors and one
  failure involving fcntl, geteuid, symlinks and executable permission bits. The
  identical named failures reproduce on unchanged base commit `7ce9100`. They are
  not counted as passing. Production deployment checks run on Linux.
- Independent whole-branch review found two API-contract issues: partial advisory
  readiness and `NO_ELIGIBLE_NODES` operation results. Both were reproduced with
  failing tests, fixed and included in the green full suite. Initial outbox parent
  directory durability was also fixed and covered by a failing-then-passing test.
- Enrollment-only dry-run against the already approved operating target passed at
  `2026-10-27T17:30:09.810578Z`. Active policy, registry and registration file hashes
  remained unchanged. No apply, event, preparation job, pull, workload change or
  timer activation occurred. Infrastructure identity details remain in private
  operational evidence.

## Activation and integration boundaries

1. Review/install the CLI and matching enrollment module, publish a dedicated
   approved operating policy, and dry-run with the actual protected Broker state.
2. Review the optional systemd drop-in against the existing service user, group,
   registry, agent output and Broker state paths. Activate in the normal rollout;
   source changes alone do not install files or enable a timer.
3. Implement Backend receipt consumption through an approved local/secure transport:
   deduplicate `event_id`, select currently approved releases/targets and issue a
   new preparation request for a changed UID/boot generation. No transport or
   consumer is enabled by this Runtime change.
4. VM creation, provider admission and initial agent installation still belong to
   their existing trusted provisioning owner. The hook verifies the installed
   agent; it does not create infrastructure or approve an arbitrary replacement.
5. Obtain the existing pilot's Backend-originated request/operation IDs and collect
   its operation plus current readiness. Keep reader credential delivery on its
   approved secure recipient route. This PR does not claim either is complete.
6. Keep actual pull events/time as a separate telemetry requirement. The collector
   deliberately reports unknown pull telemetry and never infers a cold pull from
   snapshots or local inspection duration.

The current API exposes frozen node results, not the original complete request
target list. Reports explicitly disclose `original_request_target_scope` as
`UNAVAILABLE_IN_API`; compare Backend's original request separately. Live deployment,
provider admission, Backend consumption, timer activation and pull performance
remain outside this development verification. No minor review findings are deferred.
