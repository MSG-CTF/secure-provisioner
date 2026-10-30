# Windows broker pool provenance

The first Backend → Runtime → VM → RESULT canary needs to run without claiming
that a dynamically selected VM has image or driver digests the Broker has not
reported. The current static pin comparison does not measure the chosen VM.

For `selection_mode=broker_pool`, omit `vm_template_sha256` and `driver_sha256`
from checker requests and RESULT events. Keep `checker_commit_sha`,
`config_version`, the payload digest, assignment ID and Broker execution
events. Reject a broker-pool request or event that includes the omitted digest
fields. Fixed-VM submissions retain their existing required digest contract.

Backend stores the broker-pool provenance snapshot without the two digests;
nullable database digest columns remain null. Existing fixed-VM submissions
and already recorded events keep their prior schema. No Broker API change is
needed for this canary. Future per-VM image evidence should come from Broker
or guest attestation and be recorded as measured data, not static config.

Callback authentication, token delivery, and cleanup signalling are separate
integration tasks and are not changed here.
