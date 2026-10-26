# Automatic Broker K3s target registration

The requested behavior is to register all VMs returned by Broker's K3s
credential API, without editing a target ID, IP address or credential path
for each VM. Runtime will own discovery and refresh while it is running.

## Approach

A batch extension to the deployment importer would still need registry
activation and a service restart. Runtime-native discovery instead updates
the registry used by create/status/delete and Gateway routing in place.
Use that approach, retaining the existing file registry for local/manual
targets and backwards-compatible startup when discovery is unconfigured.

## Behavior

- Fetch every page of `/v1/runtime/k3s-credentials` over authenticated HTTPS.
- Verify inline credentials, certificate fingerprint/expiry and exactly one
  Ready Kubernetes node. Use the actual Node UID as lifecycle `target_id`;
  check Broker's `target_id` when present. Never use `resource_target_id`
  as a substitute. Keep the Broker resource ID separately.
- Obtain architecture, cloud provider and region from node observations,
  with fleet policy defaults for provider/region. Derive NodePort public
  gateway and optional Gateway upstream from the credential server host.
- A single operator-approved fleet policy supplies enabled/isolation
  capability settings. Credential possession does not attest isolation.
  Existing target policy and explicit operator disablement are preserved.
- Sync once before serving and periodically thereafter, without restarting
  workers. Publish complete snapshots with concurrent-reader protection.
- Failed/incomplete listing preserves the last complete snapshot. An
  invalid/unreachable individual VM cannot prevent healthy VMs enrolling;
  its old registration is retained for maintenance but disabled for create.
- Missing or replaced nodes are retained with create disabled, so operations
  and bindings can still use their original cleanup identity.
- Save verified credentials and policy in a dedicated private, atomic state
  file for recovery after restart. Restore cached targets for maintenance
  only until Broker and live node checks succeed again. Never print tokens,
  kubeconfigs, private keys or external response bodies.
- Refuse conflicting legacy resource-ID registrations instead of creating
  two active routes to the same node.

## Configuration and scope

Discovery is opt-in with Broker base URL, Runtime token file, fleet policy
file and private state directory. Sync interval defaults to 1 minute;
request timeout to 10 seconds. No per-VM mapping is configured. This change
does not bootstrap node isolation, mutate Scheduler reservations, or repair
existing CLEANUP_PENDING records. Production activation follows release
handoff; local implementation does not restart the current service.

## Verification

Exercise pagination, actual target identity, address derivation, credential
rotation, partial failures, disappearance/reappearance, node replacement,
cache recovery, policy preservation, malformed credentials and concurrent
registry reads. Run the Go suite and relevant race tests on Linux, plus
the existing deployment importer suite against the new binary.
