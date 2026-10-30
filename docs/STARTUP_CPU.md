# Startup CPU

Only the three reviewed image digests in the image policy catalog opt in to
startup CPU. Grade Tampering uses 300m/1000m, Open House 500m/2000m and Cashout
250m/1000m (steady/peak). Author images, commands, environment, secrets, memory
and storage remain unchanged.

Scheduler reserves peak CPU and sends peak in `workload.resource_limits` plus
the optional positive `workload.steady_cpu_millicores`. Runtime independently
checks the exact image and CPU pair, including durable-command replay.
This implementation supports one WEB Kubernetes container and NodePort
exposure only. Normal requests omit the new field and preserve their durable
fingerprint. A new image digest requires a new operator review.

The Deployment template always uses steady CPU. During CREATE only, Runtime
resizes the owned live Pod to peak via `pods/resize`, retaining UID and resource
version fencing. Requests and limits change together, with no memory change or
container restart. It verifies the ReplicaSet/Deployment owner chain and all
container settings outside the approved CPU override.

After readiness, Runtime resizes the Pod back to steady CPU and waits for the
kubelet's observed generation, applied container requests/limits and absence
of pending resize conditions. Only then may CREATE succeed and publish the
Gateway route. Both synchronous and async CREATE results return
`steady_cpu_millicores`; Scheduler requires that acknowledgment before committing
the smaller reservation. A replacement Pod inherits steady CPU.

Use Linux Kubernetes nodes with in-place CPU resize enabled and a compatible
CPU manager (the verified nodes use policy `none`). The Runtime credential
needs update permission on `pods/resize` and read permission on ReplicaSets.
An unsupported resize or deadline uses the existing namespace rollback and
failed-CREATE cleanup path. Interrupted CREATE operations also retain the
existing rollback behavior. Do not lower or release a reservation on a timeout
without the normal Runtime cleanup proof.

If startup rollback exhausts its retry budget before a ready binding exists,
status lookup exposes only the recorded cleanup identity as TERMINATING.
It does not expose access or claim deletion. Explicit DELETE validates team,
target, workload ID and original namespace UID, then uses the normal cleanup
worker. Unknown namespace identity, an active create, a checkpoint or multiple
create generations cannot enter this recovery path. Lookup uses an indexed
instance identity, and repeated DELETE retains its operation ID.

Roll out Broker support first, then Runtime binary and reviewed image catalog,
then Scheduler migration and binary. Enable Scheduler's startup CPU switch
only after all three support the contract. Leave it off to retain normal CPU.
Drain opted-in work before rolling back Runtime or Scheduler. Broker retains
original held CPU for create idempotency and records steady CPU separately.
