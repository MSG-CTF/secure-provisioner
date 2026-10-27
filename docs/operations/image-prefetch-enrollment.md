# Trusted image-agent enrollment

`deploy/image_prefetch_enroll.py` is a host-side CLI and timer job. It GETs only
explicitly approved Node names through each target's existing Runtime kubeconfig,
then lists image-agent Pods in the dedicated namespace. It publishes the complete
trusted agent configuration with `fsync` and an atomic rename. It does not modify
Kubernetes, start workloads, pull images, or remove cached images. Failure leaves
the previous complete output intact; an unreachable approved node is never dropped.
Generated entries pin both the current Node UID and approved machine ID. Runtime
therefore refuses a changed machine even if a copied cluster state reuses its UID.
Older manually maintained entries may omit `machine_id` for compatibility; run
the reconciler to gain the additional pin.

The Runtime file runner validates the file at startup and rereads a bounded,
validated snapshot before every agent operation. Missing, oversized, or invalid
updates return `AGENT_UNAVAILABLE`; there is no fallback to a stale trust snapshot.
On Linux, Runtime opens every path component without following symlinks and
validates the actual descriptor before and after reading. Configuration must be a
regular file owned by root or Runtime's effective service UID, with no group/other
write bits. Ancestor directories must have the same trusted ownership and no
group/other write bits; root-owned sticky directories such as `/tmp` are allowed.
An unrelated operator UID is not implicitly trusted: install its reviewed file as
root or the Runtime service account. Non-Linux development builds rely on OS ACLs
and reject final symlinks/nonregular files; production ownership enforcement is
Linux-specific.
An already running agent invocation completes against the snapshot it started
with. New Node UIDs therefore take effect without a Runtime restart, while an old
frozen operation still needs a new preparation request after node replacement.
This reload changes only agent registration. Runtime's cluster registry and
Kubernetes clients still load at startup. A replacement that changes the cluster
API endpoint, CA, or credentials requires the existing trusted Runtime registry
rollout/API handoff; replacing the kubeconfig file alone does not reload that
client. The enrollment hook assumes the already registered client remains usable.

## Installation and existing-node registration

Review and install the dedicated DaemonSet as described in
`image-preparation.md`. Pin its image by digest and restrict its Node GET RBAC to
approved names. Then install the enrollment CLI root-owned at
`/usr/local/libexec/image_prefetch_enroll.py`. Python 3.10+ and the existing
`/usr/local/bin/kubectl` are required; no third-party Python packages are needed.

Create `/var/lib/secure-provisioner/image-prefetch` root-owned with the existing
Runtime service group and mode `0750`. Copy
`deploy/image-prefetch-enrollment.example.json` to a separate root-owned
`enrollment.candidate.json`, replace every placeholder, and set ownership
`root:<runtime group>` with mode `0640`.
The example intentionally fails validation until the actual digest is supplied.
Use the exact approved target ID, Node name, machine ID, and provider ID from
trusted provisioning evidence. An empty `provider_id` is valid only when the Node
has none; a nonempty pinned machine ID is always required. Node names alone never
authorize enrollment. `allow_replacement` defaults to false.

Publish the reviewed candidate using the supported policy writer, including for
the initial pilot setup:

```sh
/usr/bin/python3 /usr/local/libexec/image_prefetch_enroll.py publish-policy \
  --policy /var/lib/secure-provisioner/image-prefetch/enrollment.json \
  --output /var/lib/secure-provisioner/image-prefetch/nodes.json \
  --candidate /var/lib/secure-provisioner/image-prefetch/enrollment.candidate.json \
  --apply
```

All supported policy writers MUST use this command, the provisioning hook, or the
same `nodes.json.lock` protocol. Do not edit/replace the live policy independently
while jobs may run. Operator updates (including revocation and replacement
opt-in) are made in a separate reviewed candidate and published with this command.
`ENROLLMENT_BUSY` means another transaction holds the lock; retry publication
after it finishes. The command validates and publishes policy without contacting
Kubernetes or modifying the current agent output. Direct external writers that
ignore this shared lock are unsupported.

Point `--registry` at the same file as `PROVISIONER_CLUSTER_REGISTRY`. The target
must already exist there, be enabled, and have the approved architecture. The
CLI obtains its absolute kubeconfig path from that registry; policy and receipt
cannot supply commands, kubeconfig paths, or credentials. The existing kubeconfig
needs Node GET and Pod LIST in the dedicated namespace. TLS verification is
explicitly enabled. Existing Runtime Pod EXEC permission is used later by Runtime,
not by this registration job.

Before each GET, the helper reads that source through protected no-follow path
descriptors with the configured Runtime owner binding. It passes the frozen bytes
to the fixed local `kubectl --kubeconfig /dev/stdin config view --raw -o json`
conversion command, without `--flatten`. This command parses the source without
executing credential plugins or loading referenced credential files. The helper
then accepts only HTTPS servers with embedded CA data, embedded client
certificate/key data or a static token, and explicit cluster/user/context names.
It rejects exec and auth-provider plugins, tokenFile and certificate/key/CA file
references, proxies, insecure TLS, impersonation, basic auth, extensions, and
other unsupported fields before issuing a GET.

The selected static configuration is written into a private temporary directory
as a job-owned `0600` JSON snapshot. GET reads only that snapshot, never the mutable
source path. The snapshot is removed after success or failure. A source edit
after conversion cannot add a root-executed plugin or redirect GET to another
credential file. Source and normalized credential data are never printed;
conversion stderr is discarded and output remains bounded. The conversion path
is supported on the Linux production host; Windows checks cover the portable
validation and file-lock behavior.

Run a validation dry run before publication (it creates only the local lock file):

```sh
/usr/bin/python3 /usr/local/libexec/image_prefetch_enroll.py reconcile \
  --policy /var/lib/secure-provisioner/image-prefetch/enrollment.json \
  --registry /etc/secure-provisioner/clusters.json \
  --output /var/lib/secure-provisioner/image-prefetch/nodes.json
```

The job requires a Ready, schedulable Linux K3s/containerd node with the reviewed
architecture, current UID and boot ID, matching machine/provider identity, and
`msgctf.io/image-preparation-agent=true`. It requires exactly one Ready agent Pod
with the pinned image, expected service account, and expected DaemonSet owner.
It preserves container defaults and the manifest's mounts/resources. It does not
execute the agent or claim that cached challenge content is ready.

Add `--apply` to publish. Existing output mode/owner/group are preserved; new
output is `0640` and inherits the job's group. Set
`PROVISIONER_IMAGE_PREFETCH_NODES=/var/lib/secure-provisioner/image-prefetch/nodes.json`.
The first Runtime upgrade/start is required to introduce the file runner; later
enrollments do not restart it. Install the reviewed `.service` and `.timer`, using
the existing Runtime group and registry path, as root-owned mode `0644`, then
enable the timer. The CLI and fixed provisioning hook use root-owned mode `0755`.
The service can write only its dedicated state directory. Its capability bound
contains only `CAP_DAC_READ_SEARCH`: existing Runtime kubeconfigs can be owned by
the Runtime user with mode `0600`, so a root job without this capability cannot
read them. It receives no `CAP_DAC_OVERRIDE` or write bypass. Keep the fixed CLI,
policy, registry, and their parent directories protected; they determine every
credential path the job reads. Set `Group` to the existing Runtime group so newly
created output is readable by Runtime; atomic replacement preserves existing
owner/group and mode, including a root-owned group-readable `0440` nodes file.
Set `--runtime-user` to the existing Runtime service principal (for example
`provisioner`). Only registry-selected kubeconfigs and their protected ancestors may
additionally be owned by that explicitly named UID. Policy, registry, output,
receipt and lock ownership checks remain restricted to root/the job UID. This
owner binding does not change permissions or grant another user credential access.
Its existing kubeconfig grants determine its remote read access. Output includes
only fixed status/error codes, counts, and changed/replacement booleans; upstream
stderr and credentials are discarded.

## Trusted VM replacement hook

## Optional admitted Broker inventory and registration outbox

For a target admitted dynamically by Runtime, keep `--registry` pointing to the
normal static registry and add `--broker-state <PROVISIONER_BROKER_STATE_DIRECTORY>/targets.json`.
The protected state is bounded to 1 MiB by this helper; oversized inventories fail
visibly. The registry still owns static policy. A canonical ID present in both
sources is rejected rather than shadowed.

Add `broker_resource_target_id` to the approved policy slot, alongside the
canonical Runtime `target_id`. The former identifies the provider/Broker resource;
the latter is the Node UID used by Backend and readiness. They need not be equal.
Exactly one enabled admitted entry must match. The helper checks config,
credential and actual Node UID agreement, architecture, embedded static credentials,
and server agreement before publication. `--runtime-user` may own this state and
credentials, but cannot own the operator policy. Temporary credentials are removed
on success and failure. A state edit during validation aborts publication.

`allow_target_rotation` defaults to false. Explicitly enabling it permits a new
already-admitted canonical ID only for the same approved resource, node name,
machine and provider. It cannot approve a replacement VM or resource. Use the
trusted provisioning receipt for approved machine replacement; changing endpoint,
CA or credentials still requires normal Runtime client admission/rollout.

Optional `--events-dir` emits immutable version1 `agent.registration` receipts
after successful `--apply`. `event_id` hashes the version, type and `generation`
using the helper's sorted, indented JSON plus final newline. Generation contains
canonical target/resource IDs, node name/UID, machine/provider/boot IDs,
architecture, namespace and agent digest. `observed_at` is the enrollment check
time, not cache readiness. Receipts contain no token, kubeconfig or approved image
list. Duplicate ticks preserve the first receipt; a reboot emits a new generation
even if nodes.json is unchanged. Output publication and event publication are not
one filesystem transaction: an event failure returns failure and the next tick
backfills the missing event without rolling back the valid nodes file. A conflict
fails visibly. The outbox is bounded to 4096 entries and never deletes pending
receipts; the consumer/operator must archive acknowledged receipts elsewhere.

Backend integration must deduplicate `event_id`, choose currently authorized
releases and targets, and submit a **new request_id** for a changed generation.
An old operation/retry retains its old boot/UID binding. This PR supplies receipts,
not a Backend consumer, callback, automatic pull, provisioning system or agent
installer. There is no new HTTP or authentication contract.

Review `deploy/image-prefetch-enroll-broker.conf.example` as an optional systemd
drop-in and use a dedicated operating policy. Validate without `--apply`, confirm
the output path agrees with Runtime's existing agent file, then schedule activation
through the normal rollout. No timer is enabled by installing these examples.
All approved nodes must pass; do not mix disposable QA nodes into operating policy
or omit an unhealthy operating node to manufacture successful enrollment.

## Trusted VM replacement hook (continued)

For automatic same-target VM replacement, set `allow_replacement:true` on that
approved slot in a reviewed candidate and use `publish-policy`. The trusted
provisioning completion job must produce
`provisioned.json` using `deploy/image-prefetch-provisioned.example.json`. Populate
the new machine/provider identities from the provider API and the authenticated
bootstrap channel for that VM, together with the previous approved identities.
Do not source this receipt from a Backend HTTP field, a Pod label, a public node
name, a copied golden-image machine ID, or unauthenticated guest output. The image
builder must reset machine identity so every VM has its own identity.

Write the receipt root-owned, mode `0600`, by atomic rename in the protected state
directory. Invoke the installed `image-prefetch-provisioned-hook.example.sh` from
the provisioning job after the same target is registered, its kubeconfig is ready,
and its reviewed DaemonSet is Ready. The hook has a fixed CLI/path/argument list.
The CLI is also directly invocable as follows; omit `--apply` for a dry run:

```sh
/usr/bin/python3 /usr/local/libexec/image_prefetch_enroll.py accept-provisioned \
  --policy /var/lib/secure-provisioner/image-prefetch/enrollment.json \
  --registry /etc/secure-provisioner/clusters.json \
  --output /var/lib/secure-provisioner/image-prefetch/nodes.json \
  --receipt /var/lib/secure-provisioner/image-prefetch/provisioned.json --apply
```

The receipt cannot change the allowlisted target ID or Node name. Previous
machine/provider identities must match the policy, and the replacement machine
ID must differ. These comparisons prevent a stale receipt from overwriting a
later replacement. The new Kubernetes identity and agent are verified before
either file is changed. The policy is published before the agent output; if the
second write fails or the process exits between writes, run ordinary `reconcile`
again to finish from the updated trusted policy. No unverified output is
published. An advisory lock serializes timer and provisioning invocations;
`ENROLLMENT_BUSY` can be retried by the trusted job.
The CLI also records the original policy content hash and inode/ownership/
timestamp metadata. Its final revision check detects external replacements
during validation and returns `POLICY_CHANGED`. This check is defense in depth;
it is not an atomic compare-and-swap. The supported `publish-policy` entrypoint
shares the output `.lock`, providing full mutual exclusion with enrollment and
provisioning transactions. If an operator publication encounters an in-flight
hook it retries after `ENROLLMENT_BUSY`; its subsequent revocation stays in force
for every later hook. No later transaction can overwrite that revocation from an
older snapshot while using this supported writer protocol.

This provides the tested local completion hook; it does not create a VM or wire
itself into an external Broker. Node UID recreation on the same approved machine
is handled by the timer without a receipt. A replacement with a rotated Broker
target UUID remains deliberately unsupported: trusted provisioning must first
register and explicitly approve the new target/slot. Automatic target rotation
needs a separate approved slot mapping and provider project/zone/resource scope;
this tool never discovers or enrolls arbitrary new targets.

## Verification

```sh
python -m unittest discover -s deploy -p 'test_image_prefetch_enroll.py' -v
go test ./internal/imageprep ./cmd/provisioner
```

Tests cover trusted UID reload, invalid reload refusal, same-target provisioning
hook invocation, stale/unknown receipt refusal, registry and platform/identity
checks, agent selection, dry runs, failure preservation, bounded read-only kubectl
arguments, static credential whitelisting, frozen snapshot races/cleanup, a real
local kubectl plugin-refusal probe, and safe error output. Linux ownership/mode checks are exercised on
POSIX and skipped on Windows. No live DaemonSet, VM creation, or production
registration is implied by these tests.
