# Automatic image preparation

The implementation is disabled by default. Preparation changes only the actual
node's K3s image cache. It does not approve digests, start challenge containers,
reserve capacity, or make readiness a prerequisite for ordinary instance creation.
Backend may separately choose staged release activation policy.

## Runtime installation

1. Build `go build -trimpath -o provisioner ./cmd/provisioner` and
   `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o image-agent ./cmd/image-agent`.
   Use `arm64` for ARM64 nodes. Run `go test -p 1 ./...` against a disposable
   PostgreSQL database through `PROVISIONER_TEST_DATABASE_URL`; several existing
   integration packages truncate shared tables and must not run concurrently.
2. Deploy Runtime first with preparation disabled. Startup applies migration 006
   to its existing PostgreSQL database. API bridge mode does not migrate or run
   preparation workers. Existing service/CI credentials gain no preparation access.
3. Install trusted agents using one of the routes below. Every eligible node in a
   target needs an entry in `PROVISIONER_IMAGE_PREFETCH_NODES`, pinned to its current
   Kubernetes UID. Unconfigured nodes remain eligible but unready. Never omit a
   failed/unreachable node from deployment inventory to manufacture all-ready status.
4. Set the following on Runtime, using root/operator-owned files readable by its
   service account. Token files use the existing 43–128 character Base64URL format.

```dotenv
PROVISIONER_IMAGE_PREFETCH_ENABLED=false
PROVISIONER_IMAGE_PREFETCH_NODES=/etc/secure-provisioner/image-prefetch-nodes.json
PROVISIONER_IMAGE_PREPARATION_TOKEN_FILE=/etc/secure-provisioner/preparation.token
PROVISIONER_IMAGE_READINESS_TOKEN_FILE=/etc/secure-provisioner/readiness.token
PROVISIONER_IMAGE_PREFETCH_OBSERVE_INTERVAL=30s
PROVISIONER_IMAGE_PREFETCH_READINESS_TTL=60s
PROVISIONER_IMAGE_PREFETCH_MAX_ATTEMPTS=3
PROVISIONER_IMAGE_PREFETCH_WORKERS=2
```

The manager token permits create, status, child retry, and readiness query. The
readiness token permits only query. Both must differ from each other and from all
current/previous full and CI tokens. The service requires PostgreSQL and the
existing reviewed policy catalog when enabled. It rejects every container absent
from that catalog and reuses the catalog's complete graph/name/ports/profile checks.
New policy files require a Runtime restart, matching the existing immutable catalog.
Persisted observations carry the loaded file's hash and cannot survive a change.

## Preferred route: dedicated Kubernetes agent

Build the image with `deploy/image-agent.Dockerfile`, publish it to an operator-owned
registry, and record its immutable image digest. This publication is an operator
step, not something Runtime does. Replace the image placeholder and Node names in
`deploy/image-agent.example.yaml`; set `resourceNames` to only enrolled node names.
The agent service account has only Node GET permission, no Secret access, pod exec,
or workload mutation. Runtime's existing kubeconfig needs Node GET/LIST and Pod
GET/LIST/EXEC in the dedicated namespace. Keep those permissions out of Backend,
Scheduler, CI, and the existing Broker agent.

Review the dedicated namespace and hostPath mounts before applying the manifest.
Socket access is privileged host infrastructure access even though the container
does not request `privileged: true`, host PID, or host networking. Only the agent
gets the K3s socket and binary. It needs the installed K3s data directory for that
version's applets, plus read-only machine ID and boot ID. It receives no registry
passwords; CRI pulls use the node daemon's existing registry configuration.

After operator approval, label only enrolled nodes
`msgctf.io/image-preparation-agent=true`, apply the reviewed manifest, and wait for
the DaemonSet to be ready. Set each node's trusted entry to `mode: kubernetes`, the
dedicated namespace, and exactly the same pinned agent image. Runtime selects a
single Ready agent Pod on the expected current Node, verifies its image, and execs
only `/usr/local/bin/image-agent --kubernetes` with bounded JSON on stdin. The
agent independently fetches its current Node and checks actual mounted machine ID,
boot ID, OS, and architecture. Runtime compares the response with its own inventory
and configured expected Node UID. No request controls a command, namespace, image,
kubeconfig, or pod destination.

This manifest has been locally parsed and the selection/identity protocol tested;
it has not been installed or exercised in a real DaemonSet. Validate the installed
K3s binary/data mount combination on the pilot before enabling automation.

## Alternative local or SSH route

Install the binary root-owned at `/usr/local/libexec/runtime-image-agent`. Create
root-owned `/etc/secure-provisioner/image-agent.json` with the real node UID and
absolute K3s binary path:

```json
{"node_uid":"CURRENT_KUBERNETES_NODE_UID","k3s_binary":"/usr/local/bin/k3s"}
```

The local trusted node entry uses `mode: local` and an absolute `command` path.
That executable must have legitimate CRI access; a root-owned fixed wrapper may
invoke the exact agent through sudo. Do not grant arbitrary shells or K3s arguments.
An SSH entry uses `mode: ssh`, `ssh_host` (an SSH config alias), and an absolute
`ssh_config`; it cannot set `command`. The operator config specifies HostName,
User, IdentityFile, and a verified UserKnownHostsFile. Runtime uses BatchMode,
StrictHostKeyChecking, no TTY, and the fixed remote command
`sudo -n /usr/local/libexec/runtime-image-agent`. Permit only that exact command in
sudoers. The alias/config are trusted installation inputs, never HTTP fields.

## Pilot and rollout

Enable Runtime, then Backend's preparation worker and Scheduler's advisory query.
Submit the complete approved release containers to `POST /v1/image-preparations`.
Poll Location until terminal; inspect per-node/per-image classified failures.
`SUCCEEDED` is historical. Check `POST /v1/image-readiness/query` for current hints.
Verify cold pull, warm no-pull, auxiliary-image absence, cache deletion, node reboot,
policy block, worker restart, partial failure, and selected child retry before wider
rollout. Record query p95/p99, observation duration, cache IO, and node pull load.
No real node pulls or live deployment were performed. A separate read-only canary
ran the final compiled local agent against an already-cached approved `ghost-file`
image on the actual Runtime K3s node: exact digest, CRI config binding, all content,
and node UID/machine/boot identity passed in 3.425 seconds. It did not pull, restart
a service, or execute a challenge. Temporary probe files were removed. Dedicated
DaemonSet execution, remote SSH, cold pulling, and production-scale latency remain
unverified; one roughly 33 MB cached image is not a throughput guarantee.

Preparation workers have their own concurrency and leased DB queue. A claimed step
has a 150-second total deadline, five-second inventory calls, a two-minute agent
deadline, and a three-minute fenced lease. Attempts are committed before inventory
or agent invocation, so crashes cannot reset the retry budget. Per-node DB leases
serialize pulls and observations across Runtime processes. Child retries preserve
parents and frozen node UIDs. A changed UID needs a new request; an explicit retry
also preserves the frozen boot identity and will fail after reboot, so use a new
request after reboot. Only timeout/network, rate limit, and registry/Kubernetes API 5xx failures
retry automatically, at bounded exponential delays. Registry authentication,
platform, missing manifest, content, node identity, policy, and disk failures stop.

| Error code | Automatic retry |
|---|---|
| NETWORK_TIMEOUT, REGISTRY_UNAVAILABLE, RATE_LIMITED | Yes, maximum configured attempts |
| REGISTRY_UNAUTHORIZED, MANIFEST_NOT_FOUND, PLATFORM_MISMATCH | No |
| RESOURCE_EXHAUSTED, NODE_IDENTITY_MISMATCH, AGENT_UNAVAILABLE | No |
| CONTENT_INCOMPLETE, POLICY_REJECTED, NO_ELIGIBLE_NODES | No |

No upstream stderr, tokens, credentials, environment variables, or arbitrary
request fields enter operation results/logs. The API returns only fixed codes.

## Observation limits and semantics

Every prepared image set continues to be observed in the background. Query reads
PostgreSQL and current policy only; it never fans out to nodes. A complete target
inventory is required, and all images must exist on one node. Unknown targets are
omitted. Never/partially observed targets return zero counts and null times.
Observation starts before inventory collection; its original TTL is never extended
by query/replay. Future timestamps have zero positive clock tolerance. Failed scans
replace previous positives. Policy hashes invalidate persisted hints on restart.

The agent requires the exact requested reference in CRI `repoDigests`, then hashes
the requested manifest/index, selected Linux child, config, and all layer blobs in
`/run/k3s/containerd/containerd.sock`, namespace `k8s.io`. It does not equate CRI's
config image ID with a manifest digest; it binds that ID to the selected manifest's
config digest. It accepts only one matching platform child,
without CPU variants or nested indexes. An inspect-only scan never repulls. A real
cache hit performs full validation and does not call pull.

Full content hashing is intentionally conservative and can be expensive for large
images. A target scan older than TTL produces no positive hint; large sets can remain
unready until observation IO/parallelism is tuned. A node scan is bounded to two
minutes, and reads never turn slow/stale evidence into a success. Do not enable broad
rollout before measuring this cost; a future native containerd collector can use
authoritative content metadata while preserving cache-deletion detection. Historical
operation/watch retention is currently operator-managed; no automatic pruning exists.

Create requests accept optional non-null UUID `release_id` and AMD64/ARM64
`architecture`, preserve them in durable commands/fingerprints, and keep omission
compatible. Every K3s workload requires Linux and the trusted target architecture
through node selectors. K3s performs actual manifest selection at lazy pull; the
preparation agent verifies manifest platform before declaring readiness. Fresh whole
image-set nodes add only preferred node affinity. Hint failures leave lazy pull and
the existing mandatory security checks in place.
