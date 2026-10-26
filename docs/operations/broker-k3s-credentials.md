# Import Broker K3s credentials with the Scheduler target ID

## Automatic registration and refresh

Runtime fetches the authenticated Broker credential list at startup and
**once per hour**, adding only VMs that have not been registered. Existing
targets, certificates, clients, routing and enabled/disabled settings are kept.
Use this mode instead of running the single-VM importer for each new VM.
Configure it once on the Linux Runtime host:

```sh
PROVISIONER_BROKER_BASE_URL=https://broker.mjsec.kr/api
PROVISIONER_BROKER_TOKEN_FILE=/etc/secure-provisioner/secrets/broker-runtime-token
PROVISIONER_BROKER_TARGET_POLICY=/etc/secure-provisioner/broker-target-policy.json
PROVISIONER_BROKER_STATE_DIRECTORY=/var/lib/secure-provisioner/broker
PROVISIONER_BROKER_SYNC_INTERVAL=1h
PROVISIONER_BROKER_REQUEST_TIMEOUT=10s
PROVISIONER_BROKER_SYNC_TIMEOUT=2m
```

The URL defaults to the value shown when the other three paths are supplied;
the interval and timeouts also default to the values shown. With none of the
Broker settings configured, file-registry behavior is unchanged. Incomplete
settings fail startup. Keep the token in its protected file and make the state
directory writable by the Runtime service account with mode **0700**. Runtime
creates a missing state directory with that mode. The state file is **0600**.

Start the fleet policy from
[`deploy/broker-target-policy.example.json`](../../deploy/broker-target-policy.example.json).
It contains no VM IDs, IP addresses, credential paths or per-VM entries.
Provider/region are fallbacks for nodes without cloud metadata; observed node
provider/region take precedence for new registrations. Architecture always
comes from the node. If a mixed fleet lacks cloud metadata, have bootstrap
publish the provider ID and `topology.kubernetes.io/region` label.

The example registers nodes but leaves enforcement declarations false, so
workload creation is refused with `TARGET_CAPABILITY_MISMATCH`. Set these
declarations to the capabilities actually installed and verified by the fleet's
bootstrap. Include `gvisor` in `runtime_classes` for PWN-capable nodes. An
administrator kubeconfig alone does not establish these properties. Use
`enabled: false` to enroll a fleet for maintenance without permitting creates.
Existing target policy and explicit disablement in the file registry take
precedence. Policy changes take effect on restart; existing discovered targets
retain their saved policy until an operator-approved migration.

Runtime checks once during normal startup and then hourly. Each cycle fetches
every page using `next_cursor`/`after`. Known Broker resource IDs and existing
Node UID registrations are skipped; their credentials are not revalidated or
replaced. For new resources, Runtime verifies credentials and queries up to
four nodes concurrently. The returned Node UID becomes
`target_id`; Broker's `resource_target_id` remains the credential identity.
If the API returns `target_id`, Runtime checks it against the actual node. Older
responses without that additive field are supported by observing the node UID
directly. A node must be the sole Ready node in that K3s cluster.

New targets use `NODE_PORT`; their public address comes from `server_url`.
Enable `gateway_enabled` for a fleet served through the existing Gateway.
The upstream public IP is derived per VM, and Runtime still requires its
Gateway token and PostgreSQL journal. Existing Ingress targets retain their
configured ingress and public gateway.

New registrations are published atomically for create/status/delete and Gateway
lookups, without restarting the service. A failed listing page publishes
nothing. A malformed, expired or unreachable new VM is rejected while healthy
new VMs are registered. Disappearance from the API, address changes, credential
rotation or replacement of a known resource do not alter its existing target.
Those changes require an explicit maintenance/migration operation. Discovery
does not remove or disable targets, clear reservations or alter CLEANUP_PENDING
records. When no new VM is added, it does not rewrite the private state file.

Verified credentials and target policy are saved in the private state file
before publication. This file contains private keys: keep it on the Runtime
host and out of source control, artifacts and general backups. Normal restarts
restore cached clients with their saved eligibility; file-registry targets take
precedence. A transient Broker outage preserves existing targets. The temporary
API-only deployment bridge restores that cache but does not poll or enroll
nodes or create/write the state directory, including before first enrollment.
Logs report `added`, `skipped`, `rejected` and sanitized error codes, never
credentials or external error bodies. The API-only bridge restores cached
targets for maintenance only. Existing certificates are deliberately not
renewed by this hourly addition job; use the maintenance importer when needed.

For migration, first upgrade Runtime through the normal release handoff,
then add the fleet settings to its deployment environment and restart once.
Keep the existing file registry for manually managed targets. Correct or
withdraw legacy entries keyed by the Broker resource ID before enabling
discovery: Runtime refuses to enroll the same VM under a second lifecycle ID.
After activation, verify an actual Scheduler-origin create/status/delete.

## Single-VM import and compatibility

Broker's credential list and detail responses expose two different identities:

- `resource_target_id` (also Scheduler's `candidate_id`) selects the credential.
- `target_id` is the currently observed Kubernetes Node UID used by Scheduler
  create/status/delete requests and Runtime's registry lookup.

Use the returned `target_id` as the registry key. The importer verifies it
against the one Ready node reached with that credential, so no per-server
manual ID mapping is needed. A missing/null ID means the Broker has not yet
observed the Kubernetes node, or the Broker API needs the additive identity
update. Retry after that is resolved; never substitute the resource ID.

## Import command

Deploy Runtime code that accepts the optional `broker_resource_target_id`
registry field before using this importer. Deploy the Broker credential API's
additive `target_id` response first. Existing credential path IDs, pagination,
tokens and Scheduler lifecycle request schemas remain unchanged.

On the Runtime host, prepare a cluster template using the existing registry
format. It contains provider, region, architecture, public_gateway,
exposure_mode, enabled and security_capabilities. It must reflect the reviewed
isolation policy; importing an administrator certificate does not approve
isolation capabilities. `target_id`, `broker_resource_target_id` and
`kubeconfig_path` are populated by the importer. Existing entries retain their
current policy when credentials are refreshed.

```sh
sudo python3 deploy/import_broker_k3s_credentials.py \
  --resource-target-id de42849c-e0dc-43d4-8e63-9bb2bd056db4 \
  --token-file /etc/secure-provisioner/secrets/broker-runtime-token \
  --registry /etc/secure-provisioner/registry.json \
  --output-registry /etc/secure-provisioner/registry.candidate.json \
  --runtime-binary /opt/secure-provisioner/secure-provisioner \
  --template /etc/secure-provisioner/approved-cluster-template.json \
  --credential-directory /etc/secure-provisioner/kubeconfigs \
  --k3s
```

`--broker-base-url` defaults to `https://broker.mjsec.kr/api`. The token file
must contain the token authorized for Broker's Runtime credential API, not a
Scheduler or administrator token. `--k3s` selects `k3s kubectl`; otherwise a
`kubectl` executable is required. OpenSSL is also required.

The command validates HTTPS, refuses redirects, requires an inline CA and
client certificate/key without exec authentication or disabled TLS checks,
checks certificate fingerprint/expiry metadata, and verifies actual node UID,
Ready state and architecture. Before publishing credentials it runs the same
Runtime binary's `--validate-registry PATH` command against staged inputs. That
command uses Runtime's real strict parser and creates clients without starting
workers, listening, opening a database or contacting Kubernetes.

The importer installs an immutable credential file with mode 0640 and the
source registry's owner/group, and writes an immutable **candidate registry**.
It never replaces the live registry, even if an unrelated deployment/editor
changes it during the final write. Existing candidate files are reused only
when byte-identical. Use a fresh candidate filename for a changed import.
Stdout includes the two IDs, artifact paths, `prepared=true`,
`requires_activation=true`, and the SHA-256 of the source registry snapshot.

The new registry entry resembles:

```json
{
  "target_id": "99f2f3b0-495a-4a7a-9e84-b4b35a7d21b8",
  "broker_resource_target_id": "de42849c-e0dc-43d4-8e63-9bb2bd056db4",
  "kubeconfig_path": "/etc/secure-provisioner/kubeconfigs/<resource-id>-<content-hash>.yaml"
}
```

Other policy fields come from the template. Repeat the same command to refresh
credentials for that node, using the currently active registry and a fresh
candidate output path; the registry target is updated, not duplicated.
Old credential files are retained because older processes may still use them.

The running Runtime loads its registry at startup. Importing files does not
reload or restart it. Activate the candidate through the normal reviewed
release/reload procedure after in-flight operations have finished. During
activation, all registry writers must use the same deployment exclusion and
recheck the source SHA-256 receipt; if the live registry changed, re-import from
its current contents. Then verify an actual
Scheduler-origin create and delete reaches confirmed cleanup. A direct Runtime
test using the credential resource ID does not exercise this contract.

## Existing legacy registrations and node replacement

The tool refuses to overwrite an entry whose lifecycle `target_id` is the
credential resource ID, or change the node UID associated with an existing
`broker_resource_target_id`. An old operation/binding may still use that ID
for cleanup. Withdraw the target from placement, finish or reconcile its
operations/bindings/routes, preserve a rollback copy of the registry, and only
then remove/migrate the old registration and import the current verified node.
Do not enable two registry entries for the same node to hide this mismatch.

This importer does not create instances, restart services, cancel queued
operations, release Broker reservations or clear CLEANUP_PENDING records.
Repairing existing records requires their own operation and resource evidence.

For local importer tests, build Runtime and set `RUNTIME_REGISTRY_VALIDATOR`
to that binary before running `python3 -m unittest discover -s deploy`.
