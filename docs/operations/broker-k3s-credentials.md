# Import Broker K3s credentials with the Scheduler target ID

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
