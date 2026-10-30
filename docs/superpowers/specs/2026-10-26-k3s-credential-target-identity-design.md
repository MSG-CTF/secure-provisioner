# K3s credential import identity

The user wants future imports from Broker's K3s credential API to produce the
same executable target ID that Scheduler sends, without per-server manual ID
mapping. The observed failure used a Node UID while Runtime had registered the
credential's resource ID.

## Contract

- Keep `resource_target_id` as the credential lookup/pagination identity.
- Add nullable `target_id` to Broker list and detail responses, read from the
  current Kubernetes resource observation. It is the same ID sent to Scheduler.
- Never substitute the resource ID when the node ID is missing.
- Runtime's maintained import tool fetches one credential by resource ID,
  validates the embedded kubeconfig and certificate metadata, reads the actual
  Kubernetes node, and requires its UID to equal the advertised target ID.
- Register the verified `target_id`, preserving the resource ID in the import's
  non-secret identity report and credential filename.
- A caller-supplied cluster template supplies the existing Runtime policy,
  enabled state, provider/region/architecture and exposure settings. Credential
  possession alone must not invent isolation approvals.
- Preserve unrelated registry entries. Re-import updates the same target;
  an existing legacy resource-ID registration or changed node identity needs
  explicit operator migration, rather than silently removing cleanup routes.
- Import uses Runtime's real registry validator, then prepares an immutable
  candidate without replacing the live registry. The receipt includes the
  source registry hash; normal deployment exclusion and rechecking that hash
  are required at activation. Import performs no service restart, workload
  creation or state cleanup.

## Approaches

Changing Broker/Scheduler to use resource IDs in lifecycle APIs would break the
documented Node UID contract and existing operations. Discovering a UID solely
in an ad-hoc script would leave the API ambiguous. The selected approach adds
the execution ID to the API and verifies it during a repeatable import.

## Verification

Broker tests use isolated PostgreSQL and real authenticated list/detail routes;
they cover distinct IDs, current node identity, and an unobserved node. Import
tests cover the resulting registry ID, mismatch/missing identity, unsafe
kubeconfigs, failed node reads, repeated imports, unrelated entries, legacy
registration rejection, atomic writes and secret-free diagnostics. Real API
reads may validate compatibility; production mutation/deployment is separate.
