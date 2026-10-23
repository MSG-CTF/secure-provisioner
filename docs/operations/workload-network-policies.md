# Operator-owned workload network graph

Runtime reads `PROVISIONER_IMAGE_POLICIES` at startup. A schema-version-2 policy file may add `workload_networks` beside `managed_repositories` and `images`; schema version 1 and its default `STANDARD@v2` instance-wide internal access remain valid. This is an operator file, not a Create API field. New Create JSON containing `internal_connections` or `workload_network` is rejected.

Each network entry requires a unique DNS-label `id`, an `isolation_profile`, and the **complete** set of container names, immutable image digests and declared ports. Every image must also have an enabled per-image policy in `images` with the same name, profile and ports; a digest may be in only one network. Duplicate or unknown fields and incomplete request image sets fail closed. Two modes are available:

- `EXPLICIT_TCP_V1` requires a directed `allow` array. Each `{from,to,port}` edge permits TCP to a declared port on a different destination container. `allow: []` permits no private container traffic. This mode cannot contain `peer_groups`.
- `PEER_GROUPS_V1` uses `peer_groups: [{name,members}]` and omits `allow`. A named group has one or more distinct declared container names. All members sharing a group may communicate in both directions without a port or protocol restriction. Overlapping groups do not create direct access between containers that share no group. An empty or omitted group list permits no private inter-container traffic. This models Compose peer reachability rather than every Docker bridge behavior; protocol enforcement still depends on the CNI.

Either mode may add `egress: [{from,cidr,ports}]` for operator-reviewed platform or database destinations. Each rule selects one declared source container and permits only the listed TCP ports to a canonical IPv4 `/32` or IPv6 `/128` host. Ports must be distinct integers from 1 to 65535, including across rules for the same source and destination. Private hosts are allowed. Broad prefixes, hostnames, noncanonical addresses, IPv4-mapped IPv6, documentation ranges, loopback, link-local, multicast, unspecified and reserved IPv4 destinations are rejected. These are address rules; they do not enforce DNS names, HTTP paths or application authorization. For example, after reviewing the real internal host:

```json
"egress": [{"from":"service","cidr":"10.20.30.40/32","ports":[443]}]
```

The example address is illustrative, not an approved deployment destination. `OutboundMode: NONE` retains the baseline of external denial, with these saved operator exceptions and existing DNS allowance applied explicitly.

When an exact set matches, the saved `STANDARD@v2` operation has the network graph and Runtime creates matching ingress and egress rules. It does not create `allow-instance-internal`. Repositories used by a graph cannot use a newly enabled digest with default full mesh; add and approve a matching graph for a digest rotation. A schema-2 catalog should also list these managed repositories in `network_required_repositories`. This independent requirement rejects new Creates even if every graph is removed during digest rotation. Required repository names must be distinct members of `managed_repositories`. Requests outside these requirements retain default `STANDARD@v2` behavior.

An identical caller request with an accepted input fingerprint reuses its original operation and policy snapshot after operator graph changes or removal. Changed caller input conflicts. Legacy operations without a fingerprint compare the saved policy request. Queued operations and Binding snapshots retain peer groups and egress rules. Existing instances and previously accepted operations without a graph keep their saved full-mesh behavior; catalog changes do not retrofit them. A Namespace containing any extra NetworkPolicy, including a stale `allow-instance-internal`, fails before Deployment creation and is rolled back using the Namespace UID. Runtime does not silently delete the extra policy and continue.

Kubernetes NetworkPolicies are additive. The standard public ingress rule remains: on `NODE_PORT`, `portal:8080` ingress is public. Same-instance Pod traffic still needs an allowed source egress edge; public ingress alone does not grant source egress. Actual CNI behavior for Pod-to-node-IP/NodePort can differ, so live acceptance must include negative traffic tests from an unapproved Pod to both the portal Pod IP and node IP:NodePort. Also test allowed edges, disallowed private ports, DNS, and external egress. Cluster RBAC must prevent another actor adding a broad policy after Runtime readback. No complete isolation claim follows from unit tests alone.

## Afterimage policy template — **not approved or active**

The following fragment preserves Afterimage's declared shared-network memberships. It belongs inside an operator-owned schema-version-2 policy file **only after** operators review and register the seven real digests as enabled `images` entries with compatible execution and Secret requirements. Every `<..._DIGEST>` value is an intentionally invalid placeholder. Add all seven repositories to the catalog's `network_required_repositories` list. Do not paste this fragment into the live policy file yet.

The older eight directed TCP paths were an unapproved smoke hypothesis and imposed restrictions beyond Compose membership. This candidate replaces those paths with the four original peer groups. Portal also joins Compose's non-internal `edge` network. Runtime retains default external denial unless a reviewed exact-host egress exception is supplied, so the candidate does not reproduce portal's unrestricted Compose outbound access. Review any required portal egress before activation.

The independent requirement belongs at the catalog root:

```json
"network_required_repositories": [
  "ghcr.io/msg-ctf/challenges/web-afterimage/portal",
  "ghcr.io/msg-ctf/challenges/web-afterimage/core",
  "ghcr.io/msg-ctf/challenges/web-afterimage/bot",
  "ghcr.io/msg-ctf/challenges/web-afterimage/exporter",
  "ghcr.io/msg-ctf/challenges/web-afterimage/inventory-metadata",
  "ghcr.io/msg-ctf/challenges/web-afterimage/indexer",
  "ghcr.io/msg-ctf/challenges/web-afterimage/case-vault"
]
```

The following entry belongs in `workload_networks`:

```json
{
  "id": "afterimage-v1",
  "mode": "PEER_GROUPS_V1",
  "isolation_profile": "WEB",
  "containers": [
    {"name":"portal","image":"ghcr.io/msg-ctf/challenges/web-afterimage/portal@sha256:<PORTAL_DIGEST>","ports":[8080]},
    {"name":"core","image":"ghcr.io/msg-ctf/challenges/web-afterimage/core@sha256:<CORE_DIGEST>","ports":[3000]},
    {"name":"bot","image":"ghcr.io/msg-ctf/challenges/web-afterimage/bot@sha256:<BOT_DIGEST>","ports":[4000]},
    {"name":"exporter","image":"ghcr.io/msg-ctf/challenges/web-afterimage/exporter@sha256:<EXPORTER_DIGEST>","ports":[4100]},
    {"name":"inventory-metadata","image":"ghcr.io/msg-ctf/challenges/web-afterimage/inventory-metadata@sha256:<INVENTORY_METADATA_DIGEST>","ports":[4200]},
    {"name":"indexer","image":"ghcr.io/msg-ctf/challenges/web-afterimage/indexer@sha256:<INDEXER_DIGEST>","ports":[4300]},
    {"name":"case-vault","image":"ghcr.io/msg-ctf/challenges/web-afterimage/case-vault@sha256:<CASE_VAULT_DIGEST>","ports":[4400]}
  ],
  "peer_groups": [
    {"name":"appnet","members":["portal","core","bot"]},
    {"name":"exportnet","members":["portal","exporter","inventory-metadata"]},
    {"name":"cartridgenet","members":["portal","indexer"]},
    {"name":"vaultnet","members":["core","case-vault"]}
  ]
}
```

The policy file's other fields still follow [the image policy catalog](web-image-policy-catalog.md). The catalog currently manages the seven Afterimage repositories but does **not** register their digests. Their UID, writable paths, readiness, secret requirements, image publication, and real digests need separate review. Adding only the graph fragment would fail startup because its images do not match enabled per-image policies.

## Afterimage Create request template — **not deployable**

This is the CI/CD-side JSON shape after execution review and exact digest registration. Replace all `<...>` values with reviewed values. `run_as_user` is shown as a provisional input; the registered per-image policy pins the final UID and writable paths. Indexer's privilege requirements and the browser's resources require separate compatibility review; a network policy does not resolve them. The request has no network field. It uses the seven declared private/public ports and resource profile from Afterimage's `info.yaml`. The ordinary Scheduler/service authorization path is required for seven containers; the single-container CI smoke token cannot submit it. Shared secrets and FLAG references must be supplied through the approved Backend flow before a real Create can succeed.

```json
{
  "request_id": "<REQUEST_ID>",
  "instance_id": "<INSTANCE_UUID>",
  "team_id": "<TEAM_UUID>",
  "isolation_profile": "WEB",
  "target": {"runtime_type":"KUBERNETES","target_id":"<TARGET_ID>"},
  "workload": {
    "containers": [
      {"name":"portal","image":"ghcr.io/msg-ctf/challenges/web-afterimage/portal@sha256:<PORTAL_DIGEST>","ports":[8080],"exposed_ports":[8080],"run_as_user":10001},
      {"name":"core","image":"ghcr.io/msg-ctf/challenges/web-afterimage/core@sha256:<CORE_DIGEST>","ports":[3000],"exposed_ports":[],"run_as_user":10001},
      {"name":"bot","image":"ghcr.io/msg-ctf/challenges/web-afterimage/bot@sha256:<BOT_DIGEST>","ports":[4000],"exposed_ports":[],"run_as_user":10001},
      {"name":"exporter","image":"ghcr.io/msg-ctf/challenges/web-afterimage/exporter@sha256:<EXPORTER_DIGEST>","ports":[4100],"exposed_ports":[],"run_as_user":10001},
      {"name":"inventory-metadata","image":"ghcr.io/msg-ctf/challenges/web-afterimage/inventory-metadata@sha256:<INVENTORY_METADATA_DIGEST>","ports":[4200],"exposed_ports":[],"run_as_user":10001},
      {"name":"indexer","image":"ghcr.io/msg-ctf/challenges/web-afterimage/indexer@sha256:<INDEXER_DIGEST>","ports":[4300],"exposed_ports":[],"run_as_user":10001},
      {"name":"case-vault","image":"ghcr.io/msg-ctf/challenges/web-afterimage/case-vault@sha256:<CASE_VAULT_DIGEST>","ports":[4400],"exposed_ports":[],"run_as_user":10001}
    ],
    "resource_limits": {"cpu_millicores":2000,"memory_mib":4000,"ephemeral_storage_mib":2048}
  }
}
```
