# Operator-owned workload network graph

Runtime reads `PROVISIONER_IMAGE_POLICIES` at startup. A schema-version-2 policy file may add `workload_networks` beside `managed_repositories` and `images`; schema version 1 and its default `STANDARD@v2` instance-wide internal access remain valid. This is an operator file, not a Create API field. New Create JSON containing `internal_connections` or `workload_network` is rejected.

Each network entry requires a unique DNS-label `id`, `mode: "EXPLICIT_TCP_V1"`, an `isolation_profile`, the **complete** set of container names, immutable image digests and declared ports, and a directed `allow` array. Every image must also have an enabled per-image policy in `images` with the same name, profile and ports; a digest may be in only one network. `allow: []` explicitly allows no private container traffic. Each edge targets a declared TCP port on a different destination container. Duplicate or unknown fields, duplicate edges, and incomplete request image sets fail closed.

When an exact set matches, the saved `STANDARD@v2` operation has the network graph and Runtime creates both source egress and destination ingress rules. It does not create `allow-instance-internal`. Repositories used by a graph cannot use a newly enabled digest with default full mesh; add and approve a matching graph for a digest rotation. Requests outside graph-managed repositories retain default `STANDARD@v2` behavior. On a duplicate request ID, a changed graph conflicts; queued operations replay their saved policy. Binding snapshots record the graph. A Namespace containing any extra NetworkPolicy, including a stale `allow-instance-internal`, fails before Deployment creation and is rolled back using the Namespace UID. Runtime does not silently delete the extra policy and continue.

Kubernetes NetworkPolicies are additive. The standard public ingress rule remains: on `NODE_PORT`, `portal:8080` ingress is public. Same-instance Pod traffic still needs an allowed source egress edge; public ingress alone does not grant source egress. Actual CNI behavior for Pod-to-node-IP/NodePort can differ, so live acceptance must include negative traffic tests from an unapproved Pod to both the portal Pod IP and node IP:NodePort. Also test allowed edges, disallowed private ports, DNS, and external egress. Cluster RBAC must prevent another actor adding a broad policy after Runtime readback. No complete isolation claim follows from unit tests alone.

## Afterimage policy template — **not approved or active**

The following fragment belongs inside an operator-owned schema-version-2 policy file **only after** the authors approve every edge and operators register the seven real digests as enabled `images` entries. Every `<..._DIGEST>` value is an intentionally invalid placeholder. The eight edges are a smoke-test hypothesis from the challenge Compose configuration and runtime handoff, not an author-approved graph. Do not paste this fragment into the live policy file yet.

```json
{
  "id": "afterimage-v1",
  "mode": "EXPLICIT_TCP_V1",
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
  "allow": [
    {"from":"portal","to":"core","port":3000},
    {"from":"portal","to":"exporter","port":4100},
    {"from":"portal","to":"indexer","port":4300},
    {"from":"core","to":"bot","port":4000},
    {"from":"core","to":"case-vault","port":4400},
    {"from":"bot","to":"core","port":3000},
    {"from":"bot","to":"portal","port":8080},
    {"from":"exporter","to":"inventory-metadata","port":4200}
  ]
}
```

The policy file's other fields still follow [the image policy catalog](web-image-policy-catalog.md). The catalog currently manages the seven Afterimage repositories but does **not** register their digests. Their UID, writable paths, readiness, secret requirements, image publication, and real digests need separate review. Adding only the graph fragment would fail startup because its images do not match enabled per-image policies.

## Afterimage Create request template — **not deployable**

This is the CI/CD-side JSON shape after author approval and exact digest registration. Replace all `<...>` values with reviewed values. `run_as_user` is shown as a provisional input; the registered per-image policy pins the final UID and writable paths. The request has no network field. It uses the seven declared private/public ports and resource profile from Afterimage's `info.yaml`. The ordinary Scheduler/service authorization path is required for seven containers; the single-container CI smoke token cannot submit it. Shared secrets and FLAG references must be supplied through the approved Backend flow before a real Create can succeed.

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
