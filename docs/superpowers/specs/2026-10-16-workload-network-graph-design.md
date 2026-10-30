# Operator-owned workload network graph

## Intent and scope

Allow Runtime operators to opt an exact set of reviewed image digests into a per-container TCP allow graph without changing the Create API. The default `STANDARD@v2` behavior remains instance-wide internal access. The retired request field `internal_connections` remains rejected. No Afterimage digest or unapproved edge is activated in the checked-in policy file.

## Policy contract

The operator-owned image policy file accepts schema version 2 with optional `workload_networks`. Each entry has a unique DNS-label `id`, `mode: EXPLICIT_TCP_V1`, `isolation_profile`, a nonempty exact list of `{name,image,ports}` identities, and an `allow` list of `{from,to,port}` directed edges. Each identity must reference an enabled image policy with the same name, profile and declared ports. A digest belongs to at most one graph. Every edge must reference a distinct declared source and destination, target a declared destination TCP port, and be unique. Empty `allow` means no private inter-container traffic.

At admission, any image participating in a graph requires the request's entire container image/name/port set to match that graph. Once a repository appears in a graph, newly enabled digests in that repository require a matching graph instead of falling back to full mesh. The server attaches a deep-copied graph snapshot to the internal policy request. The public JSON type has no network field. `StaticResolver` validates the graph and preserves it in `STANDARD@v2` resolved policy. Operation and binding snapshots retain the graph. A duplicate request after operator policy drift conflicts or is rejected; it cannot silently receive broader access. A queued operation replays its saved graph independently of the current policy file.

## Kubernetes application

For the opt-in graph, build directed source egress and destination ingress rules with Pod selectors and exact TCP ports. Omit `allow-instance-internal`. Keep default deny, DNS, and public ingress. Before Deployment writes, list all NetworkPolicies in the new Namespace and fail if any policy outside the desired set exists, including a stale `allow-instance-internal`; verify again before reporting success. Failure uses existing namespace rollback and cleanup. `NODE_PORT` public ingress allows the public portal port from every source, but an internal Pod still needs an approved source egress edge to reach it. External traffic arriving through NodePort is an intended public exception. Actual Pod-to-node-IP/NodePort behavior can vary with CNI processing, so a live negative test must cover both the portal Pod IP and node IP:NodePort before claiming isolation.

The Namespace may still be changed by a privileged actor after readback. Cluster RBAC/admission control and live CNI testing are required before claiming deployed isolation. Kubernetes Service DNAT ordering must be validated on the target CNI.

## Verification

Test strict policy parsing and exact digest-set admission; no JSON escape hatch; resolver snapshot cloning; exact ingress/egress generation and unchanged default/v1 behavior; stale or unknown NetworkPolicy failure before Deployment; operation copy/idempotency and persistence round-trips; binding snapshot; full Go suite. Documentation gives an Afterimage policy and request template with unregistered digests and unapproved edges visibly labeled placeholders.
