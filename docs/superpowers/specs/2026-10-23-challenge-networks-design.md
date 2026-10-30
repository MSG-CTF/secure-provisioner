# Challenge-specific network policies

## User-directed scope

The user requested fixing stale Backend Secret references, retesting affected challenges, and configuring Afterimage and KOTH networks per challenge after reviewing the impact report. Preserve the existing public Create API and the STANDARD@v2 default for ordinary workloads. Do not bypass Backend release approval or synthesize replacement FLAG values.

## Approach

Reuse PR #49's operator-owned, exact-image workload policy snapshots, rebased onto current dev. Keep its EXPLICIT_TCP_V1 mode for compatibility. Add PEER_GROUPS_V1 to preserve Compose shared-network membership: two distinct declared containers sharing a named group may communicate in both directions, without an additional TCP/application-port restriction. Default deny, DNS and the explicit public-port exception remain.

KOTH platform/database access is an optional operator-owned egress exception in the saved workload policy. Each rule names an exact source container, one canonical unicast IPv4 /32 or IPv6 /128 destination, and explicit TCP ports. Reject documentation placeholders, wildcard networks, loopback, link-local, multicast and unspecified destinations. No user-provided JSON may attach or override a graph or egress rule. This is address filtering, not FQDN or URL-path enforcement; production addresses must be supplied and reviewed. Default outbound denial remains everywhere else.

An explicit network_required_repositories list prevents newly rotated digests from falling back to full mesh when graph entries are removed. Keep current dev's fingerprint-based accepted-request replay: identical input reuses the accepted operation and its original policy snapshot; changed input conflicts.

Alternatives considered: keeping the old eight-edge Afterimage example would add restrictions not present in Compose; changing all STANDARD traffic to unrestricted egress would expose unrelated workloads. Neither satisfies the requested problem-specific behavior.

## Activation constraints

Afterimage groups: appnet={portal,core,bot}; exportnet={portal,exporter,inventory-metadata}; cartridgenet={portal,indexer}; vaultnet={core,case-vault}. Only portal's approved public port is exposed. Portal's non-internal edge network permits outbound traffic in Compose; retaining egress NONE is the existing platform baseline and must be acknowledged, not described as exact Docker bridge reproduction. Do not activate real Afterimage digests before reviewing images, UID/writes/Secrets and any required portal egress.

KOTH configurations remain candidates until real platform/DB addresses, exact images, Secrets and execution requirements exist. Grand Tour's root supervisor and Dependency Hell's Kubernetes controller/runner architecture need separate execution approval; a network profile alone does not make them compatible with STANDARD nonroot execution. Do not activate placeholder CIDRs or broaden shared-node privileges.

## Verification

Test strict parsing, group membership reachability and forbidden nonmember pairs, external-rule validation, clone/persistence/replay, explicit repository guard after complete graph removal, unchanged default/v1 behavior and live CNI allow/deny behavior in disposable namespaces. Keep the operator catalog and production binary unchanged during implementation. Actual affected challenge retries require valid Backend references; an unapproved/expired release remains denied.
