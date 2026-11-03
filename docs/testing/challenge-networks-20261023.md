# Challenge network verification — 2026-10-23

## Scope

Candidate extension of PR #49 on Runtime dev `a4c1f47d5a96f44222c87cc3fd458943771a61b7`. This change was not deployed as the production Runtime binary or active image catalog. Disposable K3s diagnostics used NetworkPolicies emitted by the candidate production `StaticResolver.Resolve` and `k3s.BuildResourceSet` functions. They did not deploy actual Afterimage/KOTH images or bypass Backend Secret approval.

The test node uses K3s with kube-router network-policy enforcement and IPv4 Pod networking. Diagnostic Python processes ran nonroot, with read-only root filesystems, no service-account token, dropped capabilities, default seccomp and bounded CPU/memory. Cached approved image contents supplied the Python interpreter; their ordinary challenge entrypoint and FLAG flow were not exercised.

## Live CNI results

| Scenario | Checks | Result |
| --- | --- | --- |
| Afterimage's four original membership groups | 84 TCP checks across all 42 directed distinct-container pairs at a declared and an undeclared test port | 32 allowed and 52 denied exactly as expected |
| Same membership fixture, exact-host TCP egress | 21 source/host/port cases | Only the nominated source could reach the nominated host and port |
| Same membership fixture, UDP | 2 cases | Shared-group peer allowed; nonmember pair denied |
| Swanopoly's three directed TCP edges | 24 TCP peer/port cases | Only service→backend:8082, backend→test:9001 and backend→submit:9002 allowed |
| Same directed fixture, exact-host TCP egress | 12 source/host/port cases | Backend-only approved host/port allowed |
| Same directed fixture, public NodePort and UDP | 2 cases | Public NodePort reachable from unrelated namespace; UDP runner path denied |
| **Total** | **145** | **0 reachability mismatches** |

DNS succeeded from all seven membership peers and all four directed peers. These DNS observations are additional to the 145 checks. Additional NodePort observations: core could reach the membership fixture's portal public NodePort; case-vault could not. Backend and runner could not initiate the directed fixture's frontend NodePort path. Public NodePort is a separate intended public-ingress exception and does not make private service ports public.

The egress destination was a controlled Pod in another disposable Namespace, identified by its exact IPv4 address. This proves the generated source/address/port rules on this CNI; it does not establish connectivity to the production platform or managed PostgreSQL.

Membership result time: `2026-10-23T06:11:34.398480Z`. Directed result time: `2026-10-23T06:15:16.982743Z`. Each test finally deleted its diagnostic Namespaces and confirmed none remained. An independent final cluster check follows in the local operator evidence.

## Automated checks

- Test-first failures covered missing peer-group mode, missing explicit repository requirements, snapshot field loss and missing generated rules.
- The empty-list codec regression reproduced a saved identity change; serialization now preserves nil versus empty peer/egress lists.
- Admission tests cover strict parsing, invalid sources/addresses/ports, direct membership without transitive edges, complete digest replacement and graph removal, public-field injection rejection, and fingerprinted HTTP replay after catalog changes.
- Snapshot tests cover nested-slice cloning, operation codec round-trips and binding preservation.
- Readiness-time drift regression injects either a broad additional policy or a broadened DNS policy after Deployment creation. Both fail with no success result/checkpoint and verify rollback against the original Namespace UID/resource version.
- Full `go test -work ./...`: all 12 packages passed. Targeted affected packages also passed uncached. `git diff --check` passed.
- `go vet ./...` passed. All six ordinary candidate graphs, using the discovered published image identities, also passed the production `ValidateWorkloadNetwork` validator. This validates graph structure, not image execution approval.
- Independent review found no actionable defects; the requested readiness-drift regression closed its identified test gap.

## Published candidates and current capacity

The seven official Actions publish bundles provide 19 image candidates. Their artifact-v2 payloads match the corresponding registry-publish artifact, and container names, ports, public flags and resources match the source contracts. Scoped challenge source comparisons from each build source SHA to `84742c511bb126a5e94d9d21c85ddf9b0611b923` found no changes. Published references are retained as candidates with no image approval; the evidence source digest is not assumed to be the final published-image digest.

At `2026-10-23T06:25:35Z`, the two independent single-node targets had allocatable CPU/memory of 1600m/2810 MiB and 4000m/15984 MiB. Afterimage's declared 2000m/4000 MiB exceeds the smaller target's bounds. Grand Tour and Swanopoly each request 6000m CPU, exceeding both targets. Dependency Hell's declared aggregate is 5500m but must be assessed against its dedicated architecture rather than scheduled as an ordinary four-container Runtime workload. Passing an allocatable upper-bound check does not prove sufficient currently unreserved resources or application startup.

## Activation blockers and proof limits

1. Actual approved image digests, compatible UID/writes/capabilities/storage and current Backend references are still required for the seven challenge contracts. Missing references stay denied.
2. Runtime history contains 88 distinct recorded image/container/Secret-reference combinations. Rechecking them found five valid workload image sets; references for the seven previously blocked problems still returned `RUNTIME_SECRET_NOT_FOUND`. This does not distinguish absent records, empty secret bindings or unapproved/expired temporary releases without Backend administrator metadata.
3. Actual KOTH platform/DB destination ownership, exact address sets, ports, TLS/authentication and address-change handling remain operator inputs. The candidate does not use wildcard or documentation-placeholder destinations.
4. Grand Tour's bundled root supervisor is incompatible with a blanket nonroot STANDARD image policy. Dependency Hell requires its dedicated official hostile-production Kustomize architecture, controller/runner separation, RBAC/admission, storage and DB/API release gates.
5. Live IPv6 CNI enforcement was not tested. IPv6 input validation and manifest rendering alone do not approve production IPv6 use.
6. Actual problem solving, platform authentication, scoring, persistent data, Scheduler reset, complete team/instance isolation and production activation are not established by these diagnostics.

The seven inactive source contracts and operator input inventory are documented in [challenge network contracts](../operations/challenge-network-contracts.md). The operator catalog format and admission/replay semantics are documented in [workload network policies](../operations/workload-network-policies.md).
