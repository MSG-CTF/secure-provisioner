# Candidate challenge network contracts

The seven JSON documents in [config/challenge-networks](../../config/challenge-networks/) record the reviewed source topology, discovered published image candidates and the inputs needed for deployment. Every document has `enabled: false`, `approval: null`, `stage: candidate` and `status: blocked_pending_operator_inputs`. They are readiness documents, **not Runtime policy catalogs**, and must never be passed to `PROVISIONER_IMAGE_POLICIES` or copied into an active catalog unchanged. Published image references are concrete candidates; every `approved_image_digest` remains null. No concrete destination address or raw Secret value is supplied.

Source baseline: [`MSG-CTF/2026_MSG_CTF` at `84742c511bb126a5e94d9d21c85ddf9b0611b923`](https://github.com/MSG-CTF/2026_MSG_CTF/tree/84742c511bb126a5e94d9d21c85ddf9b0611b923). The `containers` names, declared ports, exposure and resource profiles follow each challenge's `info.yaml`. `source_component` identifies the build directory or role where its name differs. Each JSON has source paths and inclusive line ranges in `evidence`.

## Candidate and active states

`author_defined_contract` records the official Compose, deployment document or Kubernetes policy. `candidate_runtime_mapping` records a proposed mapping and labels restrictions inferred from the platform baseline. `published_candidate` records the exact downloaded artifact/run/source identities and images. Each container's `published_image_ref` points to that candidate while its `approved_image_digest` stays null. An empty address array means missing operator input; it does not authorize a wildcard destination. `exposed_ports` records source `info.yaml` exposure, not an assertion that the production gateway should expose every declared health port.

For Afterimage and the five ordinary KOTH candidates, `operator_network_candidate` provides the concrete graph shape with published image identities, declared ports and the reported WEB isolation profile. `network_required_repositories` lists their exact repository identities for an eventual catalog-root guard. Every such object is marked `incomplete_must_not_activate`. Egress rules are deliberately absent because real operator destinations are unavailable. **The five ordinary KOTH candidates cannot perform their required production platform calls without those rules.** Approve image execution policies and valid release Secret bindings as well as network destinations before generating an active catalog. Dependency Hell has `operator_network_candidate: null` and `network_required_repositories: null`; its dedicated architecture is not an ordinary Runtime graph.

The planned ordinary Runtime modes are `PEER_GROUPS_V1` for shared membership and `EXPLICIT_TCP_V1` for directed TCP connections. A separate approved operator catalog entry binds a complete set of container names, immutable images, ports and execution profiles. Exact-host TCP egress rules require the real source container, one canonical unicast IPv4 `/32` or IPv6 `/128` and explicit TCP ports. Runtime rules filter addresses and ports; they do not enforce URL paths, FQDN ownership, TLS, authentication or DNS drift.

Ordinary workloads keep the default `STANDARD@v2` behavior. Caller Create JSON does not select these policies. The operator must register appropriate repository requirements when approving a graph so a later image rotation cannot silently restore full mesh. Accepted operations continue to replay their saved policy snapshot; catalog edits do not retrofit an accepted operation.

## Discovered published candidates

The downloaded publish index identified the following latest available bundles in that discovery set. These are publication records, not image approval or deployment evidence. Their full image references are recorded in the JSON contracts.

| Challenge | Artifact | Workflow run | Declared source SHA | Candidate images |
| --- | --- | --- | --- | --- |
| Afterimage | [12241266703](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39370165254/artifacts/12241266703) | [39370165254](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39370165254) | `e2199fdf0ce1f05652518246001af8cd3e4c8490` | 7, revision 578 |
| Card Battle Arena | [12186011245](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12186011245) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 1, revision 552 |
| Grand Tour Duel | [12186016197](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12186016197) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 1, revision 552 |
| Jenga | [12184953879](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12184953879) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 1, revision 552 |
| Pixel Smuggler | [12185867315](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12185867315) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 1, revision 552 |
| Swanopoly | [12185018549](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12185018549) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 4, revision 552 |
| Dependency Hell | [12185492586](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559/artifacts/12185492586) | [39250207559](https://github.com/MSG-CTF/2026_MSG_CTF/actions/runs/39250207559) | `7e852818f66755a8d858c973189098ceb00b300d` | 4 static roles, revision 552; separate job-runner missing |

Each schema-2 `artifact-v2.json` payload exactly matched its `registry-publish.json` artifact object. Container names, ports/public flags and resource profiles matched the pinned contracts; evidence `published_image` values matched the workload image references. The metadata reports scan PASS. Its workload container records contain only name, image and ports; they do not provide execution approval, image USER/capability inspection, Docker socket/mount requirements or a verified signature. The evidence `source_digest` is not substituted for the final published image identity; that relationship has not been independently assessed.

For every candidate, `git diff <published source SHA> 84742c511bb126a5e94d9d21c85ddf9b0611b923 -- <challenge directory>` found no changed files. The contracts label this `no_scoped_source_drift`. The images still declare their older source SHAs above. Challenge-tree equality does not establish a build at the newer baseline, build reproducibility or shared workflow/base-image provenance. Those checks and actual image configuration review remain activation requirements. The Grand Tour root-supervisor requirement and Dependency Hell's separate controller/runner architecture remain blocked regardless of matching metadata.

## Operator input inventory

| Contract | Official runtime container names | Required destination inputs | Other activation blockers |
| --- | --- | --- | --- |
| [Afterimage](../../config/challenge-networks/web-afterimage.json) | portal, core, bot, exporter, inventory-metadata, indexer, case-vault | Review portal's original external routing; provide real addresses/ports only if normal runtime needs them | Seven approved images, valid release Secret references, image users/writes, browser shared memory and indexer execution compatibility |
| [Card Battle Arena](../../config/challenge-networks/koth-card-battle-arena.json) | service | `TEAM_TOKEN_VERIFY_URL`: HTTPS hostname, exact addresses and actual TCP port | Current release references, UUID/auth/session configuration, persistent SQLite, health port consumers |
| [Grand Tour Duel](../../config/challenge-networks/koth-grand-tour-duel.json) | service | `KOTH_PLATFORM_BASE_URL`: actual origin, exact addresses and TCP port | Root supervisor execution approval, required capabilities/socket permissions/limits, persistent DB/submissions/replays, release references |
| [Jenga](../../config/challenge-networks/koth-jenga.json) | jenga | `PLATFORM_URL`: actual origin, exact addresses and TCP port | Organizer image/user/write review, session/auth configuration, persistent `JENGA_DB`; disable development auth bypass |
| [Pixel Smuggler](../../config/challenge-networks/koth-pixel-smuggler.json) | service | `TEAM_TOKEN_VERIFY_URL`, `TEAM_LIST_URL`: actual origins, exact addresses and TCP ports | Approved image/release references, production auth mode and persistent SQLite/WAL |
| [Swanopoly](../../config/challenge-networks/koth-swanopoly.json) | service, backend, test, submit | Backend verification/team-list API origins, exact addresses and TCP ports | Four approved images, current references, durable single-replica SQLite, match identity and isolated runner limits |
| [Dependency Hell](../../config/challenge-networks/koth-dependency-hell.json) | service, backend, score-service, judge-coordinator | App PostgreSQL 5432, coordinator PostgreSQL 5432, canonical platform 443, target cluster API 443; actual peers and selectors | Dedicated hostile-production Kustomize architecture, fifth job-runner image, separate namespaces/RBAC/admission/RuntimeClass, PVC/DB predeploy, mTLS and gateway release gates |

The release operator supplies immutable image identities and matching per-image policies. The Backend release operator supplies valid references for the exact current release; this document does not authorize replacing unavailable secrets with invented values. Platform/API/DB/cluster operators supply endpoint ownership, hostname verification, complete address sets and a procedure for address changes. Store secret material in the approved secret system and record references/key names here only.

For the small KOTH applications, source URLs may allow an explicit nondefault port; do not assume every platform call is TCP 443. Card requires HTTPS. Dependency Hell's official production policies explicitly require platform TCP 443 and PostgreSQL TCP 5432. Its release manifests contain deliberately unusable destination placeholders; replace them through the official private release overlay. They are not operating addresses and are not reproduced as candidate Runtime rules.

## Observed capacity bounds

The workspace evidence `.scratch/network-solve-audit-20261023/test-node-capacity.json`, checked at `2026-10-23T06:25:35Z`, records two **separate single-node targets**. Main `msg-runtime-k3s` has allocatable 1600m CPU, 2810MiB memory and 6855MiB ephemeral storage. Test `msg-test-1` has 4000m CPU, 15984MiB memory and 8317MiB ephemeral storage. Their capacity cannot be summed into one deployment target.

| Challenge | Source CPU / memory / ephemeral profile | Main necessary bounds | Separate test target necessary bounds |
| --- | --- | --- | --- |
| Afterimage | 2000m / 4000MiB / 2048MiB | Insufficient CPU and memory | Fits allocatable bounds |
| Card Battle Arena | 500m / 512MiB / 1024MiB | Fits allocatable bounds | Fits allocatable bounds |
| Grand Tour Duel | 6000m / 1536MiB / 2048MiB | Insufficient CPU | Insufficient CPU |
| Jenga | 300m / 256MiB / 512MiB | Fits allocatable bounds | Fits allocatable bounds |
| Pixel Smuggler | 1000m / 1024MiB / 1024MiB | Fits allocatable bounds | Fits allocatable bounds |
| Swanopoly | 6000m / 4096MiB / 2048MiB | Insufficient CPU and memory | Insufficient CPU |
| Dependency Hell aggregate | 5500m / 3072MiB / 4096MiB | Exceeds aggregate CPU/memory bounds | Exceeds aggregate CPU bounds |

These comparisons are necessary bounds, not a scheduler or readiness guarantee. Existing requests, placement rules, runtime overhead, resource splitting and available storage still need review. Grand Tour and Swanopoly need an approved target with more capacity; reducing their source profiles requires challenge approval. Dependency Hell needs a separate assessment of the official dedicated architecture, including controller and disposable runner resources; this table does not establish ordinary four-container fit. Each JSON records the capacity observation and a `target-capacity` operator input. No real candidate image was deployed by this capacity check.

## Afterimage membership and portal routing

The official organizer Compose defines:

| Internal network | Members |
| --- | --- |
| appnet | portal, core, bot |
| exportnet | portal, exporter, inventory-metadata |
| cartridgenet | portal, indexer |
| vaultnet | core, case-vault |

Shared members have bidirectional reachability across protocols and ports. An overlapping member does not create a direct policy edge between two nonmembers. Preserve these groups with `PEER_GROUPS_V1`; the older eight-edge TCP example adds application-port restrictions that Compose does not define. Compose `expose` values identify intended listeners, not ACLs. Source: [organizer Compose, lines 2–146](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/web-afterimage/prob/for_organizer/docker-compose.yml#L2).

Portal also belongs to the non-internal `edge` network. The existing platform egress `NONE` baseline therefore differs from the original portal external routing. The operator and author must confirm normal operation under that baseline, or identify required exact-host TCP exceptions. The candidate cannot be described as exact Docker bridge reproduction while that question remains open.

Only portal 8080 is declared public. Review actual image UID/writes/Secrets before registration: Compose also gives bot 1GB shared memory, indexer read-only root plus bounded tmpfs and `SETUID`/`SETGID`, and restricted case-vault settings. A network graph does not establish that the execution profile can run them.

## Grand Tour bundled runner

The official final Dockerfile target is one `service` image containing the runner supervisor. The separate `runner`, `platform-test`, `checker` and `e2e` local Compose roles do not add production containers. The default is `KOTH_RUNNER_MODE=bundled`; only an explicitly chosen external deployment uses a separate runner over `/run/koth-runner/runner.sock`. The local separate runner has `network_mode: none`.

The official supervisor must start as root, retain its documented capabilities and permanently drop HTTP children to UID/GID 10001. It also requires the runner group/socket permissions and a hard open-file limit of at least 8192. Applying a blanket STANDARD nonroot policy prevents startup. An exact-host egress entry cannot resolve that incompatibility; the platform must approve a suitable isolated execution path before activation. Do not broaden shared-node privileges as part of network configuration. Sources: [official image distinction](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-grand-tour-duel/prob/for_organizer/service/README.md#L119), [execution contract](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-grand-tour-duel/prob/for_organizer/admin.md#L87).

## Swanopoly role boundaries

The organizer deployment document requires `service -> backend:8082`, `backend -> test:9001` and `backend -> submit:9002`, with only backend reaching runner listener ports. Public entry and health are service 8080/9090; backend and runner listeners stay private. The local Compose itself uses a flat network. Denying all other private edges and all runner external initiation is a candidate platform restriction that still needs normal-operation acceptance. Source: [deployment ports and restrictions](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-swanopoly/prob/for_organizer/README-DEPLOYMENT.md#L44).

Swanopoly supports SQLite with one backend replica and a durable data volume. Supplying a PostgreSQL DSN does not migrate its storage implementation. Preserve production mode, separate test/submit modes, runner authentication, child-process secret exclusion, CPU concurrency and execution limits.

## Dependency Hell dedicated deployment

Retain `prob/for_organizer/deploy/k8s/hostile-production` as the authoritative render entrypoint. The application, coordinator control and disposable runner workloads occupy separate namespaces. Public `info.yaml` names map to manifest roles as follows:

| info.yaml name | Production manifest role/container |
| --- | --- |
| service | frontend / frontend |
| backend | backend / backend |
| score-service | backend-internal / score-service |
| judge-coordinator | dependency-hell-coordinator / coordinator |
| Not an info.yaml static container | Disposable job-runner Jobs in the runner namespace |

The public manifest cannot express the complete production architecture. The contract deliberately has no ordinary Runtime mode and forbids ordinary graph generation. `deploy/compose.production.yml` is a trusted web/DB rehearsal, not competition production. Sources: [authoritative render](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-dependency-hell/prob/for_organizer/deploy/k8s/hostile-production/kustomization.yaml#L4), [deployment scope](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-dependency-hell/prob/for_organizer/deploy/README.md#L41).

Default deny applies to all three namespaces. Required directed application flows are gateway→frontend 8080, gateway/frontend→public backend 8081, platform→score 8082, public backend→coordinator 8090 and runner→coordinator 8090. The coordinator schedules via the cluster API; the runner fetches artifacts/inputs and posts results to the coordinator. There is no coordinator→runner TCP edge. Runner egress is only DNS and coordinator; participant network syscalls are additionally blocked inside the sandbox. Source: [application policies](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-dependency-hell/prob/for_organizer/deploy/k8s/base/networkpolicy.yaml), [control/runner policies](https://github.com/MSG-CTF/2026_MSG_CTF/blob/84742c511bb126a5e94d9d21c85ddf9b0611b923/koth-dependency-hell/prob/for_organizer/judge-coordinator/manifests/networkpolicy.yaml).

The private release overlay must provide real DB/platform/API peers, namespace labels and gateway configuration, then satisfy the official release gates. Preserve approved images, runner digest/profile binding, RuntimeClass, node separation, exact Job admission, least-privilege RBAC, quotas/PID limits, RWX storage, migration/protected-key checks, DB TLS, platform/coordinator mTLS and recovery procedures. The declared aggregate resource profile is not a substitute for those per-role settings. Do not translate this into four ordinary Runtime containers.

## Activation procedure and evidence

1. Resolve every required `operator_inputs` item with its named owner. Review source drift if the release revision differs from the pinned baseline. Verify that the complete image set was built from the reviewed source; a source SHA alone does not prove image provenance.
2. Approve exact images, compatible execution settings, current Backend Secret bindings and storage. For Grand Tour and Dependency Hell, resolve the architectural execution blockers first.
3. For ordinary Runtime candidates, create a separate operator catalog from reviewed identities and destinations. Use Afterimage groups or the documented directed TCP edges. Add repository requirements and preserve default deny/DNS/public-port behavior. Do not point Runtime at these readiness files.
4. For Dependency Hell, use the official Kustomize private overlay and its release verification gates instead of ordinary Runtime catalog generation.
5. Exercise real normal operation and intended deny paths in disposable production-compatible infrastructure. Check all relevant private edges, exact egress versus other destinations, DNS, public Pod-IP/NodePort behavior, authentication, scoring, persistence and cleanup. Development stubs or disabled authentication are insufficient evidence of production connectivity.
6. Record source/image identity, approved execution policy, endpoint ownership, configuration revision, acceptance results and cleanup evidence before a separately authorized production activation. This change supplies candidates only; it neither edits the production catalog nor deploys a Runtime binary.

JSON parsing and source crosschecks establish document consistency. They do not prove live CNI enforcement, image compatibility, author solution success or production readiness.
