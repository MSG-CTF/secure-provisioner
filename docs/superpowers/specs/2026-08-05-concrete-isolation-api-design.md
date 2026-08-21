# Concrete Isolation API Simplification Design

## Goal

Keep the existing Scheduler-to-Provisioner create contract recognizable while
adding only the concrete fields needed to build a multi-container isolated
runtime. Challenge identity and profile selection remain Scheduler concerns;
the Provisioner receives the already-resolved workload and enforces its fixed
security baseline.

## Decision

Remove these fields from `POST /internal/v1/instances`:

- `challenge_ref`
- `isolation_ref`
- `resource_profile_ref`

Keep the existing `resource_limits` object. The Scheduler resolves any
challenge-side resource profile into those numeric values before calling the
Provisioner. The Provisioner applies `STANDARD@v1` internally and does not
allow the caller to select or weaken the baseline.

The challenge source and DevSecOps pipeline may continue to store challenge
IDs, versions, isolation profile references, and resource profile references.
Those are artifact and scheduling metadata, not fields in the concrete runtime
create request.

## External create contract

The resulting multi-container request is:

```json
{
  "request_id": "create-team18-web2-01",
  "instance_id": "22222222-2222-4222-8222-222222222222",
  "team_id": "00000000-0000-4000-8000-000000000018",
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "containers": [
      {
        "name": "web",
        "image": "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ports": [8080],
        "expose": true,
        "run_as_user": 101,
        "writable_paths": [
          {
            "path": "/tmp",
            "size_mib": 64
          }
        ]
      },
      {
        "name": "api",
        "image": "ghcr.io/msg-ctf/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ports": [8080],
        "expose": false,
        "run_as_user": 10001,
        "writable_paths": []
      }
    ],
    "internal_connections": [
      {
        "source_container": "web",
        "destination_container": "api",
        "protocol": "TCP",
        "port": 8080
      }
    ],
    "outbound_mode": "NONE",
    "resource_limits": {
      "cpu_millicores": 200,
      "memory_mib": 256,
      "ephemeral_storage_mib": 256
    }
  }
}
```

The existing single-container shape remains accepted:

```json
{
  "request_id": "create-team18-single-01",
  "instance_id": "11111111-1111-4111-8111-111111111111",
  "team_id": "00000000-0000-4000-8000-000000000018",
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "image": "ghcr.io/msg-ctf/challenge@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "container_port": 8080,
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

`containers` and the legacy `image`/`container_port` pair remain mutually
exclusive.

## Ownership boundary

### Challenge artifact and DevSecOps

- Store challenge ID and version.
- Store policy/profile references selected by the platform operator.
- Build images and resolve every deployable image to an immutable digest.
- Publish an immutable, validated challenge artifact.

### Scheduler

- Select the challenge version and target.
- Enforce the team instance-count policy.
- Resolve the resource profile to concrete `resource_limits`.
- Send the concrete container topology and approved per-challenge exceptions.
- Retain challenge/profile identities for business audit.

### Provisioner

- Treat the Scheduler as authoritative for challenge identity and resource
  selection.
- Validate concrete resource values for positivity, numeric safety, and at
  least one allocatable unit per container.
- Apply the submitted resource totals as container requests/limits and enforce
  them with `ResourceQuota` and `LimitRange`.
- Apply `STANDARD@v1` unconditionally.
- Reject any concrete exception that would weaken the baseline.
- Store the resolved concrete policy needed for retry, drift detection, status,
  and deletion; do not store Scheduler-only challenge/profile references.

This boundary deliberately does not protect the cluster from a compromised
Scheduler choosing an excessively large but structurally valid resource value.
A target-level maximum resource envelope can be added separately if that trust
boundary changes. Kubernetes still prevents the created workload from using
more than the submitted limit.

## Defaults and explicit exceptions

For backward compatibility, omitted isolation fields receive safe defaults:

- `outbound_mode`: `NONE`
- `internal_connections`: empty
- `run_as_user`: `10001`
- `writable_paths`: empty

An explicitly supplied `run_as_user: 0` is invalid rather than treated as
omitted. This requires preserving JSON field presence during decoding.
`PUBLIC_INTERNET` remains reserved and rejected by the MVP resolver.

The Provisioner-generated baseline remains:

- dedicated Namespace and ServiceAccount
- disabled ServiceAccount token automount
- non-root execution
- read-only root filesystem
- no privilege escalation or privileged container
- all Linux capabilities dropped
- RuntimeDefault seccomp
- no host namespace or host filesystem access
- default-deny network policy, DNS exception, approved public ingress, and
  explicit internal connection allowlist
- CPU, memory, ephemeral-storage, Pod, Service, and NodePort quotas

## Domain and persistence changes

The wire DTO, domain command, isolation request, resolved policy, operation
equality, and runtime binding no longer carry challenge/profile references.
The resolved policy keeps the concrete baseline, container requirements,
connections, outbound mode, and resource limits.

The operation response remains unchanged. It returns operation state and, on
success, `runtime_workload_id`, the compatibility `service_url`, and all public
`endpoints`. It does not echo Scheduler-owned challenge metadata.

## Validation and errors

- Unknown removed reference fields return `400 INVALID_REQUEST`; this prevents
  callers from believing an ignored profile was applied.
- Malformed topology or resource values return `400 INVALID_REQUEST`.
- A structurally valid concrete exception rejected by the isolation resolver
  returns `422 ISOLATION_POLICY_REJECTED`.
- Duplicate JSON keys remain rejected.
- The same `request_id` with a different concrete runtime specification remains
  an idempotency conflict.

## Migration

The original single-container request needs no new fields and keeps its
submitted numeric `resource_limits`; the current compatibility behavior that
silently replaces them with `SMALL_SINGLE` values is removed.

The stacked isolation PR owns the contract change. The `test_ctf` policy-MVP
PR receives only the smallest downstream adjustment needed to keep its
generated examples compatible:

1. Provisioner request DTO and OpenAPI remove the three reference fields.
2. The resolver always supplies the fixed baseline and retains submitted
   resource totals.
3. `test_ctf` source policy files, schemas, and profile-resolution model remain
   unchanged.
4. Only the final Provisioner-request serializer omits the three
   Scheduler-owned references; its focused snapshot tests and generated
   `deploy/create-*.json` fixtures are updated with it.
5. Provisioner runtime documentation and checked-in examples use the
   simplified payload.

No compatibility period is required for the three reference fields because
they exist only on the unmerged feature branches. The production-compatible
legacy request remains supported.

## Test strategy

- HTTP decoding tests for unchanged legacy single-container requests.
- HTTP decoding tests for simplified multi-container isolation requests.
- Tests proving omitted isolation fields receive safe defaults.
- Tests proving explicit root UID, invalid writable paths, forbidden outbound
  access, and invalid connection edges are rejected.
- Tests proving submitted legacy resource values are retained.
- Resolver tests proving the fixed baseline cannot be weakened.
- Operation idempotency and runtime-binding tests using only the concrete
  policy.
- OpenAPI lint and documentation example checks.
- One focused `test_ctf` serialization test proving profile metadata remains
  in the source policy but not in the generated Provisioner request; regenerate
  only the affected `deploy/create-*.json` fixtures.
- Existing K3s resource, network policy, NodePort, race, vet, and build suites.

## Out of scope

- Returning applied policy metadata in the create result.
- Allowing a caller-selected isolation baseline.
- Enabling `PUBLIC_INTERNET`.
- Adding target-specific maximum resource envelopes.
- Changing team instance-count enforcement, which remains Scheduler-owned.
- Refactoring `test_ctf` policy schemas, profile resolution, or challenge source
  files beyond the final request-serialization compatibility adjustment.
