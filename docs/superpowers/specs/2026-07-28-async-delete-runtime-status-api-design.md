# Async Delete and Runtime Status API Design

## Status

- Date: 2026-07-28
- Repository: `MSG-CTF/secure-provisioner`
- Related issues: #16, #25
- Related runtime work: #17, #18, #24

## Purpose

Secure Provisioner will expose an asynchronous, idempotent deletion API and an
Operation polling API. It will also expose a separate runtime status API that
reports the real state of an instance's containers and the scheduling capacity
of the single-node K3s target selected by `target_id`.

The implementation is local to Secure Provisioner. The Instance Scheduler
repository is a contract reference only and must not be modified.

## Decisions

1. The existing create API remains synchronous in this scope. Converting create
   to an asynchronous API requires a separate Scheduler contract decision.
2. Delete requests are asynchronous. A successful submission returns HTTP 202
   and an Operation identifier.
3. Operation waiting uses `QUEUED`. `WAITING` remains a container state and is
   not used as an Operation state.
4. Delete request JSON follows the existing Scheduler DTO, including
   `delete_reason`.
5. The final successful delete Operation result preserves the Scheduler's
   existing semantic result: `runtime_workload_id` and `status: SUCCESS`.
6. Runtime status is looked up by `instance_id`. The stored Binding determines
   `target_id`; callers cannot redirect a lookup to another target.
7. A target represents one VM running one single-node K3s cluster.
8. Scheduling space is calculated from Kubernetes `allocatable - requested`.
   Instantaneous CPU and memory usage are observational data, not the placement
   authority.
9. AWS EC2/CloudWatch and GCP Compute/Monitoring data are phase-two work and are
   excluded.
10. The local dashboard remains local-only and is not part of the publishable
    API implementation.

## Scope

### Included

- Scheduler-compatible delete request decoding and validation
- Asynchronous delete submission
- Idempotency by `request_id`
- Operation polling and terminal result payloads
- Exact `target_id` routing through the Cluster Registry
- Binding and Kubernetes ownership validation
- Foreground Namespace deletion
- Already-absent Namespace success
- Retry classification and bounded retries
- Container lifecycle, requests, limits, and Metrics API usage
- Single-node K3s health, capacity, allocatable, requested, schedulable, and
  Metrics API usage
- OpenAPI 3.1 contract and Markdown request/response examples
- Fake Kubernetes and Metrics Client tests
- Local HTTP polling test

### Excluded

- Changes to `MSG-CTF/instance-scheduler`
- Asynchronous create API
- Scheduler DB state changes or polling worker
- Operation and Binding database persistence
- TTL detection
- AWS/GCP VM creation or deletion
- Cloud-provider power, network, and disk I/O monitoring
- Multi-node K3s targets
- Target selection or scheduling policy
- Publishing or deploying the local dashboard

## Architecture

### Runtime Binding

`InstanceRuntimeBinding` is the authority for workload placement:

```text
instance_id
  -> team_id
  -> target_id
  -> namespace
  -> runtime_workload_id
  -> lifecycle state
```

Delete and status requests load this Binding once and resolve exactly one
Cluster Registry entry. Neither path scans other AWS, GCP, or NCP targets.

The in-memory Binding Store remains an adapter behind an interface. Production
persistence is explicitly deferred, so process restart recovery is not claimed
by this implementation.

### Asynchronous Delete

The delete HTTP handler validates the path and Scheduler-compatible request,
then calls `RuntimeService.EnqueueDelete`.

The service:

1. loads the Binding by `instance_id`;
2. compares instance, team, target, runtime type, and workload identifiers;
3. marks the Binding `DELETING`;
4. enqueues an idempotent DELETE Operation;
5. returns the Operation without waiting for K3s.

If enqueue fails after a newly created Binding transition, the transition is
restored so a request-id conflict or store error does not strand the Binding in
`DELETING`. A repeated identical request keeps the existing transition and
returns the same Operation.

The Worker:

1. loads the Binding;
2. resolves its exact `target_id` with maintenance lookup;
3. verifies Namespace ownership labels;
4. requests Foreground Namespace deletion;
5. waits for Namespace `NotFound` within the bounded adapter timeout;
6. treats an already absent Namespace as success;
7. records a Scheduler-compatible delete result;
8. marks the Binding `DELETED`.

### Operation Store

The Operation Store owns the following state machine:

```text
QUEUED -> RUNNING -> SUCCEEDED
                  -> RETRYING -> QUEUED
                  -> FAILED
```

`request_id` is the idempotency key:

- same `request_id` and same command: return the existing Operation;
- same `request_id` and a different command: return `REQUEST_ID_CONFLICT`;
- an existing terminal Operation is returned unchanged.

The local implementation uses the current in-memory Store. The API and Store
interfaces must not imply restart durability.

### Runtime Status Reader

The status service loads the Binding, resolves one target, verifies Namespace
ownership, and reads:

- instance Pods and container statuses from the Kubernetes Core API;
- Pod CPU and memory usage from the Metrics API;
- the target's single Node and Node conditions from the Core API;
- Node CPU and memory usage from the Metrics API;
- all non-terminal Pods assigned to that Node to calculate requested resources.

Exactly one Node must be present. Zero or multiple Nodes return
`TARGET_TOPOLOGY_INVALID`, because this design treats a target as a single VM.

Pod requested resources use Kubernetes scheduling semantics: regular container
requests are summed, init-container maxima and Pod overhead are included, and
terminal Pods are excluded. Schedulable values are clamped at zero:

```text
schedulable = max(allocatable - requested, 0)
```

CPU is represented in millicores. Memory and ephemeral storage are represented
in MiB.

Metrics failures are degraded observations, not total status failures. Core API
status, capacity, allocatable, requested, and conditions remain available;
usage fields become `null` and metrics availability becomes false.

## HTTP API

### Submit Delete

```http
DELETE /internal/v1/instances/{instance_id}
Content-Type: application/json
```

```json
{
  "request_id": "runtime-delete-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": 18,
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
  "delete_reason": "USER_REQUESTED"
}
```

Response:

```http
HTTP/1.1 202 Accepted
Location: /internal/v1/operations/op-123
Retry-After: 2
```

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "QUEUED",
  "attempt": 0,
  "max_attempts": 3,
  "created": true
}
```

For an identical repeated request, `created` is false and the current existing
Operation state is returned.

### Poll Operation

```http
GET /internal/v1/operations/{operation_id}
```

Non-terminal response:

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "RUNNING",
  "attempt": 1,
  "max_attempts": 3
}
```

When the state is `QUEUED`, `RUNNING`, or `RETRYING`, the response includes a
`Retry-After` header.

Successful delete response:

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "SUCCEEDED",
  "attempt": 1,
  "max_attempts": 3,
  "result": {
    "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
    "status": "SUCCESS"
  }
}
```

Terminal failure response:

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "FAILED",
  "attempt": 3,
  "max_attempts": 3,
  "last_error_code": "TARGET_TEMPORARILY_UNAVAILABLE"
}
```

### Get Runtime Status

```http
GET /internal/v1/instances/{instance_id}/runtime-status
```

The response has this shape:

```json
{
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "target_id": "aws-k3s-001",
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
  "phase": "READY",
  "endpoint_ready": true,
  "metrics_available": true,
  "observed_at": "2026-07-28T14:00:00Z",
  "node": {
    "ready": true,
    "memory_pressure": false,
    "disk_pressure": false,
    "pid_pressure": false,
    "capacity": {
      "cpu_millicores": 2000,
      "memory_mib": 4096,
      "ephemeral_storage_mib": 20480
    },
    "allocatable": {
      "cpu_millicores": 1800,
      "memory_mib": 3584,
      "ephemeral_storage_mib": 18432
    },
    "requested": {
      "cpu_millicores": 900,
      "memory_mib": 1536,
      "ephemeral_storage_mib": 4096
    },
    "schedulable": {
      "cpu_millicores": 900,
      "memory_mib": 2048,
      "ephemeral_storage_mib": 14336
    },
    "usage": {
      "cpu_millicores": 640,
      "memory_mib": 1720
    }
  },
  "containers": [
    {
      "pod_name": "challenge-7b8f64cd8f-kw2gz",
      "name": "challenge",
      "state": "RUNNING",
      "ready": true,
      "restart_count": 0,
      "requests": {
        "cpu_millicores": 100,
        "memory_mib": 128,
        "ephemeral_storage_mib": 256
      },
      "limits": {
        "cpu_millicores": 500,
        "memory_mib": 512,
        "ephemeral_storage_mib": 1024
      },
      "usage": {
        "cpu_millicores": 86,
        "memory_mib": 146
      }
    }
  ]
}
```

## Error Contract

API errors use the existing stable envelope:

```json
{
  "error": {
    "code": "INSTANCE_BINDING_MISMATCH",
    "message": "request does not match the stored runtime binding"
  }
}
```

Required stable cases:

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | Invalid JSON, UUID, enum, or required field |
| 404 | `INSTANCE_NOT_FOUND` | No Binding for the instance |
| 404 | `OPERATION_NOT_FOUND` | Unknown Operation |
| 409 | `INSTANCE_BINDING_MISMATCH` | Request identifiers differ from Binding |
| 409 | `REQUEST_ID_CONFLICT` | Idempotency key reused for another command |
| 409 | `INSTANCE_STATE_CONFLICT` | Delete is invalid for the Binding state |
| 409 | `RUNTIME_OWNERSHIP_MISMATCH` | Kubernetes ownership labels do not match |
| 502 | `RUNTIME_STATUS_FAILED` | Target status could not be read |
| 503 | `TARGET_NOT_FOUND` | Registry has no target |
| 503 | `TARGET_TOPOLOGY_INVALID` | Target is not a single-node K3s |

Kubeconfig contents, Kubernetes API addresses, credentials, container
environment variables, and underlying client errors are never returned.

## Concurrency and Failure Handling

- Delete uses the existing `(target_id, instance_id)` workload lock.
- Create and delete for the same workload cannot mutate Kubernetes resources at
  the same time.
- Foreground Namespace deletion has a bounded timeout and poll interval.
- Only classified transient errors are retryable.
- A client disconnect does not change Operation ownership or create a second
  Operation.
- A duplicate request observes the existing Operation.
- Ownership mismatch is terminal and never retried.
- Metrics errors do not trigger delete or lifecycle changes.

The memory Store cannot provide crash recovery. The API documentation must call
this out as a local implementation limitation rather than promising durable
Operations.

## Testing

### Delete

- valid request returns 202, Location, Retry-After, and `QUEUED`;
- duplicate identical request returns the same Operation;
- duplicate conflicting request returns 409;
- path/body instance mismatch returns 409;
- worker moves through RUNNING to SUCCEEDED;
- retryable error exposes RETRYING and later succeeds;
- terminal error exposes FAILED and stable code;
- missing Namespace succeeds;
- ownership mismatch does not issue delete;
- successful result contains Scheduler-compatible fields.

### Runtime Status

- correct Binding routes to only its target Client;
- container lifecycle and usage are mapped correctly;
- one Node returns conditions and resources;
- requested resources include all non-terminal Pods on that Node;
- schedulable resources never become negative;
- missing Metrics API produces core status with null usage;
- zero or multiple Nodes return `TARGET_TOPOLOGY_INVALID`;
- Namespace ownership mismatch is rejected.

### Verification

```text
go test -count=1 ./...
go vet ./...
go build ./...
git diff --check
```

The local HTTP test starts the Provisioner-compatible demo service on loopback,
submits a delete, polls until `SUCCEEDED`, and confirms runtime status output
before deletion. It does not publish the dashboard or use real credentials.

## Documentation Deliverables

- `docs/api/runtime-operations.md`
- `docs/api/secure-provisioner.openapi.yaml`

Both documents cover the asynchronous delete, Operation polling, runtime status
response, stable errors, idempotency, and the local in-memory durability
limitation.
