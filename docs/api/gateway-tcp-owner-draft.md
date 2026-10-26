# Gateway TCP owner extension — draft, disabled by default

This is a proposed contract for local verification, not the deployed Gateway API.
The deployed `/v1/routes/{instance_id}` currently rejects additional request fields.
Do not enable this extension against it until the Gateway administrator approves
and implements this contract and verifies the data-plane owner restrictions.

## Opt-in and lifecycle

`PROVISIONER_GATEWAY_TCP_TRANSPORT` defaults to `legacy`. `tls` and `plain` opt
new TCP intents into this draft. HTTP keeps the existing request contract.
An opt-in requires a Gateway token file. Configuration selects only new intents:
retries, restarts, and cleanup use the immutable saved request, including owner
and transport, even after configuration changes. Existing legacy intents remain
legacy. Disabling the option does not rewrite or discard live draft intents.
Do not roll back to a Runtime binary that cannot preserve these fields while
draft intents remain live. Gateway must also reject attempts to reuse an
existing draft instance ID with omitted or changed owner/transport fields.

## Proposed PUT request and response

The management connection remains authenticated HTTPS. Same path, method,
instance-ID idempotency, upstream validation and DELETE204 cleanup proof as v1.
No participant-supplied public port is accepted; Gateway allocates it globally.

```json
{
  "target_ip": "8.8.8.8",
  "target_port": 31042,
  "protocol": "tcp",
  "public_transport": "plain",
  "owner_team_id": "00000000-0000-4000-8000-000000000002"
}
```

The example address is synthetic test input, not a deployment destination.
The owner is the trusted Scheduler's canonical, nonzero team UUID. Supplying
`owner_team_id` requests an owner-only route; it is not an optional display label.
An accepted response must echo `public_transport` and `owner_team_id`, with
`owner_access_enforced: true`. `tls` must agree with the requested transport.
All standard v1 response fields remain required; TCP `url` remains null.
Only PUT 200/201 with a complete acknowledgement confirms the route. Unexpected
successful statuses such as 202/204 also enter contract-unconfirmed hold.

```json
{
  "instance_id": "example-instance",
  "hostname": "random-instance.gate.msgctf.kr",
  "port": 42817,
  "tls": false,
  "protocol": "tcp",
  "url": null,
  "created_at": "2026-10-27T00:00:00Z",
  "public_transport": "plain",
  "owner_team_id": "00000000-0000-4000-8000-000000000002",
  "owner_access_enforced": true
}
```

Gateway may acknowledge owner enforcement only after its selected authentication
mechanism actually restricts the data path to the owning team's authenticated
participants. Ordinary public nc and random hostnames/ports do not provide this.
This Runtime change validates the acknowledgement; it does not implement or
independently prove VPN, mTLS, or network access control.
Malformed or mismatched successful draft responses become
`GATEWAY_CONTRACT_UNCONFIRMED`: Runtime stops the workload and keeps its backend
port in conflict hold. It does not blindly delete a possibly foreign route.
Cleanup requires another identical PUT with a valid acknowledgement before
DELETE204. Ordinary network-response loss retains the saved held replay; the
Gateway contract must atomically enforce ownership before exposing any listener.

## Proposed errors

Error bodies retain `{"error":{"code":"..."}}`; messages are not logged or
forwarded. The following classification applies only to the draft intent.

| Code | HTTP status | Runtime behavior |
|---|---|---|
| PORT_POOL_EXHAUSTED | 503 | Hold and retry the same intent; keep its backend allocation |
| PORT_ALLOCATION_CONFLICT | 409 | Hold and retry; this means public allocator contention, not a foreign upstream claim |
| OWNER_CONFLICT | 409 | Conflict hold and stop the workload; never delete a foreign owner's route |
| OWNER_ACCESS_NOT_CONFIGURED | 503 | Hold; never publish an unprotected fallback route |
| TRANSPORT_NOT_SUPPORTED | 422 | Fail after confirmed route/workload cleanup |
| ROUTE_CLEANUP_PENDING | 409/503 | Hold cleanup and preserve the backend allocation until DELETE204 |

Gateway must implement atomic port reservation, persisted idempotency, listener
recovery, owner enforcement, and connection termination before recycling ports.
Local synthetic API responses cannot prove those server guarantees. Before any
rollout, verify real nc/TLS connectivity, owner denial, concurrency, restart,
cleanup failure, and old v1 routes on a dedicated test Gateway.
