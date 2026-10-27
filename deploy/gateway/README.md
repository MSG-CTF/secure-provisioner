# Gateway public TCP deployment bundle

This bundle extends the Python Gateway source inspected on 2026-10-27. Its
baseline source hashes are in `baseline-provenance.json`. It contains no live
routes, runtime tokens, certificates or VM credentials. The initial change is
code-only: it has not been deployed or enabled on the production Gateway.

## Public contract

Select by endpoint protocol, regardless of challenge category. `http` keeps
HTTPS/443. With the optional pool enabled, **new** `tcp` routes receive a random
available public port and `tls: false`. Existing TLS TCP routes retain their
original hostname, port, TLS setting and creation time. Without a pool the old
TLS/443 behavior remains the default.

Authenticated management PUT requests keep exactly the existing three fields:

```json
{"target_ip":"REPLACE_WITH_PROBLEM_VM_PUBLIC_IP","target_port":31042,"protocol":"tcp"}
```

`target_port` is the actual Service NodePort read by the trusted Runtime. The
Gateway allocates a separate globally unique public port. Response example:

```json
{
  "instance_id":"example-instance",
  "hostname":"0123456789abcdef0123456789abcdef.gate.msgctf.kr",
  "port":42817,
  "tls":false,
  "protocol":"tcp",
  "url":null,
  "created_at":"2026-10-27T00:00:00Z"
}
```

Runtime's existing dynamic-port consumer converts this into
`tcp://hostname:42817`, `connection_port: 42817`, `tls: false`, without SNI.
The corresponding frontend commit displays/copies `nc hostname 42817`.
Keep `PROVISIONER_GATEWAY_TCP_TRANSPORT` unset or `legacy`: **do not enable the
older owner-enforcement draft** for this public mode. No new request field is
required. Gateway and consumer/frontend commits must all be deployed before
claiming end-to-end participant support.

These are public problem connections. Knowing the address/port permits access;
random hostnames/ports do not authenticate a team. Management remains Bearer-
authenticated HTTPS. Problem VMs must continue allowing NodePort ingress from
the Gateway only. No PROXY header or authentication prefix is inserted into
problem data; TCP half-close preserves replies after client input EOF.

## Lifecycle guarantees

Each route now uses two upstream peers with the **same approved IP and port**.
An upstream connection that never establishes gets a fresh socket after a
2-second connect timeout, with at most two attempts and a 4-second retry budget.
NGINX does not retry after a connection establishes, so application commands are
not replayed. Route metadata, TLS transport and public addresses stay unchanged.
The optional plaintext TCP pool is not enabled by this change.

The controller accepts both the previous canonical registry and the new
canonical registry. A normal successful mutation rewrites the current routes in
the new format. For rollback, stop management mutations, read the **current**
registry with this compatible controller, render it with `render_legacy`, validate
and reload NGINX, and only then restore the previous controller. Never restore a
stale registry snapshot over newer routes or tombstones.

- One host-wide nonblocking registry lock protects allocation and mutation;
  contention returns `GATEWAY_BUSY` 503 for retry with the same ID/body.
- Persisted route metadata includes `public_port`. Replay, restart and changed
  pool configuration preserve existing assignments; deleted IDs remain tombstoned.
- Allocation skips registered ports and occupied IPv4/IPv6 host ports. Exhaustion
  returns `PORT_POOL_EXHAUSTED` 503 without mutating the registry.
- The full configured pool must be reserved in Linux `ip_local_reserved_ports`.
  Reject unreserved pools rather than sharing source ports with outgoing traffic.
- NGINX reload is followed by actual listener checks. Success is not inferred
  merely from `systemctl reload` exiting zero.
- Deletion removes both listeners, destroys accepted connections using Linux
  `ss -K` for the dedicated port, and verifies absence before releasing ownership.
  Web/443 workers and unrelated connections are never globally terminated.
- Failed listener/socket cleanup returns `ROUTE_CLEANUP_PENDING` 503 and restores
  the previous registry/listeners. Failed recovery keeps the journal and returns
  `NGINX_RECOVERY_REQUIRED` 503; do not release/reuse the backend or public port.

## Deployment prerequisites and activation

Operator procedure for a later approved deployment; these steps are **not**
executed by the implementation commit:

1. Back up the existing root-owned source and configuration in a private operator
   backup. Keep the live registry/journal authoritative; never commit them.
2. Require Python 3.12+, NGINX 1.25.5+ with stream/SSL modules, `/usr/bin/ss`,
   Linux `CONFIG_INET_DIAG_DESTROY=y` and `CAP_NET_ADMIN` available to the root
   controller even when invoked from the systemd service. A root interactive
   shell's capabilities alone do not establish the service's bounding set.
3. Install `gateway/*.py` as root-owned files under
   `/opt/msgctf-gateway/gateway/`, preserving the existing service account,
   sudoers restriction, venv, token environment and NGINX configuration.
   The restricted controller invocation remains
   `/usr/bin/python3 -I /opt/msgctf-gateway/gateway/controller.py` through sudo.
   Do not permit the API service user to edit its privileged controller/source.
4. Reserve a dedicated range of at most 10,000 ports. Merge it into the existing
   `/proc/sys/net/ipv4/ip_local_reserved_ports` setting and persist it with sysctl;
   preserve all existing reservations. Keep old ranges reserved while their
   routes remain live, even after changing the allocation pool. No other service
   may explicitly bind or use these dedicated source/listener ports.
5. Allow this TCP range in the cloud and host firewalls for this Gateway only.
   Keep Gateway-only problem VM NodePort ingress. Keep wildcard DNS pointing
   at the Gateway; plain TCP routes by destination port, not hostname.
6. Add `tcp_public_ports` to `/etc/msgctf-gateway/config.json` using
   `config.example.json` as a template. The IP placeholder must be replaced;
   the existing public-IP/domain validation remains enforced.
7. Validate NGINX configuration, restart the existing `msgctf-gateway` API and
   check readiness. Create a dedicated TCP canary through Runtime, verify the
   API's actual port, external nc behavior, frontend display and deletion. Check
   existing web/TLS routes. No existing route is automatically migrated.

Removing the pool stops allocating new plaintext routes; existing ones continue
using their saved ports. Do not roll back to the old controller while any
`public_port` records or pending journals exist: it cannot parse the new format.
Keep the compatible binary or finish cleanup first. Do not restore an old route
registry over current routes/tombstones as a generic rollback.

## Tests

From this directory in a disposable environment:

```sh
python3 -m venv /tmp/gateway-test-venv
/tmp/gateway-test-venv/bin/pip install -r requirements-test.txt
/tmp/gateway-test-venv/bin/python -m unittest discover -s tests -v
```

The default suite skips the explicit root/NGINX integration test. Run it in an
isolated Linux network namespace with loopback enabled, using root and
`GATEWAY_TEST_NGINX=/usr/sbin/nginx`. It binds TLS/443 and starts its own NGINX
prefix and echo/web backends; **never run it in the production network namespace**.
No production environment/token/configuration is used. An older local WSL kernel
without `CONFIG_INET_DIAG_DESTROY` can run unit/API tests but cannot validate
successful active-socket destruction; cleanup must fail safely on that kernel.

The transient-connect fault test additionally requires `GATEWAY_TEST_IPTABLES`
pointing to iptables. It drops every SYN on the first owned upstream socket in
the isolated namespace, then permits only different source ports. This avoids
depending on a particular kernel SYN retransmission schedule or on unconfirmed
conntrack marks. The legacy renderer must fail after five seconds, while the new
renderer must recover through a fresh socket to the same endpoint. Additional
tests require exactly two attempts on connection refusal and no command replay
after an established connection resets. These tests model a connection failure;
they do not establish the historical cause of packet loss on a live network.
