# Public TCP ports for ordinary nc

The user chose public nc connectivity without team authentication for this iteration.
Use endpoint protocol, not challenge category: every new TCP instance may receive
an independently allocated Gateway port; HTTP keeps its existing HTTPS URL.
Random hostnames and ports are not access control. Keep VM NodePorts restricted to
Gateway traffic. Keep management API Bearer authentication and HTTPS unchanged.

Import the exact Python Gateway source inspected on the authorized Gateway into
`deploy/gateway/`, documenting its SHA256 provenance without credentials or live
route data. Extend its existing locked, durable registry and NGINX stream proxy.
This reuses the running design and avoids adding another proxy service. A separate
TCP proxy would simplify per-connection shutdown but adds a daemon and control
protocol; exposing VM NodePorts directly bypasses the current Gateway boundary.

The three-field PUT request remains unchanged. Optional Gateway configuration
`tcp_public_ports: {"start": 40000, "end": 49999}` enables plaintext ports for NEW
TCP routes only. An absent pool preserves v1 behavior. Existing TLS TCP routes,
HTTP routes, hostnames, timestamps and idempotent PUTs retain their original data.
Responses use the allocated `port` and explicit `tls: false`; Runtime's existing
default/legacy consumer produces `tcp://...`, and the committed UI displays nc.
Do not enable the older owner-enforcement draft or falsely acknowledge ownership.

The pool is dedicated to Gateway listeners, must be reserved from OS ephemeral
allocation and opened in cloud/host firewalls before activation. Allocation under
the registry lock skips occupied ports and returns retryable pool exhaustion.
Persist assigned ports and reject duplicate/invalid ports on registry readback.
Confirm listener changes after NGINX reload. Before deleting/recycling a plaintext
port, remove its listener, terminate its accepted TCP sockets, and confirm they are
gone; uncertainty fails cleanup and preserves rollback/journal ownership.
No global NGINX worker termination or web-connection disruption is permitted.

Scope ends at tested code and commits pushed to the existing feature branch.
No PR, merge, production configuration change, deployment or live route mutation.

Verify the real API schema, allocator/replay/restart/concurrency, rollback and
cleanup failure behavior. Use an isolated local NGINX and echo backend for actual
nc traffic, safe port reuse and unchanged HTTP/TLS behavior. No production tokens.
