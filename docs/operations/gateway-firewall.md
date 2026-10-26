# Gateway-only NodePort firewall

This is an explicit operator cutover for a fully opted-in K3s node. Merging or
releasing these files does not enable the firewall or turn the fleet Gateway ON.
Keep mixed legacy/direct-NodePort nodes and Gateway OFF targets unprotected by
this range policy until their consumers are drained or migrated.

## Policy and ownership

The example in `deploy/gateway_firewall/` permits source **34.172.6.196/32**, the
approved Gateway IPv4 address. No Gateway IPv6 source is approved, so IPv6 TCP
NodePorts fail closed. A first `raw/PREROUTING` jump matches node-local destinations
(`-m addrtype --dst-type LOCAL`) and TCP **30000:32767**
before Kubernetes destination NAT. `MSGCTF_GWNP4` returns approved source traffic;
its final rule drops other matching traffic. `MSGCTF_GWNP6` drops all matching
traffic. SSH22, HTTPS443, K3sAPI6443, UDP, OUTPUT and unrelated ports/chains retain
their existing policy. Forwarded private Pod/ClusterIP traffic, including TCP31337,
bypasses the guard. LOCAL matches the K3s NodePort dispatcher scope; matching
only a port range would incorrectly drop private workload traffic. This is an
external-ingress guard at PREROUTING.

Install the helper at `/usr/local/sbin/msgctf-gateway-nodeport-firewall.py` and
static config at `/etc/secure-provisioner/gateway-nodeport-firewall.json`.
Config and parents must be root-owned and not group/world writable. The existing
Runtime config directory is a prerequisite: **preserve its owner/group/mode**,
including root:provisioner0750 where configured. Do not run `install -d`, `chmod`,
or `chown` on that existing directory. Do not copy credential contents into this
package. The example source list is public routing policy.

Only global unicast hosts or explicit narrow networks (/28+ IPv4, /124+ IPv6,
at most 16 entries per family) are accepted. The helper rejects broad/private/
special addresses, duplicate/overlapping ranges, unknown config keys, symlink
config files and writable parents. Table, TCP range, binary paths and owned chain
names are fixed. Commands use argv arrays without shell interpolation.

## Stage disabled

Use `deploy/gateway_firewall/install-commands.json` as reviewed, ordered argv
instructions after staging this directory at `/root/msgctf-gateway-nodeport-firewall`.
It installs only the helper, example-derived config and firewall unit, validates
unit syntax and reloads systemd. It does **not** enable/start the firewall or
install either consumer drop-in. Existing destination files require manual
comparison/backups rather than bypassing the absence checks.

The [first OFF binary upgrade](gateway-v1.md#첫-off-업그레이드와-migration-순서)
and schema preparation do not authorize range enforcement. Starting this policy
on a target still registered Gateway OFF would block future legacy NodePorts.

## Activate only during the selected maintenance cutover

Use `activate-commands.json` only after closing new admission, confirming consumer
readiness and the registry target Gateway ON, draining/removing legacy challenge
Pods and live bindings/routes, and proving no direct NodePort consumers remain.
Confirm Gateway source identity, routes, Runtime config and target reachability.
Then stop Runtime, install both consumer drop-ins, validate the actual units,
reload systemd, enable/start and verify the firewall, and start Runtime.

The oneshot orders `After=local-fs.target` and before `network-pre.target`, K3s and
Runtime, without a DNS dependency. Both K3s and Runtime require/order after the
firewall and run root pre-start verification. Thus firewall failure blocks
restoration of existing Kubernetes NodePorts as well as new Runtime admission.
Before ordering alone would not provide this boot failure behavior. Preserve
Runtime `TimeoutStopSec=240` so its 180-second application drain can finish.

Verify Gateway HTTPS, external direct-NodePort timeout, IPv4 RETURN/DROP and IPv6
DROP counters, current helper `verify`, and unit startup/reboot ordering. The
oneshot is not a periodic reconciler: re-verify after other root firewall/K3s
changes. `systemd-analyze verify` checks syntax/dependencies; live boot behavior
and the existing service sandboxes also require operator validation.

## Reapply, failure and rollback

Apply checks both families before mutation. New chains are fully populated and
checked before attachment. Matching repeat apply is a no-op. An existing chain
with unexpected contents, a moved/duplicate jump or a foreign reference fails
without rewriting it; a fully populated detached chain can be reattached after
an interrupted install. Never flush a live attached chain to change policy.
Investigate mismatches while keeping any installed protection intact.

There is no `ExecStop` removal. Service stop, disable, failed authorization,
Runtime failure and failed verification leave existing rules in place. For
rollback follow `rollback-commands.json`: stop Runtime, independently prove all
routes and live bindings are cleaned, remove only these Runtime/K3s dependency
drop-ins, reload systemd, disable/stop the oneshot, then explicitly run:

```sh
/usr/bin/python3 -I /usr/local/sbin/msgctf-gateway-nodeport-firewall.py remove \
  --operator-confirm-routes-clean-and-no-live-bindings
```

The confirmation asserts operator cleanup; it does not query broker/Kubernetes
state. Remove validates both families and deletes only matching owned jumps and
chains. Unexpected rules cause refusal. Never remove protection to work around
authentication or deployment failures while routes/bindings remain.

## Validation

CI discovers the 16 firewall tests with
`python3 -m unittest discover -s deploy -p 'test_*.py' -v`.
The helper, including the LOCAL destination regression fix, passed isolated real-kernel tests
(SHA256 `28dbcf69a9f8b97d8cd0f994b695572149b5443a0163ae31d14833f3f5df4a25`).
That disposable Docker test used network=none and NET_ADMIN only: Gateway source
connected to TCP31854, other IPv4/IPv6 timed out, and ports22/443/6443 and range
boundaries remained reachable. Reapply, tamper refusal, root-config checks,
owned-only removal and systemd unit/drop-in syntax also passed. A three-container
internal Docker bridge regression reproduced the old private TCP31337 timeout,
then confirmed the LOCAL-scoped helper permits forwarding while still denying
node-local TCP31337, with no published ports or host iptables calls. This source
change does not install or activate policy on a server.
