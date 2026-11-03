# Dedicated VM runtime

The VM adapter runs a pinned multi-container release on an **operator-prepared, exclusive VM**. The scheduler's existing VM target and reservation flow is used. This change does not provision cloud VMs on demand. Kubernetes targets continue through the existing adapter.

For Afterimage's per-role privileges, repository admission guard, K3s diagnostic
evidence and rollout/rollback requirements, see
[Afterimage execution policy](afterimage-execution-policy.md).

## Register a target

1. Prepare one VM per concurrently runnable instance. Install Docker with `overlay2` on XFS with `pquota`; mount the Docker data root before Docker starts. Create a systemd slice that enforces the aggregate CPU and memory limit. Prefetch the seven approved image digests. The guest must not hold registry credentials.
2. Put `deploy/vm/agent.py` at `/usr/local/libexec/msgctf-vm-agent`, root-owned and executable. Put the exact SHA-256-named profile in `/etc/msgctf-vm/profiles/`, root-owned and not group/world writable. The agent verifies its file hash and refuses image pulls, builds, mounts, privileged mode, host networking and arbitrary commands.
3. Install `deploy/vm/network-guard.sh` as Docker's `ExecStartPre`. Block container access to host/control and cloud metadata addresses, and block external DNS/egress at the VM firewall. Keep the source Compose bridge groups: `edge`, `appnet`, `exportnet`, `cartridgenet`, `vaultnet`. Permit only the intended participant port at ingress. For the QA target this was port 18080; use stable HTTPS and a stable address before participant rollout.
4. Create separate SSH keys for runtime mutations and broker observations. Pin the host key. The guest SSH authorized keys must force the helper command with forwarding and TTY disabled; the broker key must force `--observe-only`. Restrict `sudo` to that helper. Allow SSH ingress only from the controllers.
5. Copy `deploy/vm/targets.example.json` to a protected local file, replace the address placeholders, and set `PROVISIONER_VM_TARGETS` to its path. Keep the existing Kubernetes registry and backend secret resolver configuration. The target's profile hash, image digests, ports, complete environment key set, secret key set and resource limits must match the accepted backend release exactly.

The runtime resolves backend secret references immediately before creation and sends values only to the pinned guest over SSH stdin. The guest writes the temporary Compose configuration under `/run/msgctf-vm`, a tmpfs. It stores only identity and profile metadata for retry/delete, never secret values. The submitted `run_as_user` and `/tmp` hint are accepted for compatibility with the existing scheduler; the trusted guest profile determines container privileges and writable paths.

Do not remove a target from the runtime catalog while it has a create, delete, or cleanup operation. Withdraw it from broker placement first, wait for reservations and bindings to finish, then remove the catalog entry. A queued VM create with a missing catalog entry remains cleanup-pending; it cannot fall through to Kubernetes or release its reservation as if deletion were proven.

Temporary Docker or helper failures are retryable within the existing worker attempt limit. Each retry carries the same instance, team, target and owner generation. Policy and ownership rejections remain terminal errors.

## Verified flow

On 2026-10-20, a private Afterimage revision 578 deployment test traversed the deployed backend, scheduler, broker, runtime and dedicated VM. Seven digest-pinned containers became ready. All 42 configured variables matched the backend release in Docker and process environments; `FLAG` appeared only in `case-vault`. The original, unchanged solver completed 88/88 and returned the injected test flag. External HTTP returned 200 from the permitted QA source; the six private ports and cloud metadata/control addresses were unreachable. A runtime restart kept the same seven container IDs and one successful create operation. Admin deletion left no instance containers, networks, volumes or temporary configuration. The broker recorded one reservation release and then offered the VM again. QA ingress was source-IP restricted; broad participant access and VM auto-creation were not tested.
