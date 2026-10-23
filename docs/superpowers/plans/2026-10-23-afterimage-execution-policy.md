# Afterimage execution policy binding

## Design

Reuse the existing digest-pinned dedicated VM profile. Its isolated Docker VM
preserves the original bridge groups, the indexer's root parent / UID 1001 child
with only SETUID/SETGID, and the bot's writable image filesystem. Do not add
capabilities or root exceptions to STANDARD@v2 / PSA restricted K3s workloads.

Reserve image repositories for VM execution in the operator image catalog and
derive the same restriction from configured VM targets. Enforce it at HTTP
admission and at the K3s worker before resource creation, including old queued
commands and future digests. Exact VM digest/profile admission remains unchanged.
Keep the restriction when a VM target is withdrawn by retaining its repositories
in the operator catalog. Preserve the bytes of SHA-named guest profiles across
Windows/Linux checkouts.

## Implementation and verification

1. Add failing admission, queued-command, repository-boundary and profile-byte
   tests; preserve the existing exact VM admission tests.
2. Implement optional `vm_required_repositories` and the VM-derived worker guard.
   Keep ownership-aware cleanup of interrupted creates ahead of policy rejection.
3. Register the seven Afterimage repositories, preserve hash-pinned JSON bytes,
   and document per-role execution settings, evidence and activation/rollback.
4. Run targeted tests, all Go tests, vet and deployment Python tests. Request an
   independent review, address findings, and open a separate PR against dev.

## Limits

No production deployment or policy reload in this PR task. The 2026-10-23 K3s
network experiment is not a fresh dedicated-VM solver/E2E test. PID limits on the
lab K3s node and PR #49's optional network graph are separate work.
