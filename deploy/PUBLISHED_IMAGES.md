# Automatic published images

For an existing Kubernetes execution profile, a successful main publication no
longer needs an operator to copy each new image digest into image-policies.json.
The root-owned publisher service independently checks GitHub's workflow result,
repository, main branch, source SHA, artifact identity, revision and PASS scan.
Only image digests change. Existing FLAG requirements, UID, writable paths,
private/public ports, probes, CPU controls and reviewed network edges are copied.

The backend separately collects the same publication and its revision-bound
participant files and environment. With AUTO_ACTIVATE_PUBLISHED_RELEASES=True
and IMAGE_PREPARATION_ACTIVATE_WHEN_READY=True, it queues preparation and switches
only after all configured targets report fresh readiness. Existing instances are
not replaced. An explicit operator switch/rollback supersedes automatic intent.

The first execution profile, changed ports/profile, ambiguous historical
profiles, explicitly blocked images and VM-required workloads remain fail closed.
These are execution-contract changes, not routine image updates. KOTH retains
its existing publication/environment-agent path.

If a repository has several intentionally different historical operator
profiles, set an optional `profile_templates` object in the root configuration.
Each key is a managed GHCR repository and its value is one existing approved
image in that repository. Select the profile used by the site's current release
once. All future digests copy that profile; historical digests are not rewritten.
An absent, blocked or mismatched template remains fail closed. Update the template
only when the operator intentionally changes the execution profile, not on each
CI publication.

## One-time installation

Install the reviewed release.py at /usr/local/lib/msgctf-deploy/release.py and a
Runtime binary supporting --validate-image-policies. Keep both root-owned and
non-writable by the provisioner/SSH deployment accounts. Install the sync script
at /opt/secure-provisioner-publications/published_image_sync.py (root:root 0755),
and the service/timer in /etc/systemd/system.

Create /etc/secure-provisioner-publications/config.json (root:root 0600):

```json
{
  "repository": "MSG-CTF/2026_MSG_CTF",
  "branch": "main",
  "workflow": ".github/workflows/challenge-validation.yml",
  "token_file": "/etc/secure-provisioner-publications/github-token",
  "policy_file": "/etc/secure-provisioner/image-policies.json",
  "state_file": "/var/lib/secure-provisioner-publications/state.json",
  "max_pages": 10
}
```

Put a read-only Actions credential for that repository in token_file, root:root
0600, through the existing secret channel. Never put its value in a workflow
artifact, command argument, source file or log. Signed artifact-storage redirects
use a fresh request without this credential.

Run `python3 -I /opt/secure-provisioner-publications/published_image_sync.py --plan`
to inspect sanitized decisions, then enable the timer:

```sh
systemctl daemon-reload
systemctl enable --now published-image-sync.timer
systemctl start published-image-sync.service
```

The timer retries every 30 seconds. The durable state records applied artifacts
only after a verified API bridge/worker handoff. A pending policy hash recovers a
crash between writing policy data and completing the handoff. The normal Runtime
deployment lock and policy hash comparison prevent overwriting concurrent work.
No unsigned CI code, manifest YAML or deployment bundle runs as root.

## Operations

Inspect `journalctl -u published-image-sync.service` and the root-only state file
for artifact IDs and error codes. CI failure, missing files/environment, changed
execution profile or readiness failure keeps the prior version active. During a
brief policy-sync lag the backend retries its same durable preparation request;
after 30 minutes it records a terminal failure instead of retrying forever.

To pause automatic imports, stop published-image-sync.timer. To pause backend
activation, set AUTO_ACTIVATE_PUBLISHED_RELEASES=False. Exact digest blocking
continues to take priority over automatic publication. Never delete the policy
catalog or backend publication ledger to retry an operator rollback.
