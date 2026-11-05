# K3s preloaded challenge images

The user selected keeping K3s and running challenge images already stored on the
execution VMs. Existing image preparation, digest admission, isolation, ownership,
create/delete and status paths remain the foundation.

The selected first execution VM is heavy-01 at `34.135.180.218`, in project
`msg-602221513-2`: Runtime target `3243bc60-2285-4553-a20e-032abe567f69`, Broker
resource `9b0c5dd5-0881-40be-9e89-643c0bc88bbb`. The user specified 17 dynamic
challenges, explicitly excluding web-notebook, which still exists in GitHub main.
Resolve their current approved image sets before bulk preparation or a whole-set
execution test. A single exact approved cached-image canary may verify the local
startup mechanism first; do not substitute the other same-named heavy-01.

## Approach

Keep K3s and its containerd image store (`k8s.io`). Reuse the trusted image agents
and preparation observations instead of adding a registry, importer service or
Docker execution path. Replacing K3s with Docker/Compose was considered; the user
selected the K3s route to retain the current isolation and lifecycle.

## Runtime behavior

- New challenge containers use `imagePullPolicy: Never`. The approved immutable
  image reference stays unchanged; a `ghcr.io/...@sha256:...` name is an identity,
  not permission to download during instance creation.
- Before creating a Namespace, require fresh, policy-matching preparation
  evidence for every container on at least one current eligible node. Match its
  Node UID, boot ID, machine ID, architecture and name against live inventory.
- Restrict all Deployments to those nodes with required node affinity, retaining
  existing platform selectors and any other required affinity.
- Missing, expired or unavailable evidence, disabled preparation, and no matching
  node return retryable `IMAGE_NOT_READY`; they do not create workload resources
  or fall back to a registry.
- A cache removed after the check cannot trigger a download: Kubernetes `Never`
  fails startup and the existing failure/cleanup path handles the attempt.
- Running instances are not migrated or restarted by this change. Existing status
  and delete remain usable. Old queued creates use the same local-image checks.

## Preparation and rollout

Import/preload images on each actual Linux challenge VM, not the controller or
an unrelated Docker store. Use the existing trusted preparation pipeline to
verify exact approved references and complete image content before enabling new
creates. Preparation may obtain missing images ahead of time; instance creation
never does. New/replaced nodes need their own trusted enrollment and observations.

Roll out the agents, image content and valid observations first, then the Runtime
change. Missing preparation intentionally blocks new K3s creates. Preserve cached
rollback versions and account for containerd garbage collection and disk space.
Windows EXE and the dedicated Compose VM adapter are outside this change.

## Acceptance

Tests cover local-only Pod rendering, missing/expired/partial evidence without
resource writes, node identity replacement, required placement with existing
selectors, rejected pull-policy tampering, and existing instance status/delete.
Live offline creation is a separate canary after execution-node readiness is
verified; no production images, Pods or registry configuration are changed by
implementing the feature.
