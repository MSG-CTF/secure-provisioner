#!/usr/bin/env bash
set -euo pipefail

if ! systemctl is-active --quiet k3s; then
  echo 'K3s service is not active; recover the cluster before bootstrap.' >&2
  exit 1
fi

if ! k3s kubectl get secrets -n kube-system --request-timeout=10s -o name >/dev/null 2>&1; then
  echo 'K3s Secret API is unavailable; recover the cluster before bootstrap.' >&2
  exit 1
fi

echo 'K3s bootstrap preflight passed.'
