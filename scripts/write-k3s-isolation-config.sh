#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: write-k3s-isolation-config.sh <config-dir> <pod-max-pids>' >&2
  exit 2
fi

config_dir="$1"
pod_max_pids="$2"
if [[ ! "${pod_max_pids}" =~ ^[1-9][0-9]*$ ]]; then
  echo 'pod-max-pids must be a positive decimal integer' >&2
  exit 2
fi

dropin_dir="${config_dir}/config.yaml.d"
dropin="${dropin_dir}/50-msgctf-isolation.yaml"
install -d -m 0755 -- "${dropin_dir}"
temporary="$(mktemp "${dropin_dir}/.50-msgctf-isolation.XXXXXXXX")"
trap 'rm -f -- "${temporary}"' EXIT

cat > "${temporary}" <<EOF
disable-network-policy: false
kubelet-arg+:
  - "pod-max-pids=${pod_max_pids}"
EOF
chmod 0600 "${temporary}"
mv -f -- "${temporary}" "${dropin}"
trap - EXIT
