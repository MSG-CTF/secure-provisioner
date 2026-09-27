#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
renderer="${repository_root}/scripts/write-k3s-isolation-config.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT

config_dir="${fixture_root}/k3s"
mkdir -p "${config_dir}"
printf 'secrets-encryption: true\ntls-san:\n  - example.test\n' > "${config_dir}/config.yaml"
cp "${config_dir}/config.yaml" "${fixture_root}/original.yaml"

bash "${renderer}" "${config_dir}" 256
cmp "${fixture_root}/original.yaml" "${config_dir}/config.yaml"
dropin="${config_dir}/config.yaml.d/50-msgctf-isolation.yaml"
grep -Fxq 'disable-network-policy: false' "${dropin}"
grep -Fxq 'kubelet-arg+:' "${dropin}"
grep -Fxq '  - "pod-max-pids=256"' "${dropin}"

cp "${dropin}" "${fixture_root}/original-dropin.yaml"
bash "${renderer}" "${config_dir}" 256
cmp "${fixture_root}/original-dropin.yaml" "${dropin}"

if bash "${renderer}" "${config_dir}" 0; then
  echo 'zero pod PID limit was accepted' >&2
  exit 1
fi
cmp "${fixture_root}/original-dropin.yaml" "${dropin}"

echo 'K3s isolation config preserves the base file and is idempotent'
