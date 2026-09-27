#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
writer="${repository_root}/scripts/ensure-gvisor-containerd-template.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
config_dir="${fixture_root}/containerd"
mkdir -p "${config_dir}"
template="${config_dir}/config-v3.toml.tmpl"
printf 'version = 3\n' > "${config_dir}/config.toml"

printf '{{ template "base" . }}\n# retained custom setting\n' > "${template}"
bash "${writer}" "${config_dir}"
grep -Fxq '# retained custom setting' "${template}"
grep -Fq "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]" "${template}"
grep -Fxq '  runtime_type = "io.containerd.runsc.v1"' "${template}"
cp "${template}" "${fixture_root}/expected"
bash "${writer}" "${config_dir}"
cmp "${fixture_root}/expected" "${template}"

printf "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]\n  runtime_type = \"wrong\"\n" > "${template}"
cp "${template}" "${fixture_root}/conflicting"
if bash "${writer}" "${config_dir}"; then
  echo 'conflicting runsc handler was accepted' >&2
  exit 1
fi
cmp "${fixture_root}/conflicting" "${template}"

printf "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]\n  runtime_type = \"wrong\"\n[plugins.'another.runtime']\n  runtime_type = \"io.containerd.runsc.v1\"\n" > "${template}"
cp "${template}" "${fixture_root}/adjacent-section"
if bash "${writer}" "${config_dir}"; then
  echo 'runtime type from an adjacent section was accepted' >&2
  exit 1
fi
cmp "${fixture_root}/adjacent-section" "${template}"

rm -f "${template}"
printf 'version = 2\n' > "${config_dir}/config.toml"
legacy_template="${config_dir}/config.toml.tmpl"
printf '{{ template "base" . }}\n# retained legacy setting\n' > "${legacy_template}"
bash "${writer}" "${config_dir}"
grep -Fxq '# retained legacy setting' "${legacy_template}"
grep -Fqx '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]' "${legacy_template}"
grep -Fxq '  runtime_type = "io.containerd.runsc.v1"' "${legacy_template}"
[[ ! -e "${template}" ]]
cp "${legacy_template}" "${fixture_root}/expected-legacy"
bash "${writer}" "${config_dir}"
cmp "${fixture_root}/expected-legacy" "${legacy_template}"

printf 'version = 3\n' > "${config_dir}/config.toml"
if bash "${writer}" "${config_dir}" > /dev/null 2>&1; then
  echo 'containerd version/template mismatch was accepted' >&2
  exit 1
fi
[[ ! -e "${template}" ]]

printf 'version = 99\n' > "${config_dir}/config.toml"
if bash "${writer}" "${config_dir}" > /dev/null 2>&1; then
  echo 'unknown containerd config version was accepted' >&2
  exit 1
fi

echo 'gVisor template preserves v2/v3 settings and rejects conflicts'
