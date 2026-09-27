#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: ensure-gvisor-containerd-template.sh <containerd-config-dir>' >&2
  exit 2
fi

config_dir="$1"
generated_config="${config_dir}/config.toml"
if [[ ! -f "${generated_config}" ]]; then
  echo 'generated containerd config is required to select the active template version' >&2
  exit 1
fi

config_version="$(awk '$1 == "version" && $2 == "=" && ($3 == "2" || $3 == "3") { print $3; exit }' "${generated_config}")"
case "${config_version}" in
  3)
    template="${config_dir}/config-v3.toml.tmpl"
    section="[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]"
    if [[ ! -e "${template}" && -e "${config_dir}/config.toml.tmpl" ]]; then
      echo 'legacy containerd template exists but rendered config is v3; inspect before bootstrap' >&2
      exit 1
    fi
    ;;
  2)
    template="${config_dir}/config.toml.tmpl"
    section='[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]'
    if [[ -e "${config_dir}/config-v3.toml.tmpl" ]]; then
      echo 'v3 containerd template exists but rendered config is v2; inspect before bootstrap' >&2
      exit 1
    fi
    ;;
  *)
    echo 'unsupported generated containerd config version' >&2
    exit 1
    ;;
esac

runtime_type='  runtime_type = "io.containerd.runsc.v1"'
if [[ -L "${template}" || ( -e "${template}" && ! -f "${template}" ) ]]; then
  echo 'containerd template must be a regular file' >&2
  exit 1
fi
if [[ -f "${template}" ]] && grep -Fqx "${section}" "${template}"; then
  if awk -v section="${section}" -v runtime_type="${runtime_type}" '
    $0 == section { in_section = 1; next }
    in_section && /^\[/ { exit }
    in_section && $0 == runtime_type { found = 1 }
    END { exit found ? 0 : 1 }
  ' "${template}"; then
    exit 0
  fi
  echo 'existing runsc handler conflicts with the required runtime type' >&2
  exit 1
fi

temporary="$(mktemp "${template}.XXXXXXXX")"
trap 'rm -f -- "${temporary}"' EXIT
if [[ -f "${template}" ]]; then
  cp -p -- "${template}" "${temporary}"
else
  printf '{{ template "base" . }}\n' > "${temporary}"
  chmod 0644 "${temporary}"
fi
cat >> "${temporary}" <<EOF

${section}
${runtime_type}
EOF
mv -f -- "${temporary}" "${template}"
trap - EXIT
