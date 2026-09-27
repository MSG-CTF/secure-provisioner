#!/usr/bin/env bash
set -euo pipefail

readonly POD_MAX_PIDS="${POD_MAX_PIDS:-256}"
readonly K3S_CONFIG_DIR=/etc/rancher/k3s
readonly CONTAINERD_CONFIG_DIR=/var/lib/rancher/k3s/agent/etc/containerd
readonly GVISOR_KEYRING=/usr/share/keyrings/gvisor-archive-keyring.gpg
readonly GVISOR_REPOSITORY=/etc/apt/sources.list.d/gvisor.list
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

case "${POD_MAX_PIDS}" in
  ''|*[!0-9]*)
    echo "POD_MAX_PIDS must be a positive integer." >&2
    exit 1
    ;;
esac
if (( POD_MAX_PIDS < 1 )); then
  echo "POD_MAX_PIDS must be a positive integer." >&2
  exit 1
fi

bash "${SCRIPT_DIR}/check-k3s-before-bootstrap.sh"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

key_tmp="$(mktemp)"
trap 'rm -f "${key_tmp}"' EXIT
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor >"${key_tmp}"
install -o root -g root -m 0644 "${key_tmp}" "${GVISOR_KEYRING}"
printf 'deb [arch=%s signed-by=%s] https://storage.googleapis.com/gvisor/releases release main\n' \
  "$(dpkg --print-architecture)" "${GVISOR_KEYRING}" >"${GVISOR_REPOSITORY}"

apt-get update
apt-get install -y runsc
command -v runsc >/dev/null
command -v containerd-shim-runsc-v1 >/dev/null

install -d -o root -g root -m 0755 "${K3S_CONFIG_DIR}" "${CONTAINERD_CONFIG_DIR}"
bash "${SCRIPT_DIR}/write-k3s-isolation-config.sh" "${K3S_CONFIG_DIR}" "${POD_MAX_PIDS}"

bash "${SCRIPT_DIR}/ensure-gvisor-containerd-template.sh" "${CONTAINERD_CONFIG_DIR}"

systemctl restart k3s

for _ in $(seq 1 90); do
  if k3s kubectl get node >/dev/null 2>&1 && \
     [[ "$(k3s kubectl get node -o custom-columns=READY:.status.conditions[-1].status --no-headers 2>/dev/null)" == "True" ]]; then
    break
  fi
  sleep 2
done
k3s kubectl wait --for=condition=Ready node --all --timeout=180s
bash "${SCRIPT_DIR}/check-k3s-before-bootstrap.sh"

bash "${SCRIPT_DIR}/run-gvisor-smoke.sh"

grep -q "io.containerd.runsc.v1" /var/lib/rancher/k3s/agent/etc/containerd/config.toml
grep -q "pod-max-pids=${POD_MAX_PIDS}" "${K3S_CONFIG_DIR}/config.yaml.d/50-msgctf-isolation.yaml"
bash "${SCRIPT_DIR}/check-k3s-before-bootstrap.sh"

printf 'gVisor smoke passed; pod-max-pids=%s is configured and requires a live PID limit test.\n' "${POD_MAX_PIDS}"
