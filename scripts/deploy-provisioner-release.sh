#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s <candidate-binary> <expected-sha256>\n' "$0" >&2
  exit 2
fi

candidate="$1"
expected_sha256="$2"
install_dir="${PROVISIONER_INSTALL_DIR:-/opt/secure-provisioner}"
token_file="${PROVISIONER_TOKEN_FILE:-/etc/secure-provisioner/service-token}"
service_name="${PROVISIONER_SERVICE_NAME:-secure-provisioner}"
health_max_attempts="${PROVISIONER_HEALTH_MAX_ATTEMPTS:-30}"
health_retry_delay="${PROVISIONER_HEALTH_RETRY_DELAY:-1}"
current_binary="${install_dir}/secure-provisioner"
previous_binary="${install_dir}/secure-provisioner.previous"
staged_binary="${install_dir}/secure-provisioner.new"
rollback_binary="${install_dir}/secure-provisioner.rollback"

if [[ ! -f "${candidate}" || ! -f "${token_file}" ]]; then
  printf 'candidate binary and service token are required\n' >&2
  exit 1
fi

actual_sha256="$(sha256sum "${candidate}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  printf 'candidate checksum mismatch\n' >&2
  exit 1
fi

mkdir -p "${install_dir}"
install -m 0755 "${candidate}" "${staged_binary}"
if [[ -f "${current_binary}" ]]; then
  cp -p "${current_binary}" "${previous_binary}"
fi
mv -f "${staged_binary}" "${current_binary}"

rollback() {
  printf 'deployment verification failed; restoring previous binary\n' >&2
  if [[ -f "${previous_binary}" ]]; then
    install -m 0755 "${previous_binary}" "${rollback_binary}"
    mv -f "${rollback_binary}" "${current_binary}"
    systemctl restart "${service_name}" || true
  else
    rm -f "${current_binary}"
  fi
  rm -f "${candidate}"
  exit 1
}

if ! systemctl restart "${service_name}"; then
  rollback
fi
if ! systemctl is-active --quiet "${service_name}"; then
  rollback
fi

service_token="$(tr -d '\r\n' < "${token_file}")"
health_status=""
for ((attempt = 1; attempt <= health_max_attempts; attempt++)); do
  if health_status="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${service_token}" \
    "http://127.0.0.1:8080/internal/v1/operations/ci-healthcheck-${expected_sha256}")" && \
    [[ "${health_status}" == "404" ]]; then
    break
  fi
  if (( attempt < health_max_attempts )); then
    sleep "${health_retry_delay}"
  fi
done
if [[ "${health_status}" != "404" ]]; then
  rollback
fi

rm -f "${candidate}"
printf 'provisioner deployment verified\n'
