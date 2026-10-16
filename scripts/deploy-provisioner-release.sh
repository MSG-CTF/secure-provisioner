#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <candidate-binary> <binary-sha256> --expected-current-policy-sha256 <sha256> [--candidate-env <path>] [--candidate-policy <path> --expected-candidate-policy-sha256 <sha256>]\n' "$0" >&2
  exit 2
}

[[ "$#" -ge 4 ]] || usage
candidate="$1"
expected_sha256="$2"
shift 2

candidate_env=""
candidate_policy=""
expected_policy_sha256=""
expected_candidate_policy_sha256=""
while (( "$#" > 0 )); do
  [[ "$#" -ge 2 ]] || usage
  case "$1" in
    --candidate-env) candidate_env="$2" ;;
    --candidate-policy) candidate_policy="$2" ;;
    --expected-current-policy-sha256) expected_policy_sha256="$2" ;;
    --expected-candidate-policy-sha256) expected_candidate_policy_sha256="$2" ;;
    *) usage ;;
  esac
  shift 2
done

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

valid_sha256 "${expected_sha256}" || usage
valid_sha256 "${expected_policy_sha256}" || usage
if [[ -n "${candidate_policy}" ]]; then
  valid_sha256 "${expected_candidate_policy_sha256}" || usage
elif [[ -n "${expected_candidate_policy_sha256}" ]]; then
  usage
fi

install_dir="${PROVISIONER_INSTALL_DIR:-/opt/secure-provisioner}"
token_file="${PROVISIONER_TOKEN_FILE:-/etc/secure-provisioner/service-token}"
env_file="${PROVISIONER_ENV_FILE:-/etc/secure-provisioner/provisioner.env}"
policy_file="${PROVISIONER_POLICY_FILE:-/etc/secure-provisioner/image-policies.json}"
service_name="${PROVISIONER_SERVICE_NAME:-secure-provisioner}"
health_max_attempts="${PROVISIONER_HEALTH_MAX_ATTEMPTS:-30}"
health_retry_delay="${PROVISIONER_HEALTH_RETRY_DELAY:-1}"
current_binary="${install_dir}/secure-provisioner"
previous_binary="${install_dir}/secure-provisioner.previous"
staged_binary="${install_dir}/secure-provisioner.new"
rollback_binary="${install_dir}/secure-provisioner.rollback"

for file in "${candidate}" "${token_file}" "${env_file}" "${policy_file}"; do
  if [[ ! -f "${file}" || -L "${file}" ]]; then
    printf 'required deployment input is missing or is a symbolic link\n' >&2
    exit 1
  fi
done

environment_uses_approved_policy() {
  [[ "$(grep '^PROVISIONER_IMAGE_POLICIES=' "$1" || true)" == "PROVISIONER_IMAGE_POLICIES=${policy_file}" ]]
}
if ! environment_uses_approved_policy "${env_file}"; then
  printf 'current environment does not select the approved image policy path\n' >&2
  exit 1
fi

if [[ -n "${candidate_env}" ]]; then
  if [[ ! -f "${candidate_env}" || -L "${candidate_env}" ]]; then
    printf 'candidate environment file is missing or is a symbolic link\n' >&2
    exit 1
  fi
  env_mode="$(stat -c '%a' "${candidate_env}")"
  if (( (8#${env_mode} & 077) != 0 )) ||
    [[ "$(stat -c '%u' "${candidate_env}")" != "$(stat -c '%u' "${env_file}")" ]]; then
    printf 'candidate environment file must have no group/other access and the current owner\n' >&2
    exit 1
  fi
  if ! environment_uses_approved_policy "${candidate_env}"; then
    printf 'candidate environment does not select the approved image policy path\n' >&2
    exit 1
  fi
fi

if [[ -n "${candidate_policy}" && ( ! -f "${candidate_policy}" || -L "${candidate_policy}" ) ]]; then
  printf 'candidate policy file is missing or is a symbolic link\n' >&2
  exit 1
fi

actual_sha256="$(sha256sum "${candidate}" | awk '{print $1}')"
current_policy_sha256="$(sha256sum "${policy_file}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  printf 'candidate binary checksum mismatch\n' >&2
  exit 1
fi
if [[ "${current_policy_sha256}" != "${expected_policy_sha256}" ]]; then
  printf 'current image policy checksum differs from the approved version\n' >&2
  exit 1
fi
if [[ -n "${candidate_policy}" ]]; then
  actual_candidate_policy_sha256="$(sha256sum "${candidate_policy}" | awk '{print $1}')"
  if [[ "${actual_candidate_policy_sha256}" != "${expected_candidate_policy_sha256}" ]]; then
    printf 'candidate image policy checksum mismatch\n' >&2
    exit 1
  fi
fi

mkdir -p "${install_dir}"
install -m 0755 "${candidate}" "${staged_binary}"
if [[ -f "${current_binary}" ]]; then
  cp -p "${current_binary}" "${previous_binary}"
fi
if [[ -n "${candidate_env}" ]]; then
  cp -p "${env_file}" "${env_file}.previous"
  cp -p "${candidate_env}" "${env_file}.new"
  chown --reference="${env_file}" "${env_file}.new"
  chmod --reference="${env_file}" "${env_file}.new"
fi
if [[ -n "${candidate_policy}" ]]; then
  cp -p "${policy_file}" "${policy_file}.previous"
  cp -p "${candidate_policy}" "${policy_file}.new"
  chown --reference="${policy_file}" "${policy_file}.new"
  chmod --reference="${policy_file}" "${policy_file}.new"
fi

rollback_needed=true
rollback() {
  status=$?
  trap - EXIT
  if [[ "${rollback_needed}" == true ]]; then
    printf 'deployment verification failed; restoring previous binary and configuration\n' >&2
    if [[ -f "${previous_binary}" ]]; then
      install -m 0755 "${previous_binary}" "${rollback_binary}"
      mv -f "${rollback_binary}" "${current_binary}"
    else
      rm -f "${current_binary}"
    fi
    if [[ -n "${candidate_env}" ]]; then
      cp -p "${env_file}.previous" "${env_file}.rollback"
      mv -f "${env_file}.rollback" "${env_file}"
    fi
    if [[ -n "${candidate_policy}" ]]; then
      cp -p "${policy_file}.previous" "${policy_file}.rollback"
      mv -f "${policy_file}.rollback" "${policy_file}"
    fi
    systemctl restart "${service_name}" || true
  fi
  exit "${status}"
}
trap rollback EXIT

mv -f "${staged_binary}" "${current_binary}"
if [[ -n "${candidate_env}" ]]; then
  mv -f "${env_file}.new" "${env_file}"
fi
if [[ -n "${candidate_policy}" ]]; then
  mv -f "${policy_file}.new" "${policy_file}"
fi

systemctl restart "${service_name}"
systemctl is-active --quiet "${service_name}"

service_token="$(tr -d '\r\n' < "${token_file}")"
health_status=""
health_verified=false
for ((attempt = 1; attempt <= health_max_attempts; attempt++)); do
  if health_status="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${service_token}" \
    "http://127.0.0.1:8080/internal/v1/operations/ci-healthcheck-${expected_sha256}")" &&
    [[ "${health_status}" == "404" ]]; then
    health_verified=true
    break
  fi
  if (( attempt < health_max_attempts )); then
    sleep "${health_retry_delay}"
  fi
done
if [[ "${health_verified}" != true ]]; then
  exit 1
fi

rollback_needed=false
trap - EXIT
rm -f "${candidate}"
printf 'provisioner deployment verified\n'
