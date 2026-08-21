#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deploy_script="${repository_root}/scripts/deploy-provisioner-release.sh"

new_fixture() {
  fixture_root="$(mktemp -d)"
  install_dir="${fixture_root}/install"
  fake_bin="${fixture_root}/bin"
  token_file="${fixture_root}/service-token"
  systemctl_log="${fixture_root}/systemctl.log"
  mkdir -p "${install_dir}" "${fake_bin}"
  printf 'old-binary\n' > "${install_dir}/secure-provisioner"
  printf 'new-binary\n' > "${fixture_root}/candidate"
  printf 'test-service-token\n' > "${token_file}"

  cat > "${fake_bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SYSTEMCTL_LOG}"
if [[ "${1:-}" == "is-active" ]]; then
  exit "${FAKE_SYSTEMCTL_ACTIVE_EXIT:-0}"
fi
EOF
  chmod +x "${fake_bin}/systemctl"

  cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
expected_header="Authorization: Bearer test-service-token"
joined=" $* "
if [[ "${joined}" != *" -H ${expected_header} "* ]]; then
  printf 'missing bearer header\n' >&2
  exit 2
fi
if [[ -n "${FAKE_CURL_STATE_FILE:-}" ]]; then
  attempt=0
  if [[ -f "${FAKE_CURL_STATE_FILE}" ]]; then
    attempt="$(cat "${FAKE_CURL_STATE_FILE}")"
  fi
  attempt=$((attempt + 1))
  printf '%s' "${attempt}" > "${FAKE_CURL_STATE_FILE}"
  if (( attempt <= ${FAKE_CURL_FAILURES:-0} )); then
    exit 7
  fi
fi
printf '%s' "${FAKE_CURL_STATUS:-404}"
EOF
  chmod +x "${fake_bin}/curl"
}

run_deploy() {
  local expected_sha
  expected_sha="$(sha256sum "${fixture_root}/candidate" | awk '{print $1}')"
  PATH="${fake_bin}:${PATH}" \
    SYSTEMCTL_LOG="${systemctl_log}" \
    PROVISIONER_INSTALL_DIR="${install_dir}" \
    PROVISIONER_TOKEN_FILE="${token_file}" \
    PROVISIONER_HEALTH_MAX_ATTEMPTS="${PROVISIONER_HEALTH_MAX_ATTEMPTS:-1}" \
    PROVISIONER_HEALTH_RETRY_DELAY="${PROVISIONER_HEALTH_RETRY_DELAY:-0}" \
    FAKE_CURL_STATE_FILE="${FAKE_CURL_STATE_FILE:-}" \
    FAKE_CURL_FAILURES="${FAKE_CURL_FAILURES:-0}" \
    bash "${deploy_script}" "${fixture_root}/candidate" "${expected_sha}"
}

test_success_replaces_binary_and_keeps_rollback_copy() {
  new_fixture
  trap 'rm -rf "${fixture_root}"' RETURN

  run_deploy

  [[ "$(cat "${install_dir}/secure-provisioner")" == "new-binary" ]]
  [[ "$(cat "${install_dir}/secure-provisioner.previous")" == "old-binary" ]]
  grep -Fxq 'restart secure-provisioner' "${systemctl_log}"
  grep -Fxq 'is-active --quiet secure-provisioner' "${systemctl_log}"
}

test_failed_health_check_restores_previous_binary() {
  new_fixture
  trap 'rm -rf "${fixture_root}"' RETURN

  if FAKE_CURL_STATUS=500 run_deploy; then
    printf 'deployment unexpectedly succeeded\n' >&2
    return 1
  fi

  [[ "$(cat "${install_dir}/secure-provisioner")" == "old-binary" ]]
  [[ "$(grep -c '^restart secure-provisioner$' "${systemctl_log}")" == "2" ]]
}

test_checksum_mismatch_does_not_replace_current_binary() {
  new_fixture
  trap 'rm -rf "${fixture_root}"' RETURN

  if PATH="${fake_bin}:${PATH}" \
    SYSTEMCTL_LOG="${systemctl_log}" \
    PROVISIONER_INSTALL_DIR="${install_dir}" \
    PROVISIONER_TOKEN_FILE="${token_file}" \
    bash "${deploy_script}" "${fixture_root}/candidate" \
      '0000000000000000000000000000000000000000000000000000000000000000'; then
    printf 'checksum mismatch unexpectedly succeeded\n' >&2
    return 1
  fi

  [[ "$(cat "${install_dir}/secure-provisioner")" == "old-binary" ]]
  [[ ! -e "${install_dir}/secure-provisioner.previous" ]]
}

test_startup_connection_failures_are_retried_until_api_is_ready() {
  new_fixture
  trap 'rm -rf "${fixture_root}"' RETURN
  curl_state_file="${fixture_root}/curl-attempts"

  FAKE_CURL_STATE_FILE="${curl_state_file}" \
    FAKE_CURL_FAILURES=2 \
    PROVISIONER_HEALTH_MAX_ATTEMPTS=3 \
    PROVISIONER_HEALTH_RETRY_DELAY=0 \
    run_deploy

  [[ "$(cat "${curl_state_file}")" == "3" ]]
  [[ "$(cat "${install_dir}/secure-provisioner")" == "new-binary" ]]
}

test_success_replaces_binary_and_keeps_rollback_copy
test_failed_health_check_restores_previous_binary
test_checksum_mismatch_does_not_replace_current_binary
test_startup_connection_failures_are_retried_until_api_is_ready
printf 'deploy release tests passed\n'
