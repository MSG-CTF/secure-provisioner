#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight="${repository_root}/scripts/check-k3s-before-bootstrap.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
mkdir -p "${fixture_root}/bin"

cat > "${fixture_root}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == 'is-active --quiet k3s' ]] || exit 2
[[ "${TEST_K3S_ACTIVE:-}" == 1 ]]
EOF
cat > "${fixture_root}/bin/k3s" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${TEST_K3S_CALLS}"
[[ "$*" == 'kubectl get secrets -n kube-system --request-timeout=10s -o name' ]] || exit 2
[[ "${TEST_SECRETS_API_OK:-}" == 1 ]]
EOF
chmod +x "${fixture_root}/bin/systemctl" "${fixture_root}/bin/k3s"
export PATH="${fixture_root}/bin:${PATH}"
export TEST_K3S_CALLS="${fixture_root}/k3s-calls"

export TEST_K3S_ACTIVE=1 TEST_SECRETS_API_OK=1
bash "${preflight}" > "${fixture_root}/output"
[[ -s "${TEST_K3S_CALLS}" ]]
if grep -qi secret "${fixture_root}/output"; then
  echo 'preflight printed Secret data or names' >&2
  exit 1
fi

export TEST_K3S_ACTIVE=0
: > "${TEST_K3S_CALLS}"
if bash "${preflight}" > /dev/null 2>&1; then
  echo 'inactive K3s was accepted' >&2
  exit 1
fi
[[ ! -s "${TEST_K3S_CALLS}" ]]

export TEST_K3S_ACTIVE=1 TEST_SECRETS_API_OK=0
if bash "${preflight}" > /dev/null 2>&1; then
  echo 'unreadable K3s Secrets were accepted' >&2
  exit 1
fi

echo 'K3s bootstrap preflight rejects unhealthy services and Secret APIs'
