#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke="${repository_root}/scripts/run-gvisor-smoke.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
mkdir -p "${fixture_root}/bin"
cat > "${fixture_root}/bin/k3s" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${TEST_K3S_CALLS}"
case "$*" in
  'kubectl get runtimeclass gvisor -o jsonpath={.handler} --ignore-not-found')
    printf '%s' "${TEST_RUNTIME_HANDLER:-}"
    ;;
  'kubectl create -f -'|kubectl\ apply\ -n\ gvisor-smoke-*\ -f\ -)
    cat >> "${TEST_APPLIED_MANIFEST}"
    ;;
  kubectl\ wait\ -n\ gvisor-smoke-*)
    [[ "${TEST_WAIT_FAIL:-0}" != 1 ]]
    ;;
esac
EOF
chmod +x "${fixture_root}/bin/k3s"
export PATH="${fixture_root}/bin:${PATH}"
export TEST_K3S_CALLS="${fixture_root}/calls"
export TEST_APPLIED_MANIFEST="${fixture_root}/manifest"

export TEST_RUNTIME_HANDLER=runsc TEST_WAIT_FAIL=0
bash "${smoke}"
if grep -Fq 'kubectl create -f -' "${TEST_K3S_CALLS}"; then
  echo 'existing RuntimeClass was overwritten' >&2
  exit 1
fi
grep -Eq '^kubectl create namespace gvisor-smoke-' "${TEST_K3S_CALLS}"
grep -Eq '^kubectl delete namespace gvisor-smoke-' "${TEST_K3S_CALLS}"
grep -Fq 'docker.io/library/busybox@sha256:' "${TEST_APPLIED_MANIFEST}"
if grep -Fq 'kubectl delete pod' "${TEST_K3S_CALLS}"; then
  echo 'smoke test deleted a shared Pod' >&2
  exit 1
fi

export TEST_RUNTIME_HANDLER=other
: > "${TEST_K3S_CALLS}"
if bash "${smoke}" > /dev/null 2>&1; then
  echo 'conflicting RuntimeClass was accepted' >&2
  exit 1
fi
if grep -Fq 'kubectl create namespace' "${TEST_K3S_CALLS}"; then
  echo 'conflict created a smoke Namespace' >&2
  exit 1
fi

export TEST_RUNTIME_HANDLER=runsc TEST_WAIT_FAIL=1
: > "${TEST_K3S_CALLS}"
if bash "${smoke}" > /dev/null 2>&1; then
  echo 'failed smoke wait was accepted' >&2
  exit 1
fi
grep -Eq '^kubectl delete namespace gvisor-smoke-' "${TEST_K3S_CALLS}"

export TEST_RUNTIME_HANDLER= TEST_WAIT_FAIL=0
: > "${TEST_K3S_CALLS}"
bash "${smoke}"
grep -Fxq 'kubectl create -f -' "${TEST_K3S_CALLS}"

echo 'gVisor smoke preserves shared resources and cleans up on failure'
