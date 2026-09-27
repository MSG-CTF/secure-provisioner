#!/usr/bin/env bash
set -euo pipefail

smoke_image="${GVISOR_SMOKE_IMAGE:-docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
if [[ ! "${smoke_image}" =~ ^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo 'GVISOR_SMOKE_IMAGE must use a sha256 digest' >&2
  exit 2
fi

handler="$(k3s kubectl get runtimeclass gvisor -o jsonpath='{.handler}' --ignore-not-found)"
if [[ -n "${handler}" && "${handler}" != runsc ]]; then
  echo 'existing gvisor RuntimeClass uses a different handler' >&2
  exit 1
fi
if [[ -z "${handler}" ]]; then
  cat <<'EOF' | k3s kubectl create -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
fi

read -r random_id < /proc/sys/kernel/random/uuid
namespace="gvisor-smoke-${random_id}"
namespace_created=false
cleanup() {
  status=$?
  if [[ "${namespace_created}" == true ]]; then
    if ! k3s kubectl delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null; then
      echo "could not clean up smoke Namespace ${namespace}" >&2
      status=1
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT

k3s kubectl create namespace "${namespace}" >/dev/null
namespace_created=true
cat <<EOF | k3s kubectl apply -n "${namespace}" -f -
apiVersion: v1
kind: Pod
metadata:
  name: gvisor-smoke
spec:
  runtimeClassName: gvisor
  restartPolicy: Never
  containers:
    - name: smoke
      image: ${smoke_image}
      command: ["sh", "-c", "dmesg | grep -q gVisor && sleep 300"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF

k3s kubectl wait -n "${namespace}" --for=condition=Ready pod/gvisor-smoke --timeout=180s
k3s kubectl exec -n "${namespace}" pod/gvisor-smoke -- sh -c 'dmesg | grep -q gVisor'
