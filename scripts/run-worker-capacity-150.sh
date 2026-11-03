#!/usr/bin/env bash
set -euo pipefail

# Uses and resets only the disposable loopback provisioner_load_150 database.
: "${PROVISIONER_LOAD_DATABASE_URL:?Set the dedicated test database URL}"
if [[ ${PROVISIONER_LOAD_ALLOW_TRUNCATE:-} != 1 ]]; then
  printf '%s\n' 'Set PROVISIONER_LOAD_ALLOW_TRUNCATE=1 for the disposable test database.' >&2
  exit 1
fi

task_repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$task_repo"
if [[ -z ${PROVISIONER_LOAD_OUTPUT:-} ]]; then
  PROVISIONER_LOAD_OUTPUT=$(mktemp -d "${TMPDIR:-/tmp}/provisioner-load-150.XXXXXXXX")
fi
export PROVISIONER_LOAD_OUTPUT
printf 'Results: %s\n' "$PROVISIONER_LOAD_OUTPUT"

run_capacity() {
  if [[ -n ${PROVISIONER_LOAD_TEST_BINARY:-} ]]; then
    "$PROVISIONER_LOAD_TEST_BINARY" -test.v -test.run '^TestWorkerCapacity150$' -test.timeout=20m
  else
    go test ./tests/workerload -v -run '^TestWorkerCapacity150$' -count=1 -timeout=20m
  fi
}

export PROVISIONER_LOAD_WORKERS=${PROVISIONER_LOAD_WORKERS:-10,20,30,50}
export PROVISIONER_LOAD_EXECUTION=1s
export PROVISIONER_LOAD_REPEATS=3
export PROVISIONER_LOAD_RETRY_EVERY=0
run_capacity

export PROVISIONER_LOAD_EXECUTION=10s
export PROVISIONER_LOAD_REPEATS=1
run_capacity

export PROVISIONER_LOAD_WORKERS=20,30
export PROVISIONER_LOAD_EXECUTION=1s
export PROVISIONER_LOAD_RETRY_EVERY=10
run_capacity
