$ErrorActionPreference = "Stop"
$env:PROVISIONER_TEST_DATABASE_URL = "postgres://provisioner:provisioner@127.0.0.1:54329/provisioner_test?sslmode=disable"
docker compose -f compose.postgres.yaml up -d --wait
go test -p 1 ./tests/workerload ./tests/integration -count=1 -timeout 5m
