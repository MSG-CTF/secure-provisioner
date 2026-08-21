$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repositoryRoot

try {
  docker compose -f .\compose.postgres.yaml up -d --wait
  if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL compose startup failed with exit code $LASTEXITCODE."
  }

  $env:PROVISIONER_TEST_DATABASE_URL = "postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable"

  go test ./... -count=1
  if ($LASTEXITCODE -ne 0) {
    throw "Go tests failed with exit code $LASTEXITCODE."
  }

  go vet ./...
  if ($LASTEXITCODE -ne 0) {
    throw "go vet failed with exit code $LASTEXITCODE."
  }

  go build ./...
  if ($LASTEXITCODE -ne 0) {
    throw "Go build failed with exit code $LASTEXITCODE."
  }
} finally {
  Pop-Location
}
