$ErrorActionPreference = "Stop"

$mvpRoot = Split-Path -Parent $PSScriptRoot
Push-Location $mvpRoot

try {
  gofmt -w .
  go vet ./...

  New-Item -ItemType Directory -Path "bin" -Force | Out-Null
  go test -c -o "bin\integration.test.exe" ./tests/integration

  & ".\bin\integration.test.exe" "-test.v" "-test.timeout=20s"
  if ($LASTEXITCODE -ne 0) {
    throw "Integration tests failed with exit code $LASTEXITCODE."
  }
} finally {
  Pop-Location
}
