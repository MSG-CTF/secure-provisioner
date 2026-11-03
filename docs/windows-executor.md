# Azure Windows executor

The Windows executor HTTPS API listens on the VM public IP, port 443. Install it
with a random credential dedicated to that VM, accepted as
`Authorization: Bearer <token>`. Provision this executor credential through an
Azure Managed Run Command protected parameter, outside Terraform state. Keep the
Runtime-to-Broker credential on the trusted Runtime host; never install it in a
participant VM. The client requires two token files and rejects equal values.
The API certificate is self-signed for the
VM public IP. Runtime must trust the certificate retrieved through Azure's
control plane and must verify the IP address; do not disable TLS verification.

Build the artifact from this repository and publish it at a versioned HTTPS URL:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go build -trimpath -o windows-executor.exe ./cmd/windows-executor
Get-FileHash windows-executor.exe -Algorithm SHA256
```

The VM accepts one execution at a time. `PUT /v1/executions/{uuid}` uploads a raw
EXE of 1 to 64 MiB with these headers:

```text
Authorization: Bearer <VM_EXECUTOR_API_TOKEN>
Content-Type: application/octet-stream
X-Content-SHA256: <64 lowercase hexadecimal characters>
X-Timeout-Seconds: <1..300>
```

It returns `202` after starting the `MSGWindowsExecutor` scheduled task. The
task runs as non-administrator `msgworker`, checks the SHA-256, and starts only
`jobs/<uuid>/submission.exe` with no arguments or shell. `GET` on the same URL
returns `202` while pending or `200` with `execution_id`, `status`, `exit_code`,
base64 `stdout`/`stderr`, `output_truncated`, and `duration_ms`. Output is capped
at 64 KiB combined. `DELETE` removes a finished result and allows the next job.
The same `PUT` ID and digest is accepted for an ambiguous retry; another job
gets `409` until the result is deleted.

Runtime can call the VM API with the client command. Use its Broker token file
and this VM's separate executor token file, the Broker resource target UUID,
the public IP, and the certificate fetched from that VM:

```powershell
go run ./cmd/windows-executor-client -vm https://<VM_PUBLIC_IP> -broker https://broker.mjsec.kr/api -target <RESOURCE_TARGET_UUID> -cert <VM_SERVER_CERT_PEM> -token-file <RUNTIME_BROKER_TOKEN_FILE> -executor-token-file <VM_EXECUTOR_TOKEN_FILE> -exe <COMPILED_WINDOWS_EXE> -timeout 30
```

The client first reports `started` to Broker. If Broker rejects the VM, it does
not upload the EXE. It verifies the VM TLS certificate, uploads the EXE, polls
the result, reports `finished` to Broker, checks that Broker returned
`RESET_REQUIRED`, prints the result JSON, and deletes the finished VM job.
Neither the VM client nor the Broker client follows HTTP redirects.
If the VM call fails after `started`, it reports `finished` with `unreachable`
so Broker still requires a clean reset. Broker state alone does not reset the
VM; only confirm a reset with the completed execution ID after restoring a
clean image. This command is the Runtime-to-VM integration entry point until
the Backend upload API contract is available.

This is an execution prototype. `msgworker` is not a strong sandbox: submitted
code can access the VM network and may leave child processes after a timeout.
Do not reuse a VM for another participant until it has been restored from a
clean image. Backend upload, job ownership, and image restoration are not yet
implemented.

Before deployment, update the VM provisioner to deliver distinct executor
credentials and verify the entire Azure run and clean-image reset with those
credentials. If a VM previously received the Broker credential, replace it with
a dedicated executor credential and revoke the exposed Broker credential through
a coordinated rotation. These local client and server tests do not prove the
Azure provisioning or reset path.
