# Azure Windows executor

The Windows executor HTTPS API listens on the VM public IP, port 443. The
deployed Runtime uses mTLS. Install only the Runtime client CA public
certificate in the VM and start the API with `-client-ca <CA_PEM>`. Runtime
keeps its client private key and Broker bearer token on its trusted host.
The VM requires a client certificate signed by that CA before accepting HTTP.
`-client-ca` and `-token-file` are mutually exclusive; mTLS cannot fall back to a
bearer token. The CA file must contain current CA certificates, not leaf
certificates or private keys.
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

Runtime can call the VM API with the client command. Keep its Broker token file,
mTLS client certificate and private key on the Runtime host. Use the Broker
resource target UUID, public IP, and certificate fetched from that VM:

```powershell
go run ./cmd/windows-executor-client -vm https://<VM_PUBLIC_IP> -broker https://broker.mjsec.kr/api -target <RESOURCE_TARGET_UUID> -cert <VM_SERVER_CERT_PEM> -token-file <RUNTIME_BROKER_TOKEN_FILE> -client-cert <RUNTIME_CLIENT_CERT_PEM> -client-key <RUNTIME_CLIENT_KEY_PEM> -exe <COMPILED_WINDOWS_EXE> -timeout 30
```

The existing dedicated VM token mode remains available with
`-executor-token-file` instead of the client certificate and key. It rejects
reuse of the Broker token. The server uses `-token-file` in that mode.

The client first reports `started` to Broker. If Broker rejects the VM, it does
not upload the EXE. It verifies the VM TLS certificate, uploads the EXE, polls
the result, reports `finished` to Broker, checks that Broker returned
`RESET_REQUIRED`, prints the result JSON, and deletes the finished VM job.
Neither the VM client nor the Broker client follows HTTP redirects.
If the VM call fails after `started`, it reports `finished` with `unreachable`
so Broker still requires a clean reset. Broker state alone does not reset the
VM; only confirm a reset with the completed execution ID after restoring a
clean image. The manual command is a diagnostic client. The current Backend
submission and durable Runtime queue are documented in
[Windows HTTPS Runtime](operations/windows-https-runtime.md).

The runner account is not a strong sandbox: submitted
code can access the VM network and may leave child processes after a timeout.
Do not reuse a VM for another participant until it has been restored from a
clean image. The Broker owns that restoration independently of the VM result.

Before deployment, verify the Azure VM uses the expected runner account, CA,
server certificate and scheduled task paths. After execution, verify the
Broker restores the approved image before the VM becomes READY. Windows CI
uploads the executable and source/digest receipt so the installed bytes can be
matched to the reviewed commit. Local TLS tests alone do not prove Azure
execution or image restoration.
