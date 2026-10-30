# Windows Broker mTLS alignment

## Observed deployment

On 2026-10-27 the Broker READY list returned target `aed4895c-3615-4fac-ade8-4dfad4c2d7e2`. Its connection response included `executor_certificate_pem`; the certificate SHA-256 matched the VM's port 443 certificate. The VM required a client certificate. The Runtime host had `windows-runtime-client.crt` and `.key`. A benign standalone canary completed with exit code 0 and `MSG_EXECUTOR_CANARY_OK`; Broker replayed its `finished` event as `200/FINISHED/RESET_REQUIRED`.

## Approaches

1. Keep static VM token and certificate files: smallest code change, but incompatible with the deployed mTLS executor and requires per-VM configuration.
2. Replace the transport with Broker-provided certificate and Runtime client mTLS: matches deployment and allows newly discovered Broker VMs, but discards the PR #88 prototype's token transport.
3. Add a Broker mTLS mode to the existing HTTPS transport: preserve the prototype while selecting the deployed mode in configuration. **Chosen** for compatibility with the existing PR and tests.

## Contract

- The mTLS mode uses a private Runtime client certificate and key from absolute file paths. It never sends the Broker bearer token to the VM.
- The deployed files are owned by `root:provisioner` with mode `0640`; Runtime accepts group read without group write or world access.
- The Broker's connection response supplies the VM server certificate. Runtime validates its PEM structure, validity period, IP SAN and exact certificate bytes before asking Broker to start execution. It persists the public certificate with the execution so restart recovery can use the same pin.
- The Broker READY list supplies candidates. In mTLS mode, Runtime can select any Broker READY Windows VM; the subsequent connection response and `started` event still gate execution. Static HTTPS and RDP modes retain their existing allowlists.
- The VM API remains `PUT/GET/DELETE /v1/executions/{execution_id}` and yields stdout/stderr and exit code. Broker `finished` confirmation for that execution gates Backend `RESULT`, independent of the VM's later state.
- This change does not enable participant intake or perform image restoration. The first canary left the VM reset-required; another live execution requires a clean restore and Broker reset.
