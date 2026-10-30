package windowsruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ExecutorCredential belongs to the VM HTTPS API and must never be the Broker token.
type ExecutorCredential struct {
	TokenFile       string `json:"token_file"`
	CertificateFile string `json:"certificate_file"`
	Port            int    `json:"port,omitempty"`
}

type HTTPSExecutorConfig struct {
	Targets               map[string]ExecutorCredential `json:"targets,omitempty"`
	ClientCertificateFile string                        `json:"client_certificate_file,omitempty"`
	ClientKeyFile         string                        `json:"client_key_file,omitempty"`
	Port                  int                           `json:"port,omitempty"`
}

func (c HTTPSExecutorConfig) UsesBrokerMTLS() bool {
	return c.ClientCertificateFile != "" || c.ClientKeyFile != ""
}

type executorTarget struct {
	token  string
	cert   *x509.Certificate
	client *http.Client
	port   int
}

type HTTPSExecutorTransport struct {
	targets    map[string]executorTarget
	clientCert *tls.Certificate
	port       int
}

func NewHTTPSExecutorTransport(cfg HTTPSExecutorConfig) (*HTTPSExecutorTransport, error) {
	if cfg.UsesBrokerMTLS() {
		if len(cfg.Targets) != 0 || !filepath.IsAbs(cfg.ClientCertificateFile) || !filepath.IsAbs(cfg.ClientKeyFile) || cfg.ClientCertificateFile == cfg.ClientKeyFile || cfg.Port < 0 || cfg.Port > 65535 {
			return nil, errors.New("invalid Windows Broker mTLS configuration")
		}
		for _, path := range []string{cfg.ClientCertificateFile, cfg.ClientKeyFile} {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				return nil, errors.New("Windows Broker mTLS credential unavailable")
			}
			if path == cfg.ClientKeyFile && !privateSecretPermissions(info) {
				return nil, errors.New("Windows Broker mTLS key file must be private")
			}
		}
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCertificateFile, cfg.ClientKeyFile)
		if err != nil || len(certificate.Certificate) == 0 {
			return nil, errors.New("Windows Broker mTLS key pair invalid")
		}
		port := cfg.Port
		if port == 0 {
			port = 443
		}
		return &HTTPSExecutorTransport{clientCert: &certificate, port: port}, nil
	}
	if len(cfg.Targets) == 0 {
		return nil, errors.New("Windows HTTPS executor targets are required")
	}
	result := &HTTPSExecutorTransport{targets: make(map[string]executorTarget, len(cfg.Targets))}
	for id, reference := range cfg.Targets {
		if !ValidID(id) || !filepath.IsAbs(reference.TokenFile) || !filepath.IsAbs(reference.CertificateFile) || reference.TokenFile == reference.CertificateFile || reference.Port < 0 || reference.Port > 65535 {
			return nil, errors.New("invalid Windows HTTPS executor target")
		}
		info, err := os.Lstat(reference.TokenFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || !privateSecretPermissions(info) {
			return nil, errors.New("Windows HTTPS executor token file must be private and regular")
		}
		tokenRaw, err := os.ReadFile(reference.TokenFile)
		if err != nil || len(tokenRaw) > 4096 {
			return nil, errors.New("Windows HTTPS executor token unavailable")
		}
		token := strings.TrimSpace(string(tokenRaw))
		if len(token) < 32 || strings.ContainsAny(token, " \t\r\n\x00") {
			return nil, errors.New("invalid Windows HTTPS executor token")
		}
		certPEM, err := os.ReadFile(reference.CertificateFile)
		if err != nil || len(certPEM) > 1<<20 {
			return nil, errors.New("Windows HTTPS executor certificate unavailable")
		}
		block, rest := pemDecodeCertificate(certPEM)
		if block == nil || len(rest) != 0 {
			return nil, errors.New("invalid Windows HTTPS executor certificate")
		}
		cert, err := x509.ParseCertificate(block)
		if err != nil {
			return nil, errors.New("invalid Windows HTTPS executor certificate")
		}
		fingerprint := sha256.Sum256(cert.Raw)
		// The PR #88 VM certificate is self-signed. Trust and pin only its exact
		// certificate; the Broker IP is checked before opening the connection.
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("unexpected Windows executor certificate chain")
			}
			peer := state.PeerCertificates[0]
			actual := sha256.Sum256(peer.Raw)
			if subtle.ConstantTimeCompare(fingerprint[:], actual[:]) != 1 {
				return errors.New("Windows executor certificate changed")
			}
			if time.Now().Before(peer.NotBefore) || time.Now().After(peer.NotAfter) {
				return errors.New("Windows executor certificate expired")
			}
			return nil
		}}
		port := reference.Port
		if port == 0 {
			port = 443
		}
		result.targets[id] = executorTarget{token: token, cert: cert, port: port, client: &http.Client{
			Transport:     &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	}
	return result, nil
}

func (t *HTTPSExecutorTransport) UsesToken(token string) bool {
	for _, target := range t.targets {
		if subtle.ConstantTimeCompare([]byte(target.token), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func pemDecodeCertificate(raw []byte) ([]byte, []byte) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, nil
	}
	return block.Bytes, bytes.TrimSpace(rest)
}

type executorResult struct {
	ExecutionID     string `json:"execution_id"`
	Status          string `json:"status"`
	ExitCode        *int64 `json:"exit_code"`
	StdoutBase64    string `json:"stdout_base64"`
	StderrBase64    string `json:"stderr_base64"`
	OutputTruncated bool   `json:"output_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

func (t *HTTPSExecutorTransport) endpoint(c Connection) (executorTarget, string, error) {
	address, err := netip.ParseAddr(c.Host)
	if !ValidID(c.TargetID) || c.Protocol != "rdp" || err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return executorTarget{}, "", errors.New("invalid Windows executor target")
	}
	if t.clientCert != nil {
		block, rest := pemDecodeCertificate([]byte(c.ExecutorCertificatePEM))
		if block == nil || len(rest) != 0 || len(c.ExecutorCertificatePEM) > 1<<20 {
			return executorTarget{}, "", errors.New("invalid Broker executor certificate")
		}
		cert, err := x509.ParseCertificate(block)
		if err != nil || cert.VerifyHostname(c.Host) != nil || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return executorTarget{}, "", errors.New("Broker executor certificate does not match VM")
		}
		fingerprint := sha256.Sum256(cert.Raw)
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{*t.clientCert}, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) != 1 {
					return errors.New("Windows executor certificate changed")
				}
				actual := sha256.Sum256(state.PeerCertificates[0].Raw)
				if subtle.ConstantTimeCompare(fingerprint[:], actual[:]) != 1 {
					return errors.New("Windows executor certificate changed")
				}
				return nil
			}}, Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		return executorTarget{cert: cert, client: client, port: t.port}, "https://" + net.JoinHostPort(c.Host, strconv.Itoa(t.port)), nil
	}
	target, ok := t.targets[c.TargetID]
	if !ok {
		return executorTarget{}, "", errors.New("invalid Windows executor target")
	}
	if err := target.cert.VerifyHostname(c.Host); err != nil {
		return executorTarget{}, "", errors.New("Windows executor certificate does not match Broker host")
	}
	return target, "https://" + net.JoinHostPort(c.Host, strconv.Itoa(target.port)), nil
}

func (t *HTTPSExecutorTransport) ValidateConnection(c Connection) error {
	_, _, err := t.endpoint(c)
	return err
}

func (t *HTTPSExecutorTransport) request(ctx context.Context, target executorTarget, method, url string, body []byte, job Job) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if target.token != "" {
		r.Header.Set("Authorization", "Bearer "+target.token)
	}
	if method == http.MethodPut {
		digest := sha256.Sum256(body)
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
		r.Header.Set("X-Timeout-Seconds", strconv.Itoa(int(job.Timeout/time.Second)))
	}
	return target.client.Do(r)
}

func (t *HTTPSExecutorTransport) Execute(ctx context.Context, c Connection, job Job) Outcome {
	target, base, err := t.endpoint(c)
	if err != nil || !ValidID(job.ID) || len(job.Payload) < 2 || len(job.Payload) > 64<<20 || job.Payload[0] != 'M' || job.Payload[1] != 'Z' || job.Timeout < time.Second || job.Timeout > 300*time.Second || job.ConnectTimeout < time.Second || job.OutputLimit < 1 || job.OutputLimit > 1<<20 {
		return Outcome{Result: "failed", ErrorCode: "EXECUTOR_REQUEST_INVALID"}
	}
	url := base + "/v1/executions/" + job.ID
	putCtx, cancel := context.WithTimeout(ctx, job.ConnectTimeout)
	response, putErr := t.request(putCtx, target, http.MethodPut, url, job.Payload, job)
	if response != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		response.Body.Close()
	}
	cancel()
	putUncertain := putErr != nil || response != nil && response.StatusCode >= 500
	if !putUncertain && response.StatusCode != http.StatusAccepted {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_AUTH_REJECTED"}
		}
		if response.StatusCode == http.StatusConflict {
			return Outcome{Result: "failed", ErrorCode: "EXECUTOR_BUSY"}
		}
		return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_UPLOAD_REJECTED"}
	}
	// A lost PUT response is ambiguous. GET only this execution ID; never create a new ID.
	deadline := time.NewTimer(job.Timeout + job.ConnectTimeout)
	defer deadline.Stop()
	sawPending := !putUncertain
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_INTERRUPTED"}
		case <-deadline.C:
			return executorPollDeadline(sawPending)
		default:
		}
		pollCtx, stop := context.WithTimeout(ctx, job.ConnectTimeout)
		response, err := t.request(pollCtx, target, http.MethodGet, url, nil, job)
		if err == nil && response.StatusCode == http.StatusOK {
			var result executorResult
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
			response.Body.Close()
			stop()
			if readErr != nil || len(data) > 1<<20 || json.Unmarshal(data, &result) != nil {
				return Outcome{Result: "failed", ErrorCode: "EXECUTOR_RESULT_INVALID"}
			}
			return parseExecutorResult(result, job)
		}
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			response.Body.Close()
		}
		stop()
		if err == nil && response.StatusCode == http.StatusAccepted {
			sawPending = true
		}
		if err == nil && response.StatusCode != http.StatusAccepted && !(putUncertain && response.StatusCode == http.StatusNotFound) {
			return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_RESULT_UNAVAILABLE"}
		}
		select {
		case <-ctx.Done():
			return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_INTERRUPTED"}
		case <-deadline.C:
			return executorPollDeadline(sawPending)
		case <-ticker.C:
		}
	}
}

func executorPollDeadline(sawPending bool) Outcome {
	if sawPending {
		return Outcome{Result: "timeout", ErrorCode: "EXECUTOR_RESULT_TIMEOUT"}
	}
	return Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_UPLOAD_UNCERTAIN"}
}

// Resume uses the executor's idempotent PUT to recover the same execution ID.
func (t *HTTPSExecutorTransport) Resume(ctx context.Context, c Connection, job Job) Outcome {
	return t.Execute(ctx, c, job)
}

func parseExecutorResult(result executorResult, job Job) Outcome {
	invalid := Outcome{Result: "failed", ErrorCode: "EXECUTOR_RESULT_INVALID"}
	if result.ExecutionID != job.ID || result.DurationMS < 0 || result.DurationMS > int64(job.Timeout/time.Millisecond)+5000 || len(result.StdoutBase64) > base64.StdEncoding.EncodedLen(job.OutputLimit)+4 || len(result.StderrBase64) > base64.StdEncoding.EncodedLen(job.OutputLimit)+4 {
		return invalid
	}
	stdout, err1 := base64.StdEncoding.Strict().DecodeString(result.StdoutBase64)
	stderr, err2 := base64.StdEncoding.Strict().DecodeString(result.StderrBase64)
	if err1 != nil || err2 != nil || len(stdout)+len(stderr) > job.OutputLimit || result.Status != "succeeded" && result.Status != "failed" && result.Status != "timeout" || result.Status == "succeeded" && (result.ExitCode == nil || *result.ExitCode != 0) {
		return invalid
	}
	started := time.Now().UTC().Add(-time.Duration(result.DurationMS) * time.Millisecond)
	if result.DurationMS == 0 && result.Status == "failed" && result.ExitCode == nil {
		return Outcome{Result: "failed", ErrorCode: "EXECUTOR_LAUNCH_FAILED", Started: pointerBool(false)}
	}
	return Outcome{Result: result.Status, ExitCode: result.ExitCode, StartedAt: &started, Stdout: string(stdout), Stderr: string(stderr), StdoutTruncated: result.OutputTruncated, StderrTruncated: result.OutputTruncated}
}

func pointerBool(value bool) *bool { return &value }

// Cleanup is called only after the result and Broker finished receipt are durable.
func (t *HTTPSExecutorTransport) Cleanup(ctx context.Context, c Connection, id string) error {
	target, base, err := t.endpoint(c)
	if err != nil || !ValidID(id) {
		return errors.New("invalid Windows executor cleanup")
	}
	response, err := t.request(ctx, target, http.MethodDelete, base+"/v1/executions/"+id, nil, Job{})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Windows executor cleanup status %d", response.StatusCode)
	}
	return nil
}
