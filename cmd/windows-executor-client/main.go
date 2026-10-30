package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

func main() {
	vmURL := flag.String("vm", "", "Azure VM HTTPS URL, for example https://203.0.113.10")
	brokerURL := flag.String("broker", "https://broker.mjsec.kr/api", "Broker HTTPS API base URL")
	target := flag.String("target", "", "Broker resource target UUID for the Azure Windows VM")
	certPath := flag.String("cert", "", "VM server certificate PEM file")
	tokenPath := flag.String("token-file", "", "existing Runtime API token file")
	binaryPath := flag.String("exe", "", "compiled Windows EXE")
	timeout := flag.Int("timeout", 30, "execution timeout in seconds (1-300)")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(errors.New("unexpected arguments"))
	}
	if err := run(*vmURL, *brokerURL, *target, *certPath, *tokenPath, *binaryPath, *timeout); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func run(rawURL, brokerURL, target, certPath, tokenPath, binaryPath string, timeout int) (runErr error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || (u.Port() != "" && u.Port() != "443") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("VM URL must be https://<public-ip>[:443]")
	}
	broker, err := url.Parse(brokerURL)
	if err != nil || broker.Scheme != "https" || broker.Hostname() == "" || broker.User != nil || broker.Opaque != "" || broker.RawQuery != "" || broker.Fragment != "" {
		return errors.New("Broker URL must be an HTTPS API base URL")
	}
	targetID, err := uuid.Parse(target)
	if err != nil || targetID == uuid.Nil {
		return errors.New("target must be a Broker resource target UUID")
	}
	if timeout < 1 || timeout > 300 {
		return errors.New("timeout must be 1-300 seconds")
	}
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return errors.New("VM certificate file contains no certificate")
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 32 || strings.ContainsAny(token, "\r\n\t ") {
		return errors.New("invalid Runtime API token")
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
		return errors.New("EXE must be a regular file of 1-67108864 bytes")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Timeout:   3 * time.Minute,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+180)*time.Second)
	defer cancel()
	id := uuid.NewString()
	brokerEndpoint := strings.TrimRight(brokerURL, "/") + "/v1/runtime/windows-vms/" + targetID.String() + "/execution-events"
	brokerClient := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := reportBrokerEvent(brokerClient, brokerEndpoint, token, id, "started", "", nil); err != nil {
		// A lost response can leave a committed started event behind.
		_ = reportBrokerEvent(brokerClient, brokerEndpoint, token, id, "finished", "unreachable", nil)
		return fmt.Errorf("Broker started event: %w", err)
	}
	finishResult := "unreachable"
	var finishExitCode *int
	finished := false
	defer func() {
		if !finished {
			if err := reportBrokerEvent(brokerClient, brokerEndpoint, token, id, "finished", finishResult, finishExitCode); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("Broker finished event: %w", err))
			}
		}
	}()
	endpoint := strings.TrimRight(rawURL, "/") + "/v1/executions/" + id
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, file)
	if err != nil {
		return err
	}
	request.ContentLength = info.Size()
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Content-SHA256", hex.EncodeToString(hash.Sum(nil)))
	request.Header.Set("X-Timeout-Seconds", fmt.Sprint(timeout))
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	if err := expectStatus(response, http.StatusAccepted); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err = client.Do(request)
		if err != nil {
			return err
		}
		if response.StatusCode == http.StatusAccepted {
			response.Body.Close()
			continue
		}
		if response.StatusCode != http.StatusOK {
			return expectStatus(response, http.StatusOK)
		}
		var result struct {
			ExecutionID     string `json:"execution_id"`
			Status          string `json:"status"`
			ExitCode        *int   `json:"exit_code"`
			StdoutBase64    string `json:"stdout_base64"`
			StderrBase64    string `json:"stderr_base64"`
			OutputTruncated bool   `json:"output_truncated"`
			DurationMS      int64  `json:"duration_ms"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result)
		response.Body.Close()
		if decodeErr != nil || result.ExecutionID != id {
			return errors.New("invalid executor result")
		}
		switch result.Status {
		case "succeeded", "failed", "timeout":
			if result.Status == "succeeded" && result.ExitCode != nil && *result.ExitCode != 0 {
				return errors.New("invalid executor exit code")
			}
		default:
			return errors.New("invalid executor status")
		}
		finishResult, finishExitCode = result.Status, result.ExitCode
		if err := reportBrokerEvent(brokerClient, brokerEndpoint, token, id, "finished", finishResult, finishExitCode); err != nil {
			return fmt.Errorf("Broker finished event: %w", err)
		}
		finished = true
		encoded, _ := json.Marshal(result)
		fmt.Println(string(encoded))
		request, err = http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err = client.Do(request)
		if err != nil {
			return err
		}
		if err := expectStatus(response, http.StatusNoContent); err != nil {
			return err
		}
		if result.Status != "succeeded" {
			return fmt.Errorf("EXE finished with status %s", result.Status)
		}
		return nil
	}
}

func reportBrokerEvent(client *http.Client, endpoint, token, executionID, event, result string, exitCode *int) error {
	encoded, _ := json.Marshal(struct {
		ExecutionID string `json:"execution_id"`
		Event       string `json:"event"`
		Result      string `json:"result,omitempty"`
		ExitCode    *int   `json:"exit_code,omitempty"`
	}{executionID, event, result, exitCode})
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("Broker returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	var receipt struct {
		ExecutionID string `json:"execution_id"`
		VMState     string `json:"vm_state"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&receipt); err != nil {
		return fmt.Errorf("invalid Broker event response: %w", err)
	}
	wantState := "RUNNING"
	if event == "finished" {
		wantState = "RESET_REQUIRED"
	}
	if receipt.ExecutionID != executionID || receipt.VMState != wantState {
		return errors.New("Broker did not confirm the expected VM state")
	}
	return nil
}

func expectStatus(response *http.Response, expected int) error {
	defer response.Body.Close()
	if response.StatusCode == expected {
		return nil
	}
	message, _ := io.ReadAll(io.LimitReader(response.Body, 512))
	return fmt.Errorf("executor API returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
}
