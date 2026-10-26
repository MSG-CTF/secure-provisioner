package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultRoot   = `C:\ProgramData\MSG\windows-executor`
	maxBinarySize = 64 << 20
	maxOutputSize = 64 << 10
)

type job struct {
	ExecutionID    string `json:"execution_id"`
	SHA256         string `json:"sha256"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type result struct {
	ExecutionID     string `json:"execution_id"`
	Status          string `json:"status"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	StdoutBase64    string `json:"stdout_base64"`
	StderrBase64    string `json:"stderr_base64"`
	OutputTruncated bool   `json:"output_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

type outputLimit struct {
	mu        sync.Mutex
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	truncated bool
	limit     chan struct{}
}

type outputStream struct {
	output *outputLimit
	stderr bool
}

func (stream outputStream) Write(p []byte) (int, error) {
	out := stream.output
	out.mu.Lock()
	defer out.mu.Unlock()
	buffer := &out.stdout
	if stream.stderr {
		buffer = &out.stderr
	}
	remaining := maxOutputSize - out.stdout.Len() - out.stderr.Len()
	if remaining < len(p) {
		buffer.Write(p[:max(remaining, 0)])
		if !out.truncated {
			out.truncated = true
			close(out.limit)
		}
		return len(p), nil
	}
	buffer.Write(p)
	return len(p), nil
}

func main() {
	root := flag.String("root", defaultRoot, "executor data directory")
	version := flag.Bool("version", false, "print executor version")
	serve := flag.Bool("serve", false, "serve the executor API")
	initServer := flag.Bool("init-server", false, "create the server certificate")
	serverIP := flag.String("server-ip", "", "public IP address in the server certificate")
	tokenFile := flag.String("token-file", "", "Runtime API token file")
	tlsCert := flag.String("tls-cert", "", "server certificate PEM file")
	tlsKey := flag.String("tls-key", "", "server private key PEM file")
	flag.Parse()
	if *version {
		fmt.Println("windows-executor 0.1.0")
		return
	}
	if flag.NArg() != 0 {
		fail(errors.New("unexpected arguments"))
	}
	if *initServer {
		if err := createServerCertificate(*tlsCert, *tlsKey, *serverIP); err != nil {
			fail(err)
		}
		return
	}
	if *serve {
		if err := serveAPI(*root, *tokenFile, *tlsCert, *tlsKey); err != nil {
			fail(err)
		}
		return
	}
	if err := run(*root); err != nil {
		_ = recordFailure(*root)
		fail(err)
	}
}

func recordFailure(root string) error {
	manifest, err := os.ReadFile(filepath.Join(root, "job.json"))
	if err != nil {
		return err
	}
	var task job
	if err := json.Unmarshal(manifest, &task); err != nil {
		return err
	}
	id, err := uuid.Parse(task.ExecutionID)
	if err != nil || id.String() != task.ExecutionID {
		return errors.New("invalid execution ID")
	}
	resultPath := filepath.Join(root, "result.json")
	if _, err := os.Stat(resultPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.Marshal(result{ExecutionID: task.ExecutionID, Status: "failed", StdoutBase64: "", StderrBase64: ""})
	if err != nil {
		return err
	}
	temporary := resultPath + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, resultPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func run(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	jobPath := filepath.Join(root, "job.json")
	resultPath := filepath.Join(root, "result.json")
	if _, err := os.Lstat(resultPath); err == nil {
		return errors.New("previous result must be collected before starting another job")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := os.ReadFile(jobPath)
	if err != nil {
		return err
	}
	if len(raw) > 4096 {
		return errors.New("job manifest is too large")
	}
	var task job
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&task); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("job manifest must contain one object")
	}
	id, err := uuid.Parse(task.ExecutionID)
	if err != nil || id.String() != task.ExecutionID || task.TimeoutSeconds < 1 || task.TimeoutSeconds > 300 {
		return errors.New("invalid job identity or timeout")
	}
	if len(task.SHA256) != 64 || strings.ToLower(task.SHA256) != task.SHA256 {
		return errors.New("invalid SHA-256 digest")
	}
	if _, err := hex.DecodeString(task.SHA256); err != nil {
		return err
	}
	jobDir := filepath.Join(root, "jobs", task.ExecutionID)
	executable := filepath.Join(jobDir, "submission.exe")
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBinarySize {
		return errors.New("invalid submission executable")
	}
	file, err := os.Open(executable)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != task.SHA256 {
		return errors.New("submission checksum mismatch")
	}

	started := time.Now()
	output := &outputLimit{limit: make(chan struct{})}
	command := exec.Command(executable)
	command.Dir = jobDir
	command.Stdin = nil
	command.Stdout = outputStream{output: output}
	command.Stderr = outputStream{output: output, stderr: true}
	command.WaitDelay = 5 * time.Second
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(time.Duration(task.TimeoutSeconds) * time.Second)
	defer timer.Stop()
	status := "failed"
	select {
	case err = <-done:
		if err == nil {
			status = "succeeded"
		}
	case <-timer.C:
		status = "timeout"
		stopProcessTree(command.Process)
		<-done
	case <-output.limit:
		stopProcessTree(command.Process)
		<-done
	}
	var exitCode *int
	if status != "timeout" {
		code := command.ProcessState.ExitCode()
		exitCode = &code
	}
	output.mu.Lock()
	if output.truncated && status != "timeout" {
		status = "failed"
	}
	response := result{
		ExecutionID:     task.ExecutionID,
		Status:          status,
		ExitCode:        exitCode,
		StdoutBase64:    base64.StdEncoding.EncodeToString(output.stdout.Bytes()),
		StderrBase64:    base64.StdEncoding.EncodeToString(output.stderr.Bytes()),
		OutputTruncated: output.truncated,
		DurationMS:      time.Since(started).Milliseconds(),
	}
	output.mu.Unlock()
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	temporary := resultPath + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, resultPath)
}

func stopProcessTree(process *os.Process) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "taskkill.exe", "/PID", fmt.Sprint(process.Pid), "/T", "/F")
	_ = command.Run()
	_ = process.Kill()
}
