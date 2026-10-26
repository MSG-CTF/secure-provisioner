package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func createServerCertificate(certPath, keyPath, address string) error {
	ip := net.ParseIP(address)
	if ip == nil || certPath == "" || keyPath == "" {
		return errors.New("server certificate requires an IP address and certificate paths")
	}
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || cert.VerifyHostname(address) != nil {
			return errors.New("installed certificate does not match the VM IP address")
		}
		return nil
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return errors.New("incomplete server certificate; refusing to replace its identity")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: address},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return nil
}

func serveAPI(root, tokenPath, certPath, keyPath string) error {
	if root == "" || tokenPath == "" || certPath == "" || keyPath == "" {
		return errors.New("executor API requires root, token and TLS files")
	}
	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) < 32 || strings.ContainsAny(token, "\r\n\t ") {
		return errors.New("invalid Runtime API token")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	api := &executorAPI{root: root, tokenHash: sha256.Sum256([]byte(token))}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/executions/{id}", api.submit)
	mux.HandleFunc("GET /v1/executions/{id}", api.get)
	mux.HandleFunc("DELETE /v1/executions/{id}", api.remove)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := &http.Server{
		Addr: ":443", Handler: api.authorize(mux),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
		WriteTimeout: 3 * time.Minute, IdleTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return server.ListenAndServeTLS(certPath, keyPath)
}

type executorAPI struct {
	root      string
	tokenHash [32]byte
	mu        sync.Mutex
}

func (api *executorAPI) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="windows-executor"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		supplied := sha256.Sum256([]byte(strings.TrimPrefix(values[0], "Bearer ")))
		if subtle.ConstantTimeCompare(supplied[:], api.tokenHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="windows-executor"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (api *executorAPI) paths(w http.ResponseWriter, r *http.Request) (string, string, string, bool) {
	id := r.PathValue("id")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		http.Error(w, "invalid execution ID", http.StatusBadRequest)
		return "", "", "", false
	}
	return id, filepath.Join(api.root, "job.json"), filepath.Join(api.root, "result.json"), true
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("executor file exceeds size limit")
	}
	return data, nil
}

func (api *executorAPI) submit(w http.ResponseWriter, r *http.Request) {
	id, manifestPath, resultPath, ok := api.paths(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "expected application/octet-stream", http.StatusUnsupportedMediaType)
		return
	}
	digest := r.Header.Get("X-Content-SHA256")
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		http.Error(w, "invalid SHA-256", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(digest); err != nil {
		http.Error(w, "invalid SHA-256", http.StatusBadRequest)
		return
	}
	timeout, err := strconv.Atoi(r.Header.Get("X-Timeout-Seconds"))
	if err != nil || timeout < 1 || timeout > 300 {
		http.Error(w, "invalid timeout", http.StatusBadRequest)
		return
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if raw, err := readLimited(manifestPath, 4096); err == nil {
		var existing job
		if json.Unmarshal(raw, &existing) == nil && existing.ExecutionID == id && existing.SHA256 == digest && existing.TimeoutSeconds == timeout {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.Error(w, "VM already has an execution", http.StatusConflict)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "execution state unavailable", http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat(resultPath); err == nil {
		http.Error(w, "previous result has not been collected", http.StatusConflict)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "result state unavailable", http.StatusInternalServerError)
		return
	}
	jobDir := filepath.Join(api.root, "jobs", id)
	if err := os.Mkdir(jobDir, 0700); err != nil {
		http.Error(w, "could not create job directory", http.StatusInternalServerError)
		return
	}
	defer func() {
		if _, err := os.Stat(manifestPath); errors.Is(err, os.ErrNotExist) {
			_ = os.RemoveAll(jobDir)
		}
	}()
	temporary := filepath.Join(jobDir, "submission.exe.tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		http.Error(w, "could not create submission", http.StatusInternalServerError)
		return
	}
	reader := http.MaxBytesReader(w, r.Body, maxBinarySize)
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), reader)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size == 0 || hex.EncodeToString(hash.Sum(nil)) != digest {
		_ = os.Remove(temporary)
		http.Error(w, "invalid submission or checksum", http.StatusBadRequest)
		return
	}
	if err := os.Rename(temporary, filepath.Join(jobDir, "submission.exe")); err != nil {
		http.Error(w, "could not save submission", http.StatusInternalServerError)
		return
	}
	encoded, _ := json.Marshal(job{ExecutionID: id, SHA256: digest, TimeoutSeconds: timeout})
	manifestTemporary := filepath.Join(jobDir, "job.json.tmp")
	if err := os.WriteFile(manifestTemporary, encoded, 0600); err != nil {
		http.Error(w, "could not save execution", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(manifestTemporary, manifestPath); err != nil {
		http.Error(w, "could not save execution", http.StatusInternalServerError)
		return
	}
	if _, err := exec.Command("schtasks.exe", "/Run", "/TN", "MSGWindowsExecutor").CombinedOutput(); err != nil {
		_ = os.Remove(manifestPath)
		http.Error(w, "could not start executor task", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (api *executorAPI) get(w http.ResponseWriter, r *http.Request) {
	id, manifestPath, resultPath, ok := api.paths(w, r)
	if !ok {
		return
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	raw, err := readLimited(manifestPath, 4096)
	if err != nil {
		http.Error(w, "execution not found", http.StatusNotFound)
		return
	}
	var current job
	if json.Unmarshal(raw, &current) != nil || current.ExecutionID != id {
		http.Error(w, "execution not found", http.StatusNotFound)
		return
	}
	result, err := readLimited(resultPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		http.Error(w, "result unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result)
}

func (api *executorAPI) remove(w http.ResponseWriter, r *http.Request) {
	id, manifestPath, resultPath, ok := api.paths(w, r)
	if !ok {
		return
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	raw, err := readLimited(manifestPath, 4096)
	var current job
	if err != nil || json.Unmarshal(raw, &current) != nil || current.ExecutionID != id {
		http.Error(w, "execution not found", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(resultPath); err != nil {
		http.Error(w, "execution is still running", http.StatusConflict)
		return
	}
	if err := os.RemoveAll(filepath.Join(api.root, "jobs", id)); err != nil {
		http.Error(w, "could not remove execution", http.StatusInternalServerError)
		return
	}
	if err := os.Remove(resultPath); err != nil {
		http.Error(w, "could not remove result", http.StatusInternalServerError)
		return
	}
	if err := os.Remove(manifestPath); err != nil {
		http.Error(w, "could not remove manifest", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
