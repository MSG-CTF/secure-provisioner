package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"time"
)

// Production uses Runtime mTLS. A VM holds only the client CA public
// certificate, never the Runtime client private key or Broker bearer token.
func executorAuthentication(tokenPath, clientCAPath string) (*executorAPI, *tls.Config, error) {
	if (tokenPath == "") == (clientCAPath == "") {
		return nil, nil, errors.New("exactly one of client-ca and token-file is required")
	}
	api := &executorAPI{}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if tokenPath != "" {
		info, err := os.Lstat(tokenPath)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return nil, nil, errors.New("Windows executor token file unavailable")
		}
		raw, err := os.ReadFile(tokenPath)
		if err != nil {
			return nil, nil, errors.New("Windows executor token file unavailable")
		}
		token := strings.TrimSpace(string(raw))
		if len(token) < 32 || strings.ContainsAny(token, "\r\n\t \x00") {
			return nil, nil, errors.New("invalid Windows executor API token")
		}
		api.tokenHash = sha256.Sum256([]byte(token))
		return api, config, nil
	}
	info, err := os.Lstat(clientCAPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 {
		return nil, nil, errors.New("Windows executor client CA file unavailable")
	}
	raw, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, nil, errors.New("Windows executor client CA file unavailable")
	}
	pool := x509.NewCertPool()
	count := 0
	for rest := bytes.TrimSpace(raw); len(rest) != 0; {
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("invalid Windows executor client CA PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return nil, nil, errors.New("invalid Windows executor client CA certificate")
		}
		pool.AddCert(cert)
		count++
		if count > 16 {
			return nil, nil, errors.New("too many Windows executor client CA certificates")
		}
		rest = bytes.TrimSpace(tail)
	}
	if count == 0 {
		return nil, nil, errors.New("Windows executor client CA certificate required")
	}
	api.requireMTLS = true
	config.ClientCAs = pool
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return api, config, nil
}
