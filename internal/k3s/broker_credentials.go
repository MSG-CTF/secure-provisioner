package k3s

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"k8s.io/client-go/tools/clientcmd"
)

type brokerCredential struct {
	SchemaVersion int       `json:"schema_version"`
	ResourceID    string    `json:"resource_target_id"`
	TargetID      string    `json:"target_id"`
	ServerURL     string    `json:"server_url"`
	Kubeconfig    string    `json:"kubeconfig_base64"`
	Fingerprint   string    `json:"client_certificate_fingerprint_sha256"`
	NotAfter      time.Time `json:"client_certificate_not_after"`
}

func brokerError(code string) error { return errors.New(code) }

func brokerUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && value == id.String()
}

func brokerHTTPS(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(value, "\r\n\\") {
		return nil, brokerError("BROKER_INVALID_HTTPS_ENDPOINT")
	}
	return u, nil
}

func brokerJSON(raw []byte, out any, strict bool) error {
	if err := rejectDuplicateRegistryJSONKeys(bytes.NewReader(raw)); err != nil {
		return brokerError("BROKER_INVALID_JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		d.DisallowUnknownFields()
	}
	if err := d.Decode(out); err != nil {
		return brokerError("BROKER_INVALID_JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return brokerError("BROKER_INVALID_JSON")
	}
	return nil
}

// Verify before constructing client-go clients: exec plugins, local files,
// impersonation and proxy settings must never be activated by a credential.
func verifiedBrokerConfig(credential brokerCredential, checkExpiry bool) ([]byte, error) {
	if credential.SchemaVersion != 1 || !brokerUUID(credential.ResourceID) || (credential.TargetID != "" && !brokerUUID(credential.TargetID)) {
		return nil, brokerError("BROKER_INVALID_IDENTITY")
	}
	server, err := brokerHTTPS(credential.ServerURL)
	if err != nil || server.Port() != "6443" || (server.Path != "" && server.Path != "/") {
		return nil, brokerError("BROKER_INVALID_K3S_ENDPOINT")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(credential.Kubeconfig)
	if err != nil || len(raw) == 0 || len(raw) > 512*1024 {
		return nil, brokerError("BROKER_INVALID_KUBECONFIG")
	}
	config, err := clientcmd.Load(raw)
	if err != nil || len(config.Clusters) != 1 || len(config.AuthInfos) != 1 || len(config.Contexts) != 1 {
		return nil, brokerError("BROKER_INVALID_KUBECONFIG")
	}
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil, brokerError("BROKER_INVALID_KUBECONFIG")
	}
	cluster, auth := config.Clusters[context.Cluster], config.AuthInfos[context.AuthInfo]
	if cluster == nil || auth == nil || cluster.Server != credential.ServerURL || cluster.InsecureSkipTLSVerify || cluster.CertificateAuthority != "" || len(cluster.CertificateAuthorityData) == 0 || cluster.ProxyURL != "" || cluster.TLSServerName != "" || len(cluster.Extensions) != 0 || len(config.Extensions) != 0 || len(context.Extensions) != 0 ||
		auth.Exec != nil || auth.AuthProvider != nil || auth.Token != "" || auth.TokenFile != "" || auth.Username != "" || auth.Password != "" || auth.Impersonate != "" || auth.ImpersonateUID != "" || len(auth.ImpersonateGroups) != 0 || len(auth.ImpersonateUserExtra) != 0 || auth.ClientCertificate != "" || auth.ClientKey != "" || len(auth.Extensions) != 0 {
		return nil, brokerError("BROKER_UNSAFE_KUBECONFIG")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cluster.CertificateAuthorityData) {
		return nil, brokerError("BROKER_INVALID_CA")
	}
	pair, err := tls.X509KeyPair(auth.ClientCertificateData, auth.ClientKeyData)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, brokerError("BROKER_INVALID_CLIENT_CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, brokerError("BROKER_INVALID_CLIENT_CERTIFICATE")
	}
	fingerprint := sha256.Sum256(cert.Raw)
	if credential.Fingerprint != hex.EncodeToString(fingerprint[:]) || !credential.NotAfter.Equal(cert.NotAfter) || (checkExpiry && (time.Now().Before(cert.NotBefore) || !time.Now().Add(5*time.Minute).Before(cert.NotAfter))) {
		return nil, brokerError("BROKER_CERTIFICATE_METADATA_MISMATCH")
	}
	return raw, nil
}
