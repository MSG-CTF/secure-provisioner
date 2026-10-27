package windowsruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type RuntimeConfig struct {
	BrokerURL               string                `json:"broker_url"`
	BrokerTokenFile         string                `json:"broker_token_file"`
	RDP                     FreeRDPConfig         `json:"rdp"`
	HTTPSExecutor           *HTTPSExecutorConfig  `json:"https_executor,omitempty"`
	ExecutionTimeoutSeconds int                   `json:"execution_timeout_seconds"`
	ConnectTimeoutSeconds   int                   `json:"connect_timeout_seconds"`
	MaxPayloadBytes         int                   `json:"max_payload_bytes"`
	OutputLimitBytes        int                   `json:"output_limit_bytes"`
	Concurrency             int                   `json:"concurrency"`
	Checker                 *CheckerRuntimeConfig `json:"checker,omitempty"`
}

type CheckerRuntimeConfig struct {
	BackendURL       string            `json:"backend_url"`
	Backends         map[string]string `json:"backends,omitempty"`
	CheckerCommitSHA string            `json:"checker_commit_sha"`
	VMTemplateSHA256 string            `json:"vm_template_sha256"`
	DriverSHA256     string            `json:"driver_sha256"`
	ConfigVersion    string            `json:"config_version"`
}

func LoadConfig(path string) (*RuntimeConfig, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Windows runtime config requires an absolute path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Windows runtime config unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("Windows runtime config too large")
	}
	var cfg RuntimeConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid Windows runtime config JSON")
	}
	u, err := url.Parse(cfg.BrokerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("Windows broker requires an HTTPS base URL")
	}
	if !filepath.IsAbs(cfg.BrokerTokenFile) {
		return nil, errors.New("Windows broker token requires an absolute path")
	}
	if cfg.HTTPSExecutor != nil {
		if len(cfg.RDP.Credentials) != 0 {
			return nil, errors.New("Windows HTTPS executor cannot share RDP credentials")
		}
		if cfg.HTTPSExecutor.UsesBrokerMTLS() {
			if len(cfg.HTTPSExecutor.Targets) != 0 || !filepath.IsAbs(cfg.HTTPSExecutor.ClientCertificateFile) || !filepath.IsAbs(cfg.HTTPSExecutor.ClientKeyFile) || cfg.HTTPSExecutor.ClientCertificateFile == cfg.HTTPSExecutor.ClientKeyFile || cfg.HTTPSExecutor.ClientCertificateFile == cfg.BrokerTokenFile || cfg.HTTPSExecutor.ClientKeyFile == cfg.BrokerTokenFile || cfg.HTTPSExecutor.Port < 0 || cfg.HTTPSExecutor.Port > 65535 {
				return nil, errors.New("invalid Windows Broker mTLS credential reference")
			}
		} else {
			if len(cfg.HTTPSExecutor.Targets) == 0 || cfg.HTTPSExecutor.Port != 0 {
				return nil, errors.New("Windows HTTPS executor targets are required without RDP credentials")
			}
			for id, target := range cfg.HTTPSExecutor.Targets {
				if !ValidID(id) || !filepath.IsAbs(target.TokenFile) || !filepath.IsAbs(target.CertificateFile) || target.TokenFile == cfg.BrokerTokenFile || target.CertificateFile == cfg.BrokerTokenFile {
					return nil, errors.New("invalid Windows HTTPS executor credential reference")
				}
			}
		}
	} else {
		if !filepath.IsAbs(cfg.RDP.WorkRoot) || insideDirectory(cfg.RDP.WorkRoot, cfg.BrokerTokenFile) || !filepath.IsAbs(cfg.RDP.ClientPath) || !filepath.IsAbs(cfg.RDP.XvfbPath) || len(cfg.RDP.Credentials) == 0 {
			return nil, errors.New("Windows RDP executable paths and VM credentials are required")
		}
		for id, cred := range cfg.RDP.Credentials {
			if !ValidID(id) || !filepath.IsAbs(cred.PasswordFile) || insideDirectory(cfg.RDP.WorkRoot, cred.PasswordFile) || !filepath.IsAbs(cred.ResultKeyFile) || insideDirectory(cfg.RDP.WorkRoot, cred.ResultKeyFile) || !strings.HasPrefix(cred.AccountSID, "S-1-5-21-") {
				return nil, errors.New("invalid Windows VM credential reference")
			}
		}
	}
	if _, err := cfg.ServiceConfig(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
func (c RuntimeConfig) ServiceConfig() (ServiceConfig, error) {
	cfg := DefaultServiceConfig()
	if c.ExecutionTimeoutSeconds < 0 || c.ExecutionTimeoutSeconds > 3600 || c.ConnectTimeoutSeconds < 0 || c.ConnectTimeoutSeconds > 300 {
		return cfg, errors.New("Windows execution or connection timeout out of range")
	}
	if c.ExecutionTimeoutSeconds != 0 {
		cfg.ExecutionTimeout = time.Duration(c.ExecutionTimeoutSeconds) * time.Second
	}
	if c.ConnectTimeoutSeconds != 0 {
		cfg.ConnectTimeout = time.Duration(c.ConnectTimeoutSeconds) * time.Second
	}
	if c.MaxPayloadBytes != 0 {
		cfg.MaxPayload = c.MaxPayloadBytes
	}
	if c.OutputLimitBytes != 0 {
		cfg.OutputLimit = c.OutputLimitBytes
	}
	if c.Concurrency != 0 {
		cfg.Concurrency = c.Concurrency
	}
	if cfg.MaxPayload < 2 || cfg.MaxPayload > 10<<20 || cfg.OutputLimit < 1 || cfg.OutputLimit > 1<<20 || cfg.Concurrency < 1 || cfg.Concurrency > 16 {
		return cfg, errors.New("Windows payload, output, or worker limit out of range")
	}
	return cfg, nil
}
func insideDirectory(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// The deployed Runtime uses root:provisioner 0640 secrets. Group read is
// permitted, but group write/execute and all world access are not.
func privateSecretPermissions(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0037 == 0
}

// ReadBrokerToken never returns a file path or secret contents in an error.
func (c RuntimeConfig) ReadBrokerToken() (string, error) {
	info, err := os.Lstat(c.BrokerTokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || !privateSecretPermissions(info) {
		return "", errors.New("Windows broker token file must be private and regular")
	}
	raw, err := os.ReadFile(c.BrokerTokenFile)
	if err != nil {
		return "", errors.New("Windows broker token unavailable")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if token == "" || strings.ContainsAny(token, " \t\r\n\x00") {
		return "", errors.New("invalid Windows broker token")
	}
	return token, nil
}
