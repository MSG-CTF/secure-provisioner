package windowsruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBrokerTokenAcceptsServiceGroupReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits required")
	}
	path := filepath.Join(t.TempDir(), "broker-token")
	if err := os.WriteFile(path, []byte("broker-runtime-token-secret-value"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	cfg := RuntimeConfig{BrokerTokenFile: path}
	if _, err := cfg.ReadBrokerToken(); err != nil {
		t.Fatalf("service-group readable token rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ReadBrokerToken(); err == nil {
		t.Fatal("world-readable Broker token accepted")
	}
}

func TestConfigBoundsAndSecretsStayOutsideShare(t *testing.T) {
	root := t.TempDir()
	cfg := RuntimeConfig{BrokerURL: "https://broker.mjsec.kr/api", BrokerTokenFile: filepath.Join(root, "token"), RDP: FreeRDPConfig{WorkRoot: filepath.Join(root, "jobs"), ClientPath: filepath.Join(root, "freerdp"), XvfbPath: filepath.Join(root, "xvfb-run"), Credentials: map[string]Credential{testTarget: {PasswordFile: filepath.Join(root, "password"), ResultKeyFile: filepath.Join(root, "result-key"), AccountSID: "S-1-5-21-1-2-3-1001"}}}}
	path := filepath.Join(root, "config.json")
	write := func() {
		raw, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := got.ServiceConfig()
	if err != nil || sc.ExecutionTimeout != 180*time.Second || sc.MaxPayload != 10<<20 {
		t.Fatal(sc, err)
	}
	cfg.ExecutionTimeoutSeconds = 3601
	write()
	if _, err = LoadConfig(path); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
	cfg.ExecutionTimeoutSeconds = 0
	cfg.BrokerTokenFile = filepath.Join(cfg.RDP.WorkRoot, "token")
	write()
	if _, err = LoadConfig(path); err == nil {
		t.Fatal("shared token accepted")
	}
	cfg.BrokerTokenFile = filepath.Join(root, "token")
	cfg.BrokerURL = "http://broker.mjsec.kr/api"
	write()
	if _, err = LoadConfig(path); err == nil {
		t.Fatal("HTTP broker accepted")
	}
	if err = os.WriteFile(path, []byte(`{"password":"raw"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadConfig(path); err == nil {
		t.Fatal("unknown secret option accepted")
	}
}

func TestConfigSelectsHTTPSExecutorWithoutRDPFiles(t *testing.T) {
	root := t.TempDir()
	cfg := RuntimeConfig{BrokerURL: "https://broker.mjsec.kr/api", BrokerTokenFile: filepath.Join(root, "broker-token"), HTTPSExecutor: &HTTPSExecutorConfig{Targets: map[string]ExecutorCredential{testTarget: {TokenFile: filepath.Join(root, "executor-token"), CertificateFile: filepath.Join(root, "executor.pem")}}}}
	path := filepath.Join(root, "config.json")
	write := func() {
		raw, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	got, err := LoadConfig(path)
	if err != nil || got.HTTPSExecutor == nil || len(got.HTTPSExecutor.Targets) != 1 {
		t.Fatalf("HTTPS config rejected: %+v %v", got, err)
	}
	cfg.HTTPSExecutor.Targets[testTarget] = ExecutorCredential{TokenFile: cfg.BrokerTokenFile, CertificateFile: filepath.Join(root, "executor.pem")}
	write()
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("Broker token path reused for VM executor")
	}
}

func TestConfigSelectsBrokerMTLSWithoutStaticTargets(t *testing.T) {
	root := t.TempDir()
	cfg := RuntimeConfig{BrokerURL: "https://broker.mjsec.kr/api", BrokerTokenFile: filepath.Join(root, "broker-token"), HTTPSExecutor: &HTTPSExecutorConfig{ClientCertificateFile: filepath.Join(root, "client.crt"), ClientKeyFile: filepath.Join(root, "client.key")}}
	path := filepath.Join(root, "windows.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || got.HTTPSExecutor == nil || !got.HTTPSExecutor.UsesBrokerMTLS() {
		t.Fatalf("Broker mTLS config: %+v err=%v", got, err)
	}
}
