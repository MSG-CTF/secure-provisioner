package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

func TestBrokerConfigIsOptInAndRequiresCompleteFleetSettings(t *testing.T) {
	config, err := loadBrokerConfig(environment(nil))
	if err != nil || config.BaseURL != "" {
		t.Fatal("legacy startup changed", config, err)
	}
	dir := t.TempDir()
	values := map[string]string{
		"PROVISIONER_BROKER_TOKEN_FILE":      filepath.Join(dir, "token"),
		"PROVISIONER_BROKER_TARGET_POLICY":   filepath.Join(dir, "policy.json"),
		"PROVISIONER_BROKER_STATE_DIRECTORY": filepath.Join(dir, "state"),
	}
	config, err = loadBrokerConfig(environment(values))
	if err != nil || config.BaseURL != "https://broker.mjsec.kr/api" || config.Interval != time.Hour || config.RequestTimeout != 10*time.Second {
		t.Fatal("fleet settings", config, err)
	}
	for _, key := range []string{"PROVISIONER_BROKER_TOKEN_FILE", "PROVISIONER_BROKER_TARGET_POLICY", "PROVISIONER_BROKER_STATE_DIRECTORY"} {
		t.Run(key, func(t *testing.T) {
			old := values[key]
			delete(values, key)
			if _, err := loadBrokerConfig(environment(values)); err == nil {
				t.Fatal("incomplete discovery settings accepted")
			}
			values[key] = old
		})
	}
	values["PROVISIONER_BROKER_SYNC_INTERVAL"] = "0s"
	if _, err := loadBrokerConfig(environment(values)); err == nil {
		t.Fatal("zero refresh interval accepted")
	}
	values["PROVISIONER_BROKER_SYNC_INTERVAL"] = "30s"
	values["PROVISIONER_BROKER_REQUEST_TIMEOUT"] = "5s"
	config, err = loadBrokerConfig(environment(values))
	if err != nil || config.Interval != 30*time.Second || config.RequestTimeout != 5*time.Second {
		t.Fatal(config, err)
	}
}

type startupBrokerFactory struct{}

func (startupBrokerFactory) FromKubeconfigData([]byte) (k3s.ClientSet, error) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "observed-vm", UID: "10000000-0000-4000-8000-000000000001", Labels: map[string]string{"topology.kubernetes.io/region": "us-central1"}}, Spec: corev1.NodeSpec{ProviderID: "gce://project/us-central1-a/vm"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{Architecture: "amd64"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	return k3s.ClientSet{Kubernetes: fake.NewSimpleClientset(node), Metrics: metricsfake.NewSimpleClientset()}, nil
}

func TestBrokerApplicationStartupWarmsCacheAndSurvivesBrokerOutage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private Broker state requires the Linux Runtime filesystem")
	}
	var credential map[string]any
	var requests atomic.Int32
	var unavailable atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path != "/api/v1/runtime/k3s-credentials" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 43) {
			t.Error("incorrect startup Broker request")
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{credential}, "next_cursor": nil})
	}))
	defer server.Close()
	cert := server.Certificate()
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	encoded := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	raw, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "runtime", "clusters": []any{map[string]any{"name": "vm", "cluster": map[string]any{"server": "https://192.0.2.10:6443", "certificate-authority-data": encoded(certPEM)}}}, "users": []any{map[string]any{"name": "runtime", "user": map[string]any{"client-certificate-data": encoded(certPEM), "client-key-data": encoded(keyPEM)}}}, "contexts": []any{map[string]any{"name": "runtime", "context": map[string]any{"cluster": "vm", "user": "runtime"}}}})
	fingerprint := sha256.Sum256(cert.Raw)
	credential = map[string]any{"schema_version": 1, "resource_target_id": "00000000-0000-4000-8000-000000000001", "target_id": "10000000-0000-4000-8000-000000000001", "server_url": "https://192.0.2.10:6443", "kubeconfig_base64": encoded(raw), "client_certificate_fingerprint_sha256": hex.EncodeToString(fingerprint[:]), "client_certificate_not_after": cert.NotAfter.Format(time.RFC3339)}
	dir := t.TempDir()
	registry := filepath.Join(dir, "registry.json")
	token := filepath.Join(dir, "token")
	policy := filepath.Join(dir, "policy.json")
	for path, body := range map[string]string{registry: `{"clusters":[]}`, token: strings.Repeat("b", 43), policy: `{"enabled":true,"security_capabilities":{"network_policy_enforced":false,"supplemental_groups_policy_strict":false,"pod_pid_limit_enforced":false,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"}}}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := loadConfig(environment(map[string]string{"PROVISIONER_CLUSTER_REGISTRY": registry, "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken}))
	if err != nil {
		t.Fatal(err)
	}
	config.Broker = k3s.BrokerSyncConfig{BaseURL: server.URL + "/api", TokenFile: token, PolicyPath: policy, StateDirectory: filepath.Join(dir, "broker"), HTTPClient: server.Client(), Factory: startupBrokerFactory{}}
	app, err := newApplication(config, nil)
	if err != nil || app.syncTargets == nil {
		t.Fatal("discovery not wired into Runtime startup", err)
	}
	stateFile := filepath.Join(config.Broker.StateDirectory, "targets.json")
	before, err := os.ReadFile(stateFile)
	if err != nil || !strings.Contains(string(before), "10000000-0000-4000-8000-000000000001") || requests.Load() != 1 {
		t.Fatal("startup did not enroll the API target", err)
	}
	unavailable.Store(true)
	if _, err := newApplication(config, nil); err != nil {
		t.Fatal("Broker outage blocked restart with maintenance cache", err)
	}
	after, err := os.ReadFile(stateFile)
	if err != nil || string(after) != string(before) {
		t.Fatal("failed listing overwrote prior cached credentials", err)
	}
}

func TestBrokerRefreshStopsBeforeWorkerLifecycleReturns(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	app := &application{
		runWorker:   func(context.Context) error { <-started; return nil },
		syncTargets: func(ctx context.Context) { close(started); <-ctx.Done(); close(stopped) },
	}
	done := make(chan error, 1)
	go func() { done <- runWorkers(context.Background(), app) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-stopped:
		default:
			t.Fatal("background discovery outlived workers")
		}
	case <-time.After(time.Second):
		t.Fatal("discovery did not stop when workers stopped")
	}
}
