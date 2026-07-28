package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"k8s.io/client-go/kubernetes/fake"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

func TestLoadConfigRequiresRegistryAndUsesSafeDefaults(t *testing.T) {
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("loadConfig() error = nil without registry")
	}

	config, err := loadConfig(environment(map[string]string{
		"PROVISIONER_CLUSTER_REGISTRY": "clusters.json",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != "127.0.0.1:8080" || config.RegistryPath != "clusters.json" ||
		config.WorkerConcurrency != 4 || config.MaxAttempts != 3 ||
		config.ReadyTimeout != 2*time.Minute || config.PollInterval != time.Second ||
		config.RollbackTimeout != 30*time.Second || config.DeleteTimeout != time.Minute {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadConfigParsesRuntimeSettingsAndRejectsInvalidValues(t *testing.T) {
	config, err := loadConfig(environment(map[string]string{
		"PROVISIONER_ADDR":               "0.0.0.0:9090",
		"PROVISIONER_CLUSTER_REGISTRY":   "clusters.json",
		"PROVISIONER_WORKER_CONCURRENCY": "2",
		"PROVISIONER_MAX_ATTEMPTS":       "5",
		"PROVISIONER_READY_TIMEOUT":      "90s",
		"PROVISIONER_POLL_INTERVAL":      "250ms",
		"PROVISIONER_ROLLBACK_TIMEOUT":   "20s",
		"PROVISIONER_DELETE_TIMEOUT":     "45s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != "0.0.0.0:9090" || config.WorkerConcurrency != 2 ||
		config.MaxAttempts != 5 || config.ReadyTimeout != 90*time.Second ||
		config.PollInterval != 250*time.Millisecond || config.RollbackTimeout != 20*time.Second ||
		config.DeleteTimeout != 45*time.Second {
		t.Fatalf("config = %#v", config)
	}

	for _, key := range []string{
		"PROVISIONER_WORKER_CONCURRENCY",
		"PROVISIONER_MAX_ATTEMPTS",
		"PROVISIONER_READY_TIMEOUT",
		"PROVISIONER_POLL_INTERVAL",
		"PROVISIONER_ROLLBACK_TIMEOUT",
		"PROVISIONER_DELETE_TIMEOUT",
	} {
		t.Run(key, func(t *testing.T) {
			values := map[string]string{
				"PROVISIONER_CLUSTER_REGISTRY": "clusters.json",
				key:                            "0",
			}
			if _, err := loadConfig(environment(values)); err == nil {
				t.Fatal("loadConfig() error = nil")
			}
		})
	}
}

func TestNewApplicationQueuesCreateThroughRuntimeService(t *testing.T) {
	registryPath := filepath.Join(t.TempDir(), "clusters.json")
	registryJSON := `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"unused","public_gateway":"https://gateway.example.test","ingress_class":"traefik","enabled":true}]}`
	if err := os.WriteFile(registryPath, []byte(registryJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(environment(map[string]string{
		"PROVISIONER_CLUSTER_REGISTRY": registryPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	app, err := newApplication(config, fakeClientFactory{})
	if err != nil {
		t.Fatal(err)
	}

	body := `{
		"request_id":"req-01",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"image":"registry.example.test/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"container_port":8080,
			"resource_limits":{"cpu_millicores":500,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	app.handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || response.Header().Get("Location") == "" {
		t.Fatalf("status = %d, headers = %#v, body = %s", response.Code, response.Header(), response.Body.String())
	}
}

func environment(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

type fakeClientFactory struct{}

func (fakeClientFactory) FromKubeconfig(string) (k3s.ClientSet, error) {
	return k3s.ClientSet{
		Kubernetes: fake.NewSimpleClientset(),
		Metrics:    metricsfake.NewSimpleClientset(),
	}, nil
}
