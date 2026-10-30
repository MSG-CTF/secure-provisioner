package k3s

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

const brokerResource1 = "00000000-0000-4000-8000-000000000001"
const brokerResource2 = "00000000-0000-4000-8000-000000000002"
const brokerNode1 = "10000000-0000-4000-8000-000000000001"
const brokerNode2 = "10000000-0000-4000-8000-000000000002"

type brokerFactoryFunc func([]byte) (ClientSet, error)

func (f brokerFactoryFunc) FromKubeconfigData(raw []byte) (ClientSet, error) { return f(raw) }

type brokerTestFactory struct {
	mu    sync.Mutex
	nodes map[string]*corev1.Node
}

func (f *brokerTestFactory) FromKubeconfigData(raw []byte) (ClientSet, error) {
	config, err := clientcmd.Load(raw)
	if err != nil {
		return ClientSet{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cluster := range config.Clusters {
		node := f.nodes[cluster.Server]
		if node == nil {
			return ClientSet{}, fmt.Errorf("unreachable test node")
		}
		return ClientSet{Kubernetes: fake.NewClientset(node.DeepCopy()), Metrics: metricsfake.NewSimpleClientset()}, nil
	}
	return ClientSet{}, fmt.Errorf("missing cluster")
}

type brokerFixture struct {
	t                *testing.T
	mu               sync.Mutex
	pages            map[string]map[string]any
	status           map[string]int
	registry         *Registry
	factory          *brokerTestFactory
	config           BrokerSyncConfig
	certificate, key string
	fingerprint      string
	expiry           time.Time
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Broker private state uses POSIX permissions on the Linux Runtime host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Truncate(time.Second).Add(24 * time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "broker-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	registry, err := NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &brokerFixture{t: t, pages: map[string]map[string]any{}, status: map[string]int{}, registry: registry, factory: &brokerTestFactory{nodes: map[string]*corev1.Node{}}, certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), fingerprint: hex.EncodeToString(fingerprint[:]), expiry: expiry}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/k3s-credentials" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 43) {
			t.Error("wrong Broker endpoint/auth")
			w.WriteHeader(401)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		cursor := r.URL.Query().Get("after")
		if status := f.status[cursor]; status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("sensitive-upstream-body"))
			return
		}
		_ = json.NewEncoder(w).Encode(f.pages[cursor])
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 43)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"enabled":true,"security_capabilities":`+completeSecurityCapabilitiesJSON+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	f.config = BrokerSyncConfig{BaseURL: server.URL + "/api", TokenFile: token, PolicyPath: policy, StateDirectory: filepath.Join(dir, "state"), Interval: time.Minute, RequestTimeout: time.Second, HTTPClient: server.Client(), Factory: f.factory}
	f.page("", nil, nil)
	return f
}

func TestBrokerNodeMetadataOverridesFleetFallbacks(t *testing.T) {
	f := newBrokerFixture(t)
	policy := `{"provider":"AWS","region":"fallback-region","enabled":true,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}`
	if err := os.WriteFile(f.config.PolicyPath, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cluster, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil || cluster.Config.Provider != ProviderGCP || cluster.Config.Region != "us-central1" {
		t.Fatal("observed node metadata ignored", cluster.Config, err)
	}
}

func TestBrokerNewGatewayTargetDerivesUpstream(t *testing.T) {
	f := newBrokerFixture(t)
	policy := `{"enabled":true,"gateway_enabled":true,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}`
	if err := os.WriteFile(f.config.PolicyPath, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.registry.GatewayTargets()[brokerNode1] != "192.0.2.10" {
		t.Fatal("Gateway did not receive automatically derived upstream")
	}
}

func TestBrokerKnownCredentialsStayUnchangedAfterRotationOrNetworkFailure(t *testing.T) {
	f := newBrokerFixture(t)
	credential := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	f.page("", []map[string]any{credential}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := f.registry.LookupForCreate(brokerNode1)
	other := newBrokerFixture(t)
	f.certificate, f.key, f.fingerprint, f.expiry = other.certificate, other.key, other.fingerprint, other.expiry
	credential = f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	f.page("", []map[string]any{credential}, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil || before.Client != after.Client {
		t.Fatal("existing credential transport was replaced", err)
	}
	info, err := os.Stat(filepath.Join(f.config.StateDirectory, "targets.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential state not private", err)
	}
	f.factory.mu.Lock()
	delete(f.factory.nodes, "https://192.0.2.10:6443")
	f.factory.mu.Unlock()
	result, err := s.Sync(context.Background())
	if err != nil || result.Skipped != 1 || result.Rejected != 0 {
		t.Fatal(result, err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("existing target eligibility changed", err)
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err != nil {
		t.Fatal("unreachable target lost maintenance transport")
	}
}

func TestBrokerFailedStateCommitPublishesNothing(t *testing.T) {
	f := newBrokerFixture(t)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	s := f.controller()
	if err := os.Mkdir(filepath.Join(f.config.StateDirectory, "targets.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("failed state write ignored")
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err == nil {
		t.Fatal("non-durable target was published")
	}
}

func TestBrokerAPIOnlyRestoreIsReadOnlyEvenBeforeFirstEnrollment(t *testing.T) {
	f := newBrokerFixture(t)
	f.config.ReadOnly = true
	s := f.controller()
	if _, err := os.Stat(f.config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("API-only restore created a state directory", err)
	}
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("read-only discovery allowed synchronization")
	}
	f.config.ReadOnly = false
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(f.config.StateDirectory, "targets.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0400); err != nil {
		t.Fatal(err)
	}
	f.registry, _ = NewRegistry(nil, nil)
	f.config.ReadOnly = true
	f.controller()
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err != nil {
		t.Fatal("read-only bridge lost cleanup client", err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err == nil {
		t.Fatal("API-only bridge enabled cached create")
	}
	after, err := os.ReadFile(statePath)
	if err != nil || string(after) != string(before) {
		t.Fatal("API-only bridge changed credential state", err)
	}
}

func TestBrokerPeriodicRegistrationWithConcurrentRegistryReaders(t *testing.T) {
	f := newBrokerFixture(t)
	f.config.Interval = 5 * time.Millisecond
	s := f.controller()
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var readers sync.WaitGroup
	for n := 0; n < 4; n++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for ctx.Err() == nil {
				_, _ = f.registry.LookupForCreate(brokerNode1)
				_, _ = f.registry.LookupForMaintenance(brokerNode1)
				_ = f.registry.GatewayTargets()
			}
		}()
	}
	registered := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(result BrokerSyncResult, err error) {
			if err == nil && result.Added == 1 {
				select {
				case registered <- struct{}{}:
				default:
				}
			}
		})
	}()
	select {
	case <-registered:
	case <-time.After(2 * time.Second):
		t.Fatal("new VM was not registered by background refresh")
	}
	cancel()
	<-done
	readers.Wait()
}

func (f *brokerFixture) credential(resource, node, host string) map[string]any {
	f.t.Helper()
	encoded := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	server := "https://" + host + ":6443"
	kubeconfig := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "runtime", "clusters": []any{map[string]any{"name": "node", "cluster": map[string]any{"server": server, "certificate-authority-data": encoded(f.certificate)}}}, "users": []any{map[string]any{"name": "runtime", "user": map[string]any{"client-certificate-data": encoded(f.certificate), "client-key-data": encoded(f.key)}}}, "contexts": []any{map[string]any{"name": "runtime", "context": map[string]any{"cluster": "node", "user": "runtime"}}}}
	raw, _ := json.Marshal(kubeconfig)
	f.factory.mu.Lock()
	f.factory.nodes[server] = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "vm-" + node, UID: types.UID(node), Labels: map[string]string{"topology.kubernetes.io/region": "us-central1"}}, Spec: corev1.NodeSpec{ProviderID: "gce://project/us-central1-a/vm"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{Architecture: "amd64"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	f.factory.mu.Unlock()
	return map[string]any{"schema_version": 1, "resource_target_id": resource, "target_id": node, "source_bootstrap_job_id": "20000000-0000-4000-8000-000000000001", "server_url": server, "kubeconfig_base64": encoded(string(raw)), "client_certificate_fingerprint_sha256": f.fingerprint, "client_certificate_not_after": f.expiry.Format(time.RFC3339), "generated_at": time.Now().UTC().Format(time.RFC3339), "uploaded_at": time.Now().UTC().Format(time.RFC3339)}
}

func (f *brokerFixture) page(cursor string, items []map[string]any, next any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if items == nil {
		items = []map[string]any{}
	}
	f.pages[cursor] = map[string]any{"items": items, "next_cursor": next}
}

func (f *brokerFixture) controller() *BrokerSync {
	f.t.Helper()
	controller, err := NewBrokerSync(f.registry, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	return controller
}

func TestBrokerRegistersAllPagesByVerifiedNodeUID(t *testing.T) {
	f := newBrokerFixture(t)
	one := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	two := f.credential(brokerResource2, brokerNode2, "192.0.2.20")
	delete(two, "target_id") // Older API responses still use the verified node UID.
	f.page("", []map[string]any{one}, "next page/1")
	f.page("next page/1", []map[string]any{two}, nil)
	result, err := f.controller().Sync(context.Background())
	if err != nil || result.Added != 2 || result.Rejected != 0 {
		t.Fatalf("sync: %+v, %v", result, err)
	}
	for _, id := range []string{brokerNode1, brokerNode2} {
		cluster, err := f.registry.LookupForCreate(id)
		if err != nil || cluster.Config.Provider != ProviderGCP || cluster.Config.Region != "us-central1" || cluster.Config.Architecture != "amd64" || cluster.Config.ExposureMode != ExposureModeNodePort {
			t.Fatalf("target %s not registered correctly: %+v %v", id, cluster.Config, err)
		}
	}
	oneCluster, _ := f.registry.LookupForCreate(brokerNode1)
	if oneCluster.Config.PublicGateway != "http://192.0.2.10" || oneCluster.Config.BrokerResourceTargetID != brokerResource1 {
		t.Fatalf("address/identity: %+v", oneCluster.Config)
	}
	if _, err := f.registry.LookupForCreate(brokerResource1); err == nil {
		t.Fatal("resource ID incorrectly used as lifecycle ID")
	}
}

func TestBrokerDisappearanceAndRestartPreserveExistingRoutes(t *testing.T) {
	f := newBrokerFixture(t)
	one := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	f.page("", []map[string]any{one}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.page("", nil, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("missing node eligibility changed", err)
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err != nil {
		t.Fatal("cleanup route lost:", err)
	}
	f.registry, _ = NewRegistry(nil, nil)
	s = f.controller()
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err != nil {
		t.Fatal("restart lost cleanup route:", err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("cached node eligibility changed on restart", err)
	}
	f.page("", []map[string]any{one}, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("reappearing node not restored:", err)
	}
}

func TestBrokerDiscoveredTargetSupportsCreateStatusAndDeleteAfterDisappearance(t *testing.T) {
	f := newBrokerFixture(t)
	credential := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	command := validCreateCommand(brokerNode1)
	client := readyClient(t, command)
	installNodePortAllocator(t, client, 31042)
	node := f.factory.nodes["https://192.0.2.10:6443"].DeepCopy()
	if _, err := client.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.config.Factory = brokerFactoryFunc(func([]byte) (ClientSet, error) {
		return ClientSet{Kubernetes: client, Metrics: metricsfake.NewSimpleClientset()}, nil
	})
	f.page("", []map[string]any{credential}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, f.registry)
	result, err := adapter.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal("discovered target create:", err)
	}
	if result.ServiceURL != "http://192.0.2.10:31042" {
		t.Fatal("wrong derived endpoint", result.ServiceURL)
	}
	namespace, _ := NamespaceForInstance(command.InstanceID)
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding := runtimebinding.Binding{InstanceID: command.InstanceID, TeamID: command.TeamID, TargetID: brokerNode1, Namespace: namespace, NamespaceUID: string(ns.UID), RuntimeWorkloadID: result.RuntimeWorkloadID, State: runtimebinding.StateCreated}
	reader, _ := NewStatusReader(f.registry)
	status, err := reader.Get(context.Background(), binding)
	if err != nil || !status.Node.Ready || status.TargetID != brokerNode1 {
		t.Fatal("discovered target status", status, err)
	}
	f.page("", nil, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	deleter, err := NewDeleteAdapterForCreateAdapter(adapter, DeleteAdapterConfig{DeleteTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatal("retired target cleanup:", err)
	}
	if _, err := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("namespace was not cleaned up", err)
	}
}

func TestBrokerIncompletePagesDoNotPublishOrRetireAnything(t *testing.T) {
	f := newBrokerFixture(t)
	one := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	f.page("", []map[string]any{one}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	two := f.credential(brokerResource2, brokerNode2, "192.0.2.20")
	f.page("", []map[string]any{two}, "failed")
	f.status["failed"] = 503
	_, err := s.Sync(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("missing/sensitive listing error:", err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("partial failure retired healthy node")
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode2); err == nil {
		t.Fatal("partial page was published")
	}
	delete(f.status, "failed")
	f.page("failed", nil, "failed")
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("repeating cursor accepted")
	}
}

func TestBrokerRejectsBadIdentityWithoutBlockingHealthyTargets(t *testing.T) {
	f := newBrokerFixture(t)
	one := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	two := f.credential(brokerResource2, brokerNode2, "192.0.2.20")
	one["target_id"] = brokerNode2
	f.page("", []map[string]any{one, two}, nil)
	result, err := f.controller().Sync(context.Background())
	if err != nil || result.Added != 1 || result.Rejected != 1 {
		t.Fatalf("sync %+v: %v", result, err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode2); err != nil {
		t.Fatal("healthy target blocked:", err)
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode1); err == nil {
		t.Fatal("unverified node enrolled")
	}
}

func TestBrokerPreservesExplicitManualDisableAndPolicy(t *testing.T) {
	f := newBrokerFixture(t)
	cfg := validClusterConfig(brokerNode1, ProviderGCP, "manual.yaml")
	cfg.Enabled = false
	f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err == nil {
		t.Fatal("manual disable overwritten")
	}
	cluster, err := f.registry.LookupForMaintenance(brokerNode1)
	if err != nil || cluster.Config.PublicGateway != "https://gateway.example.invalid" || cluster.Config.ExposureMode != ExposureModeIngressPath {
		t.Fatal("existing policy overwritten:", cluster.Config, err)
	}
}

func TestBrokerFleetGatewayDefaultPreservesStaticAndCachedOptOut(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprint("cached=", cached), func(t *testing.T) {
			f := newBrokerFixture(t)
			cfg := validClusterConfig(brokerNode1, ProviderGCP, "manual.yaml")
			cfg.ExposureMode = ExposureModeNodePort
			cfg.Gateway = &GatewayConfig{Enabled: false}
			f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
			f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
			if cached {
				f.registry, _ = NewRegistry(nil, nil)
				if _, err := f.controller().Sync(context.Background()); err != nil {
					t.Fatal(err)
				}
				state, err := loadBrokerState(f.config.StateDirectory)
				if err != nil {
					t.Fatal(err)
				}
				entry := state[brokerNode1]
				entry.Config.Gateway = &GatewayConfig{Enabled: false}
				state[brokerNode1] = entry
				if err := saveBrokerState(f.config.StateDirectory, state); err != nil {
					t.Fatal(err)
				}
				f.registry, _ = NewRegistry(nil, nil)
			}
			policy := `{"enabled":true,"gateway_enabled":true,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}`
			if err := os.WriteFile(f.config.PolicyPath, []byte(policy), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := f.controller().Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			cluster, err := f.registry.LookupForCreate(brokerNode1)
			if err != nil || cluster.Config.Gateway == nil || cluster.Config.Gateway.Enabled {
				t.Fatal("explicit per-target Gateway opt-out overwritten", cluster.Config.Gateway, err)
			}
		})
	}
}

func TestBrokerMalformedResourceIDsDoNotBlockHealthyEnrollment(t *testing.T) {
	for _, malformed := range []string{"missing", "null"} {
		t.Run(malformed, func(t *testing.T) {
			f := newBrokerFixture(t)
			credential := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
			var invalid any = map[string]any{}
			if malformed == "null" {
				invalid = nil
			}
			f.pages[""] = map[string]any{"items": []any{invalid, invalid, credential}, "next_cursor": nil}
			result, err := f.controller().Sync(context.Background())
			if err != nil || result.Added != 1 || result.Rejected != 2 {
				t.Fatalf("malformed resource IDs blocked a healthy target: %+v %v", result, err)
			}
			if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
				t.Fatal("healthy target not registered", err)
			}
		})
	}
}

func TestBrokerRejectsCredentialTamperingAndLegacyMappings(t *testing.T) {
	for _, mutation := range []string{"fingerprint", "expiry", "exec", "server", "legacy"} {
		t.Run(mutation, func(t *testing.T) {
			f := newBrokerFixture(t)
			credential := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
			switch mutation {
			case "fingerprint":
				credential["client_certificate_fingerprint_sha256"] = strings.Repeat("0", 64)
			case "expiry":
				credential["client_certificate_not_after"] = "2001-01-01T00:00:00Z"
			case "server":
				credential["server_url"] = "https://192.0.2.20:6443"
			case "exec":
				raw, _ := base64.StdEncoding.DecodeString(credential["kubeconfig_base64"].(string))
				config, _ := clientcmd.Load(raw)
				config.AuthInfos["runtime"].Exec = &clientcmdapi.ExecConfig{Command: "must-never-execute"}
				raw, _ = clientcmd.Write(*config)
				credential["kubeconfig_base64"] = base64.StdEncoding.EncodeToString(raw)
			case "legacy":
				cfg := validClusterConfig(brokerResource1, ProviderGCP, "legacy.yaml")
				f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
			}
			f.page("", []map[string]any{credential}, nil)
			result, err := f.controller().Sync(context.Background())
			if err != nil || result.Rejected != 1 {
				t.Fatalf("unsafe target accepted: %+v %v", result, err)
			}
			if _, err := f.registry.LookupForCreate(brokerNode1); err == nil {
				t.Fatal("unsafe target enabled")
			}
		})
	}
}
