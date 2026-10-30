package k3s

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Regression: treating the Broker identity URI as a file prevents exec even
// though node/pod requests succeed with the inline mTLS credential.
func TestImageAgentUsesBrokerCredentialForExecAfterSyncAndRestore(t *testing.T) {
	f := newBrokerFixture(t)
	block, _ := pem.Decode([]byte(f.key))
	issuer, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "broker-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: f.expiry, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &issuer.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	f.certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	fingerprint := sha256.Sum256(rootDER)
	f.fingerprint = hex.EncodeToString(fingerprint[:])
	const agentImage = "ghcr.io/msg-ctf/runtime-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	n := imageprep.Node{TargetID: brokerNode1, UID: brokerNode1, Name: "broker-agent-node", MachineID: "machine-a", BootID: "boot-a", Architecture: "AMD64"}
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.Name, UID: brokerNode1, Labels: map[string]string{"topology.kubernetes.io/region": "us-central1"}}, Spec: corev1.NodeSpec{ProviderID: "gce://project/us-central1-a/vm"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{MachineID: n.MachineID, BootID: n.BootID, Architecture: "amd64", OperatingSystem: "linux"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent-a", Namespace: "runtime-system", UID: "agent-pod", Labels: map[string]string{"app.kubernetes.io/name": "runtime-image-agent"}}, Spec: corev1.PodSpec{NodeName: n.Name, Containers: []corev1.Container{{Name: "agent", Image: agentImage}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	var execs atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/nodes":
			_ = json.NewEncoder(w).Encode(corev1.NodeList{Items: []corev1.Node{node}})
		case "/api/v1/nodes/" + n.Name:
			_ = json.NewEncoder(w).Encode(node)
		case "/api/v1/namespaces/runtime-system/pods":
			_ = json.NewEncoder(w).Encode(corev1.PodList{Items: []corev1.Pod{pod}})
		case "/api/v1/namespaces/runtime-system/pods/agent-a/exec":
			if r.Method != http.MethodPost || r.URL.Query().Get("container") != "agent" || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "broker-test" {
				t.Error("agent exec did not retain the selected mTLS identity and container")
			}
			execs.Add(1)
			// Reject the upgrade deliberately; the regression concerns reaching
			// the authenticated endpoint, not simulating Kubernetes streams.
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(metav1.Status{Status: "Failure", Reason: metav1.StatusReasonForbidden, Code: 403})
		default:
			http.NotFound(w, r)
		}
	}))
	block, _ = pem.Decode([]byte(f.certificate))
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(f.certificate))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.config.Factory = brokerFactoryFunc(func(raw []byte) (ClientSet, error) {
		config, err := clientcmd.RESTConfigFromKubeConfig(raw)
		if err != nil {
			return ClientSet{}, err
		}
		// Substitute only the external API endpoint with the in-process server;
		// preserve hostname verification, CA, client certificate and private key.
		config.Host = server.URL
		return lifecycleClients(config)
	})
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if result, err := f.controller().Sync(context.Background()); err != nil || result.Added != 1 {
		t.Fatalf("Broker target registration failed: %+v %v", result, err)
	}
	target := imageprep.AgentTarget{TargetID: brokerNode1, NodeName: n.Name, NodeUID: n.UID, MachineID: n.MachineID, Namespace: pod.Namespace, AgentImage: agentImage, Mode: "kubernetes"}
	for _, phase := range []string{"after-sync", "after-cache-restore"} {
		registry := f.registry
		if phase == "after-cache-restore" {
			registry, _ = NewRegistry(nil, nil)
			if _, err := NewBrokerSync(registry, f.config); err != nil {
				t.Fatal(err)
			}
		}
		before := execs.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = KubernetesImageRunner(registry)(ctx, target, n, imageprep.AgentRequest{Image: agentImage, Architecture: "AMD64", Pull: false})
		cancel()
		if execs.Load() != before+1 {
			t.Fatalf("%s: Broker agent never reached its authenticated exec endpoint; virtual kubeconfig identity must not be opened as a local file", phase)
		}
	}
	// Retaining a config must not weaken the pre-existing TLS safety check.
	cluster, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil {
		t.Fatal(err)
	}
	cluster.restConfig.Insecure = true
	cluster.restConfig.CAData = nil
	f.registry.targets[brokerNode1] = cluster
	before := execs.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = KubernetesImageRunner(f.registry)(ctx, target, n, imageprep.AgentRequest{Image: agentImage, Architecture: "AMD64", Pull: false})
	if err == nil || execs.Load() != before {
		t.Fatal("insecure retained config reached the agent exec endpoint")
	}
}

func TestRegistryLookupDoesNotMutateSharedExecAuthConfiguration(t *testing.T) {
	extension := &runtime.Unknown{Raw: []byte(`{"audience":"cluster-a"}`)}
	config := &rest.Config{ExecProvider: &clientcmdapi.ExecConfig{Command: "existing-auth-helper", Config: extension}}
	registry := &Registry{targets: map[string]Cluster{"target-a": {Config: ClusterConfig{Enabled: true}, restConfig: config}}}
	copy, err := registry.LookupForCreate("target-a")
	if err != nil {
		t.Fatal(err)
	}
	if config.ExecProvider.Config != extension {
		t.Fatal("registry lookup mutated the shared exec auth extension while holding only a read lock")
	}
	copy.restConfig.ExecProvider.Command = "different-helper"
	copy.restConfig.ExecProvider.Config.(*runtime.Unknown).Raw[0] = 'x'
	if config.ExecProvider.Command != "existing-auth-helper" || extension.Raw[0] != '{' {
		t.Fatal("lookup result can mutate another consumer's authentication configuration")
	}
}
