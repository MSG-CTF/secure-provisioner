package k3s

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func isolatedCleanupConfig(t *testing.T) *rest.Config {
	t.Helper()
	path := os.Getenv("PROVISIONER_TEST_CLEANUP_KUBECONFIG")
	if path == "" {
		t.Skip("set an isolated loopback K3s kubeconfig to run this test")
	}
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(config.Host)
	if err != nil || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		t.Fatal("cleanup test refuses non-loopback Kubernetes endpoints")
	}
	config.QPS, config.Burst = 20, 40
	return config
}

type cleanupRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip cleanupRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// This test refuses non-loopback clusters. It exercises actual Kubernetes
// resource deletion, not a deployed Scheduler/Broker or challenge application.
func TestIsolatedNamespaceContentCleanup(t *testing.T) {
	config := isolatedCleanupConfig(t)
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bindings := make([]runtimebinding.Binding, 0, 12)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, binding := range bindings {
			uid := types.UID(binding.NamespaceUID)
			_ = client.CoreV1().Namespaces().Delete(cleanup, binding.Namespace, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		}
	})
	for range 12 {
		binding, namespace, objects := terminatingContentFixture()
		binding.InstanceID = uuid.NewString()
		binding.TeamID = provisioner.TeamID(uuid.NewString())
		binding.Namespace, _ = NamespaceForInstance(binding.InstanceID)
		binding.RuntimeWorkloadID = RuntimeWorkloadID(binding.TargetID, binding.Namespace)
		namespace.Name, namespace.UID, namespace.ResourceVersion = binding.Namespace, "", ""
		namespace.DeletionTimestamp, namespace.Spec.Finalizers = nil, nil
		namespace.Labels = ownershipLabels(provisioner.CreateWorkloadCommand{InstanceID: binding.InstanceID, TeamID: binding.TeamID})
		created, err := client.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		binding.NamespaceUID = string(created.UID)
		bindings = append(bindings, binding)
		for _, object := range objects[1:] {
			metadata, _ := meta.Accessor(object)
			metadata.SetNamespace(binding.Namespace)
			metadata.SetUID("")
			metadata.SetResourceVersion("")
			metadata.SetLabels(namespace.Labels)
			switch value := object.(type) {
			case *corev1.Secret:
				_, err = client.CoreV1().Secrets(binding.Namespace).Create(ctx, value, metav1.CreateOptions{})
			case *corev1.ServiceAccount:
				_, err = client.CoreV1().ServiceAccounts(binding.Namespace).Create(ctx, value, metav1.CreateOptions{})
			case *corev1.ResourceQuota:
				value.Spec.Hard = corev1.ResourceList{"count/secrets": resource.MustParse("2")}
				_, err = client.CoreV1().ResourceQuotas(binding.Namespace).Create(ctx, value, metav1.CreateOptions{})
			case *corev1.LimitRange:
				value.Spec.Limits = []corev1.LimitRangeItem{{Type: corev1.LimitTypeContainer, Max: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}}}
				_, err = client.CoreV1().LimitRanges(binding.Namespace).Create(ctx, value, metav1.CreateOptions{})
			case *networkingv1.NetworkPolicy:
				_, err = client.NetworkingV1().NetworkPolicies(binding.Namespace).Create(ctx, value, metav1.CreateOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	// Seeding is test setup, not lifecycle traffic. Start the adapter's normal
	// 20 QPS / 40 burst client after setup, and apply the production Gateway's
	// eight-callback admission limit to each two-second cleanup step.
	var requestMu sync.Mutex
	requests := map[string]int{}
	childDeletes := 0
	config.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		return cleanupRoundTripper(func(request *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(request)
			parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
			for i, part := range parts {
				if part != "namespaces" {
					continue
				}
				resource := "namespaces"
				if i+2 < len(parts) {
					resource = parts[i+2]
				}
				requestMu.Lock()
				requests[request.Method+" "+resource]++
				if request.Method == http.MethodDelete && resource != "namespaces" && err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
					childDeletes++
				}
				requestMu.Unlock()
				break
			}
			return response, err
		})
	}
	clients, err := lifecycleClients(config)
	if err != nil {
		t.Fatal(err)
	}
	adapter := deleteTestAdapter(t, clients.Kubernetes)
	admission := make(chan struct{}, 8)
	var workers sync.WaitGroup
	var resultMu sync.Mutex
	seconds := make([]float64, 0, len(bindings))
	for _, binding := range bindings {
		workers.Add(1)
		go func() {
			defer workers.Done()
			started := time.Now()
			for ctx.Err() == nil {
				select {
				case admission <- struct{}{}:
				case <-ctx.Done():
					t.Error("cleanup admission exceeded the test deadline")
					return
				}
				step, stop := context.WithTimeout(ctx, 2*time.Second)
				err := adapter.DeleteStoppedWorkload(step, deleteCommand(binding), binding)
				stop()
				<-admission
				if err == nil {
					if _, lookup := client.CoreV1().Namespaces().Get(ctx, binding.Namespace, metav1.GetOptions{}); !apierrors.IsNotFound(lookup) {
						t.Errorf("cleanup succeeded before namespace absence: %v", lookup)
						return
					}
					resultMu.Lock()
					seconds = append(seconds, time.Since(started).Seconds())
					resultMu.Unlock()
					return
				}
				var pending *operations.ProgressPendingError
				if !errors.As(err, &pending) {
					t.Errorf("isolated cleanup failed: %v; cause: %v", err, errors.Unwrap(err))
					return
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
			t.Error("isolated cleanup did not finish within the test deadline")
		}()
	}
	workers.Wait()
	if len(seconds) != 12 {
		t.Fatalf("completed %d/12 isolated cleanups", len(seconds))
	}
	result, _ := json.Marshal(map[string]any{"namespaces": len(seconds), "delete_seconds": seconds, "cluster": "isolated loopback K3s", "production_test": false,
		"api_requests": requests, "successful_preparation_deletes": childDeletes})
	t.Log("ISOLATED_NAMESPACE_CLEANUP=" + string(result))
}
