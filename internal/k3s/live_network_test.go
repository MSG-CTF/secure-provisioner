package k3s

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// 실행은 명시적으로 지정된 개발용 registry와 테스트 fixture image로 제한한다.
// CI에서 이 테스트를 선택한 경우 환경 누락은 skip이 아니라 실패다.
func TestK3sLiveInstanceNetwork(t *testing.T) {
	registryPath := strings.TrimSpace(os.Getenv("K3S_NETWORK_REGISTRY"))
	if registryPath == "" && os.Getenv("K3S_NETWORK_REQUIRED") != "true" {
		t.Skip("K3S_NETWORK_REGISTRY is not set")
	}
	for _, name := range []string{"K3S_NETWORK_REGISTRY", "K3S_NETWORK_TARGET_ID", "K3S_NETWORK_IMAGE"} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	image := os.Getenv("K3S_NETWORK_IMAGE")
	if !immutableNetworkFixture(image) {
		t.Fatal("K3S_NETWORK_IMAGE must be an immutable image@sha256 reference")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Fatal("kubectl is required for in-pod connectivity checks")
	}
	registry, err := LoadRegistry(registryPath, KubeconfigClientFactory{})
	if err != nil {
		t.Fatal("cannot load development target registry")
	}
	cluster, err := registry.Lookup(os.Getenv("K3S_NETWORK_TARGET_ID"))
	if err != nil {
		t.Fatal("development target is not registered")
	}
	if cluster.Config.ExposureMode != ExposureModeNodePort {
		t.Fatal("this test requires NODE_PORT exposure; INGRESS_PATH needs separate backend verification")
	}
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: 2 * time.Minute, PollInterval: time.Second, RollbackTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	first := createLiveNetworkInstance(t, ctx, cluster, adapter, image, "00000000-0000-4000-8000-000000000018")
	sameTeam := createLiveNetworkInstance(t, ctx, cluster, adapter, image, first.command.TeamID)
	otherTeam := createLiveNetworkInstance(t, ctx, cluster, adapter, image, "00000000-0000-4000-8000-000000000019")

	for index, instance := range []liveNetworkInstance{first, sameTeam, otherTeam} {
		t.Run(fmt.Sprintf("instance-%d-internal-and-dns", index), func(t *testing.T) {
			for _, direction := range [][2]string{{"web", "api"}, {"api", "web"}} {
				for _, destination := range []string{direction[1] + "." + instance.namespace.Name + ".svc.cluster.local", instance.pods[direction[1]].Status.PodIP} {
					for _, port := range []string{"8080", "9000"} {
						assertLiveReachability(t, ctx, cluster, instance, direction[0], net.JoinHostPort(destination, port), true)
					}
				}
			}
		})
	}
	for name, target := range map[string]liveNetworkInstance{"same-team-other-instance": sameTeam, "other-team": otherTeam} {
		t.Run(name, func(t *testing.T) {
			// 대상 내부에서 먼저 응답을 확인하여 서비스 미기동을 차단 성공으로 오인하지 않는다.
			assertLiveReachability(t, ctx, cluster, target, "web", "api:9000", true)
			for _, destination := range []string{"api." + target.namespace.Name + ".svc.cluster.local", target.pods["api"].Status.PodIP} {
				assertLiveReachability(t, ctx, cluster, first, "web", net.JoinHostPort(destination, "9000"), false)
			}
			assertLiveReachability(t, ctx, cluster, first, "web", "api:9000", true)
		})
	}
	t.Run("public-and-private-port-separation", func(t *testing.T) {
		if len(first.result.Endpoints) != 1 || first.result.Endpoints[0].ContainerName != "web" || first.result.Endpoints[0].Port != 8080 {
			t.Fatal("runtime result must contain only the public endpoint")
		}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Get(first.result.ServiceURL)
		if err != nil {
			t.Fatal("public fixture endpoint is not reachable from the test runner")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 256))
		if err != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "secure-provisioner-network-fixture" {
			t.Fatal("public endpoint did not return the controlled fixture response")
		}
		services, err := cluster.Client.CoreV1().Services(first.namespace.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal("cannot inspect instance Services")
		}
		publicPorts := 0
		for _, service := range services.Items {
			if service.Spec.Type != corev1.ServiceTypeNodePort {
				continue
			}
			for _, port := range service.Spec.Ports {
				if port.Port != 8080 || service.Spec.Selector[containerNameLabel] != "web" {
					t.Fatal("private container or port became publicly exposed")
				}
				publicPorts++
			}
		}
		if cluster.Config.ExposureMode == ExposureModeNodePort && publicPorts != 1 {
			t.Fatal("expected exactly one public NodePort")
		}
	})
	t.Log("connectivity checks completed; fixture namespace cleanup follows")
}

type liveNetworkInstance struct {
	command   provisioner.CreateWorkloadCommand
	result    provisioner.CreateWorkloadResult
	namespace *corev1.Namespace
	pods      map[string]corev1.Pod
}

func createLiveNetworkInstance(t *testing.T, ctx context.Context, cluster Cluster, adapter *Adapter, image string, teamID provisioner.TeamID) liveNetworkInstance {
	t.Helper()
	command, err := integrationCreateCommand(cluster.Config.TargetID, integrationUUID(t), "network-"+integrationUUID(t), []provisioner.WorkloadContainer{
		{Name: "web", Image: image, Ports: []int{8080, 9000}, Expose: true},
		{Name: "api", Image: image, Ports: []int{8080, 9000}},
	}, isolation.WorkloadProfileWeb, isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 64, EphemeralStorageMiB: 64})
	if err != nil {
		t.Fatal("cannot resolve fixture policy")
	}
	command.TeamID = teamID
	command.Containers[0].Expose = false
	command.Containers[0].ExposedPorts = []int{8080}
	command.PolicyRequest.Containers[0].Expose = false
	command.PolicyRequest.Containers[0].ExposedPorts = []int{8080}
	command.Policy, err = isolation.NewStaticResolver().Resolve(command.PolicyRequest)
	if err != nil || command.Policy.IsolationRef.Version != "v2" {
		t.Fatal("this test requires the STANDARD@v2 instance policy")
	}
	namespaceName, _ := NamespaceForInstance(command.InstanceID)
	var createdUID string
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		ns, getErr := cluster.Client.CoreV1().Namespaces().Get(cleanupCtx, namespaceName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return
		}
		if getErr != nil || createdUID == "" || string(ns.UID) != createdUID || !labels.SelectorFromSet(ownershipLabels(command)).Matches(labels.Set(ns.Labels)) {
			t.Error("cannot establish original fixture namespace identity for cleanup")
			return
		}
		if err := cleanupIntegrationNamespace(cleanupCtx, cluster.Client, ns); err != nil {
			t.Error("fixture namespace cleanup did not complete")
		}
	})
	result, err := adapter.CreateWorkload(ctx, command)
	createdUID = result.NamespaceUID
	if err != nil {
		t.Fatal("fixture workload creation failed; inspect the development target locally")
	}
	ns, err := cluster.Client.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil || createdUID == "" || string(ns.UID) != createdUID {
		t.Fatal("created fixture namespace is unavailable")
	}
	observed, err := cluster.Client.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(ownershipLabels(command)).String()})
	if err != nil {
		t.Fatal("cannot list fixture pods")
	}
	pods := make(map[string]corev1.Pod)
	for _, pod := range observed.Items {
		if pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning && net.ParseIP(pod.Status.PodIP) != nil {
			pods[pod.Labels[containerNameLabel]] = pod
		}
	}
	if len(pods) != 2 {
		t.Fatal("expected two running fixture pods")
	}
	return liveNetworkInstance{command: command, result: result, namespace: ns, pods: pods}
}

func assertLiveReachability(t *testing.T, ctx context.Context, cluster Cluster, instance liveNetworkInstance, source, address string, expected bool) {
	t.Helper()
	// marker는 Pod 안에서 생성한다. kubectl/exec 실패를 네트워크 차단으로 취급하지 않는다.
	const probe = `if wget -q -T 2 -t 1 -O /dev/null "http://$1/"; then printf reachable; else printf blocked; fi`
	deadline := time.Now().Add(20 * time.Second)
	blockedObservations := 0
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		command := exec.CommandContext(probeCtx, "kubectl", "--kubeconfig", cluster.Config.KubeconfigPath, "--request-timeout=8s",
			"-n", instance.namespace.Name, "exec", instance.pods[source].Name, "-c", source, "--", "sh", "-c", probe, "probe", address)
		output, err := command.Output()
		cancel()
		if err != nil {
			t.Fatal("in-pod probe execution failed; this is not evidence of network isolation")
		}
		marker := string(output)
		if marker != "reachable" && marker != "blocked" {
			t.Fatal("invalid probe result")
		}
		if !expected {
			if marker == "reachable" {
				t.Fatal("connection succeeded across an instance boundary")
			}
			blockedObservations++
			if blockedObservations == 3 {
				return
			}
			continue
		}
		if marker == "reachable" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("network expectation not met (expected reachable=%t)", expected)
		}
		select {
		case <-ctx.Done():
			t.Fatal("network verification timed out")
		case <-time.After(time.Second):
		}
	}
}

func immutableNetworkFixture(image string) bool {
	name, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || name == "" || len(digest) != 64 || strings.ContainsAny(name, " \t\r\n@") {
		return false
	}
	for _, c := range digest {
		if !('a' <= c && c <= 'f') && !('0' <= c && c <= '9') {
			return false
		}
	}
	return true
}
