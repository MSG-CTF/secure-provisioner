package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func graphTestNetwork() *isolation.WorkloadNetwork {
	return &isolation.WorkloadNetwork{
		ID: "grade-db-v1", Mode: isolation.NetworkModeExplicitTCPV1, IsolationProfile: isolation.WorkloadProfileWeb,
		Containers: []isolation.NetworkIdentity{
			{Name: "web", Image: "ghcr.io/msg-ctf/grade/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}},
			{Name: "internal", Image: "ghcr.io/msg-ctf/grade/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ports: []int{8080, 9090}},
		},
		Allow: []isolation.NetworkEdge{{From: "web", To: "internal", Port: 9090}},
	}
}

func TestWorkloadNetworkCreatesOnlyDirectedTCPRules(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	resources, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	if findNetworkPolicy(resources.NetworkPolicies, "allow-instance-internal") != nil {
		t.Fatal("broad internal policy retained")
	}
	egress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-egress-web")
	ingress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-ingress-internal")
	if len(egress.Spec.Egress) != 1 || len(ingress.Spec.Ingress) != 1 {
		t.Fatal("directed edge is missing")
	}
	if len(egress.Spec.Egress[0].Ports) != 1 || *egress.Spec.Egress[0].Ports[0].Protocol != corev1.ProtocolTCP || egress.Spec.Egress[0].Ports[0].Port.IntValue() != 9090 {
		t.Fatal("egress port is not exact TCP 9090")
	}
	if len(ingress.Spec.Ingress[0].Ports) != 1 || ingress.Spec.Ingress[0].Ports[0].Port.IntValue() != 9090 {
		t.Fatal("ingress port is not exact TCP 9090")
	}
	if egress.Spec.Egress[0].To[0].PodSelector.MatchLabels[containerNameLabel] != "internal" || ingress.Spec.Ingress[0].From[0].PodSelector.MatchLabels[containerNameLabel] != "web" {
		t.Fatal("edge endpoints are not exact")
	}
	if findNetworkPolicy(resources.NetworkPolicies, "allow-internal-egress-internal") != nil {
		t.Fatal("reverse egress unexpectedly allowed")
	}
}

func TestWorkloadNetworkRejectsSavedImageDrift(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	command.Containers[1].Image = "ghcr.io/msg-ctf/grade/db@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command); runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
		t.Fatalf("drift accepted: %v", err)
	}
}

func TestEmptyWorkloadNetworkAllowListKeepsPrivateTrafficDenied(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	graph.Allow = []isolation.NetworkEdge{}
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	resources, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range resources.NetworkPolicies {
		if policy.Name == "allow-instance-internal" || policy.Name == "allow-internal-egress-web" || policy.Name == "allow-internal-ingress-internal" {
			t.Fatalf("empty graph created internal allow: %s", policy.Name)
		}
	}
}

func TestWorkloadNetworkNodePortPublicIngressIsExplicitException(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	cluster := networkPolicyCluster(command.TargetID)
	cluster.Config.ExposureMode = ExposureModeNodePort
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	public := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-public-ingress-web")
	if public.Spec.Ingress[0].From != nil {
		t.Fatal("NodePort public ingress exception changed")
	}
	if findNetworkPolicy(resources.NetworkPolicies, "allow-instance-internal") != nil {
		t.Fatal("private full mesh reappeared")
	}
}

func TestWorkloadNetworkRejectsUnexpectedNamespacePolicyBeforeDeployment(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	resources, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareProtectionHashes(resources); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allow-instance-internal", "unexpected-allow"} {
		t.Run(name, func(t *testing.T) {
			extra := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: resources.Namespace.Name}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, Ingress: []networkingv1.NetworkPolicyIngressRule{{}}}}
			client := fake.NewSimpleClientset(resources.Namespace.DeepCopy(), extra)
			if _, err := applyResourceSet(context.Background(), client, resources); err == nil {
				t.Fatal("unexpected policy was accepted")
			}
			assertCreateActionCount(t, client, "deployments", 0)
		})
	}
}

func TestAdapterRollsBackGraphNamespaceOnUnexpectedPolicyOrListError(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	for _, name := range []string{"stale broad policy", "list error"} {
		t.Run(name, func(t *testing.T) {
			client := readyMultiContainerClient(t, command)
			if name == "stale broad policy" {
				namespace, err := NamespaceForInstance(command.InstanceID)
				if err != nil {
					t.Fatal(err)
				}
				extra := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-instance-internal", Namespace: namespace}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, Ingress: []networkingv1.NetworkPolicyIngressRule{{}}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
				if err := client.Tracker().Create(networkingv1.SchemeGroupVersion.WithResource("networkpolicies"), extra, namespace); err != nil {
					t.Fatal(err)
				}
			} else {
				client.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("list failed") })
			}
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %s, err = %v", runtimeErrorCode(t, err), err)
			}
			assertCreateActionCount(t, client, "deployments", 0)
			assertDeleteActionCount(t, client, "namespaces", 1)
		})
	}
}

func TestGraphPolicyChangeDuringReadinessFailsOperationAndRollsBackNamespaceUID(t *testing.T) {
	for _, change := range []string{"extra broad policy", "broaden expected policy"} {
		t.Run(change, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			graph := graphTestNetwork()
			for index := range command.Containers {
				command.Containers[index].Image = graph.Containers[index].Image
			}
			command.Policy.WorkloadNetwork = graph
			command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
			client := readyMultiContainerClient(t, command)
			namespace, err := NamespaceForInstance(command.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			changedDuringReadiness, checkedAfterChange := false, false
			client.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
				checkedAfterChange = changedDuringReadiness
				return false, nil, nil
			})
			// Pods are first listed by readiness, after Deployment application and
			// the policy checks preceding it. Change the tracker at this boundary.
			client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				if changedDuringReadiness {
					return false, nil, nil
				}
				policies := networkingv1.SchemeGroupVersion.WithResource("networkpolicies")
				if change == "extra broad policy" {
					extra := &networkingv1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{Name: "late-allow-all", Namespace: namespace},
						Spec: networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{},
							PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
							Ingress:     []networkingv1.NetworkPolicyIngressRule{{}}, Egress: []networkingv1.NetworkPolicyEgressRule{{}},
						},
					}
					if err := client.Tracker().Create(policies, extra, namespace); err != nil {
						return true, nil, err
					}
				} else {
					current, err := client.Tracker().Get(policies, namespace, "allow-dns")
					if err != nil {
						return true, nil, err
					}
					broadened := current.(*networkingv1.NetworkPolicy).DeepCopy()
					broadened.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
					if err := client.Tracker().Update(policies, broadened, namespace); err != nil {
						return true, nil, err
					}
				}
				changedDuringReadiness = true
				return false, nil, nil
			})
			var deletedWith *metav1.Preconditions
			client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
				deletedWith = action.(k8stesting.DeleteAction).GetDeleteOptions().Preconditions.DeepCopy()
				return false, nil, nil
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			executor, err := NewExecutor(adapter)
			if err != nil {
				t.Fatal(err)
			}
			store := operations.NewMemoryStore(func() (string, error) { return "late-network-change", nil })
			queued, _, err := store.EnqueueCreate(command, 1)
			if err != nil {
				t.Fatal(err)
			}
			worker, err := operations.NewWorker(store, executor, operations.WorkerConfig{Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			workerDone := make(chan error, 1)
			go func() { workerDone <- worker.Run(ctx) }()
			defer func() { cancel(); <-workerDone }()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			var finished operations.Operation
			for {
				finished, err = store.Get(queued.ID)
				if err != nil {
					t.Fatal(err)
				}
				if finished.Status == operations.OperationStatusFailed || finished.Status == operations.OperationStatusSucceeded {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("operation did not finish after readiness policy change")
				case <-ticker.C:
				}
			}
			if finished.Status != operations.OperationStatusFailed || finished.LastErrorCode != "RESOURCE_APPLY_FAILED" || !finished.Result.CreateCleanupCompleted || finished.Result.Create != nil || finished.CreateCheckpoint != nil {
				t.Fatalf("late policy change was not a clean failure: %#v", finished)
			}
			if !changedDuringReadiness || !checkedAfterChange {
				t.Fatal("policy change was not checked after readiness")
			}
			assertCreateActionCount(t, client, "deployments", 2)
			assertDeleteActionCount(t, client, "namespaces", 1)
			if deletedWith == nil || deletedWith.UID == nil || string(*deletedWith.UID) != "test-namespace-uid" || deletedWith.ResourceVersion == nil || *deletedWith.ResourceVersion != "1" {
				t.Fatalf("rollback lost namespace UID/resourceVersion preconditions: %#v", deletedWith)
			}
			if _, err := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatalf("rolled back namespace still exists: %v", err)
			}
		})
	}
}
