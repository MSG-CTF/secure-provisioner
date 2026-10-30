package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// This exercises the real Gateway/Kubernetes deletion adapters with a fake API.
// It does not substitute for a live controller or Broker reservation test.
func TestTwelveGatewayCleanupsRetainRecoveryUntilNamespaceAbsence(t *testing.T) {
	const count = 12
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	var records [count]Record
	var journals [count]*memoryJournal
	var remotes [count]*fakeRoutes
	for i := range records {
		command := provisioner.CreateWorkloadCommand{
			InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1),
			TeamID:     provisioner.TeamID(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+101)),
			TargetID:   "target", RuntimeType: provisioner.RuntimeTypeKubernetes,
		}
		namespace, err := k3s.NamespaceForInstance(command.InstanceID)
		if err != nil {
			t.Fatal(err)
		}
		uid := fmt.Sprintf("namespace-%d", i)
		_, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: types.UID(uid), ResourceVersion: "1", Labels: map[string]string{
				"app.kubernetes.io/managed-by": "secure-provisioner",
				"msgctf.io/instance-id":        command.InstanceID, "msgctf.io/team-id": string(command.TeamID),
			}}, Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{"kubernetes"}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		records[i] = Record{Command: command, Result: provisioner.CreateWorkloadResult{
			NamespaceUID: uid, RuntimeWorkloadID: k3s.RuntimeWorkloadID(command.TargetID, namespace),
		}, Phase: PhaseRouteDeleted}
		journals[i] = &memoryJournal{records: map[string]Record{command.InstanceID: records[i]}}
		remotes[i] = &fakeRoutes{}
	}
	resource := corev1.SchemeGroupVersion.WithResource("namespaces")
	deletes := make(map[string]int)
	var deleteMu sync.Mutex
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		name := action.(k8stesting.DeleteAction).GetName()
		current, err := client.Tracker().Get(resource, "", name)
		if err != nil {
			return true, nil, err
		}
		namespace := current.(*corev1.Namespace).DeepCopy()
		now := metav1.Now()
		namespace.DeletionTimestamp = &now
		deleteMu.Lock()
		deletes[name]++
		deleteMu.Unlock()
		return true, nil, client.Tracker().Update(resource, namespace, "")
	})
	registry, err := k3s.NewRegistry([]k3s.ClusterConfig{{
		TargetID: "target", Provider: k3s.ProviderLocal, Region: "local", Architecture: "amd64",
		KubeconfigPath: "unused", PublicGateway: "http://8.8.8.8", ExposureMode: k3s.ExposureModeNodePort, Enabled: true,
		SecurityCapabilities: k3s.SecurityCapabilities{
			NetworkPolicyProvider: "test", DNSNamespace: "kube-system", DNSPodSelector: map[string]string{"app": "dns"},
			NetworkPolicyEnforced: true, SupplementalGroupsPolicyStrict: true, PodPIDLimitEnforced: true,
		},
	}}, gatewayFactory{client})
	if err != nil {
		t.Fatal(err)
	}
	remove, err := k3s.NewDeleteAdapter(registry, k3s.DeleteAdapterConfig{DeleteTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	backend := &KubernetesBackend{Registry: registry, Delete: remove}
	for round := 0; round < 3; round++ {
		if round == 2 {
			for _, record := range records {
				if err := client.Tracker().Delete(resource, "", recoveryBinding(record).Namespace); err != nil {
					t.Fatal(err)
				}
			}
		}
		var workers sync.WaitGroup
		for i, record := range records {
			workers.Add(1)
			go func() {
				defer workers.Done()
				// Reconstruct the adapter on every pass, retaining its journal.
				adapter := NewAdapter(backend, remotes[i], journals[i])
				err := adapter.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: record.Command.InstanceID}, recoveryBinding(record))
				current, loadErr := journals[i].Get(ctx, record.Command.InstanceID)
				binding, recoveryErr := adapter.RecoveryBinding(ctx, record.Command.InstanceID)
				if round < 2 {
					var pending *operations.ProgressPendingError
					if !errors.As(err, &pending) || loadErr != nil || current.Phase != PhaseRouteDeleted || recoveryErr != nil || binding.NamespaceUID != record.Result.NamespaceUID {
						t.Errorf("cleanup %d lost recovery while namespace exists: error=%v phase=%s recovery=%v", i, err, current.Phase, recoveryErr)
					}
				} else if err != nil || loadErr != nil || current.Phase != PhaseDeleted || !errors.Is(recoveryErr, runtimebinding.ErrNotFound) {
					t.Errorf("cleanup %d did not complete after confirmed absence: error=%v phase=%s recovery=%v", i, err, current.Phase, recoveryErr)
				}
				if remotes[i].deletes != 0 {
					t.Errorf("cleanup %d repeated an acknowledged route deletion", i)
				}
			}()
		}
		workers.Wait()
	}
	if len(deletes) != count {
		t.Fatalf("namespace deletion count=%d want %d", len(deletes), count)
	}
	for namespace, calls := range deletes {
		if calls != 1 {
			t.Errorf("%s deletion was resubmitted %d times", namespace, calls)
		}
	}
}

type deferredLifecycleJournal struct {
	*memoryJournal
	failure error
}

func (j deferredLifecycleJournal) WithLock(context.Context, string, func(Session) error) error {
	return j.failure
}

func TestGatewayAdmissionProgressAndDatabaseFaultRemainDistinct(t *testing.T) {
	for _, admission := range []bool{true, false} {
		for _, create := range []bool{true, false} {
			t.Run(fmt.Sprintf("admission=%t/create=%t", admission, create), func(t *testing.T) {
				command := provisioner.CreateWorkloadCommand{InstanceID: "busy-instance", TargetID: "target", RuntimeType: provisioner.RuntimeTypeKubernetes,
					Containers: []provisioner.WorkloadContainer{{Name: "web", Ports: []int{8080}, Expose: true}}}
				record := Record{Command: command, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns1", RuntimeWorkloadID: "target/namespace/instance"}, Phase: PhaseRouteDeleted}
				var failure error = errors.New("database connection failed")
				wantCode := "GATEWAY_JOURNAL_UNAVAILABLE"
				if admission {
					failure = operations.NewProgressPendingError("GATEWAY_LIFECYCLE_BUSY", nil)
					wantCode = "GATEWAY_LIFECYCLE_BUSY"
				}
				journal := deferredLifecycleJournal{&memoryJournal{records: map[string]Record{command.InstanceID: record}}, failure}
				backend, remote := &fakeBackend{}, &fakeRoutes{}
				adapter := NewAdapter(backend, remote, journal)
				var err error
				if create {
					_, err = adapter.CreateWorkload(context.Background(), command)
				} else {
					err = adapter.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, recoveryBinding(record))
				}
				code, retryable := operations.ClassifyExecutionError(err)
				var pending *operations.ProgressPendingError
				if code != wantCode || !retryable || errors.As(err, &pending) != admission {
					t.Fatalf("admission and fault paths merged: code=%s retryable=%v error=%v", code, retryable, err)
				}
				current, _ := journal.Get(context.Background(), command.InstanceID)
				if current.Phase != PhaseRouteDeleted || backend.creates != 0 || backend.deletes != 0 || backend.quiesces != 0 || remote.deletes != 0 || remote.puts != 0 {
					t.Fatal("failed admission mutated workload, route or cleanup intent")
				}
			})
		}
	}
}
