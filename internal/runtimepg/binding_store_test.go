package runtimepg

import (
	"reflect"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func TestPostgresBindingStoreRoundTripsMultipleEndpoints(t *testing.T) {
	database := openTestDatabase(t)
	want := runtimebinding.Binding{
		InstanceID: "11111111-1111-4111-8111-111111111111", TeamID: "00000000-0000-4000-8000-000000000001", TargetID: "aws-k3s-001",
		Namespace: "instance-11111111", NamespaceUID: "namespace-uid", RuntimeWorkloadID: "aws-k3s-001/instance-11111111",
		ContainerRequirements: []isolation.ContainerRequirement{{Name: "web", Ports: []int{8080, 9000}, ExposedPorts: []int{8080}, RunAsUser: 10001}},
		Endpoints: []provisioner.WorkloadEndpoint{
			{ContainerName: "web", Port: 8080, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://203.0.113.10:30080"},
			{ContainerName: "admin", Port: 9090, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://203.0.113.10:30090"},
		},
		State: runtimebinding.StateCreated, CreatedAt: time.Unix(90, 0), UpdatedAt: time.Unix(90, 0),
	}
	if _, created, err := database.Bindings().SaveCreated(want); err != nil || !created {
		t.Fatalf("SaveCreated created=%t err=%v", created, err)
	}
	got, err := database.Bindings().Get(want.InstanceID)
	if err != nil || !reflect.DeepEqual(got.Endpoints, want.Endpoints) || !reflect.DeepEqual(got.ContainerRequirements, want.ContainerRequirements) {
		t.Fatalf("Get = %#v, %v", got, err)
	}
}
