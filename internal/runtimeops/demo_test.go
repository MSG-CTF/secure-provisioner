package runtimeops

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestDemoServiceExposesContainerStatusAndUsage(t *testing.T) {
	service, err := NewDemoService()
	if err != nil {
		t.Fatal(err)
	}

	status, err := service.GetRuntimeStatus(context.Background(), DemoInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if status.TargetID != DemoTargetID || status.Phase != "READY" || !status.EndpointReady ||
		!status.MetricsAvailable || len(status.Containers) != 2 {
		t.Fatalf("status = %#v", status)
	}
	if status.Containers[0].Usage == nil || status.Containers[0].Usage.CPUMillicores <= 0 {
		t.Fatalf("container usage = %#v", status.Containers[0].Usage)
	}
}

func TestDemoServiceProcessesDelete(t *testing.T) {
	service, err := NewDemoService()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Run(ctx) }()

	status, err := service.GetRuntimeStatus(context.Background(), DemoInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	operation, created, err := service.EnqueueDelete(provisioner.DeleteWorkloadCommand{
		RequestID:         "demo-delete-01",
		InstanceID:        DemoInstanceID,
		TeamID:            DemoTeamID,
		RuntimeType:       provisioner.RuntimeTypeKubernetes,
		TargetID:          DemoTargetID,
		RuntimeWorkloadID: status.RuntimeWorkloadID,
		Reason:            provisioner.DeleteReasonUserRequested,
	})
	if err != nil || !created {
		t.Fatalf("EnqueueDelete() = (%#v, %t, %v)", operation, created, err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for operation.Status != operations.OperationStatusSucceeded {
		if time.Now().After(deadline) {
			t.Fatalf("operation = %#v", operation)
		}
		time.Sleep(time.Millisecond)
		operation, err = service.GetOperation(operation.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err = service.GetRuntimeStatus(context.Background(), DemoInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "TERMINATED" {
		t.Fatalf("phase = %q", status.Phase)
	}
}
