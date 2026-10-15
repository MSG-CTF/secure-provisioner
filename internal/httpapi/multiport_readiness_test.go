package httpapi

import "testing"

func TestCreateRequiresExplicitReadinessForMultiplePublicPorts(t *testing.T) {
	request := validCreateWorkloadRequest()
	request.Workload.Containers[0].Ports = []int{8080, 9090}

	if err := request.Validate(); err == nil {
		t.Fatal("multiple public ports accepted without explicit readiness")
	}

	request.Workload.Healthcheck = &RuntimeHealthcheck{Container: "web", Port: 8080, Path: "/healthz"}
	if err := request.Validate(); err != nil {
		t.Fatalf("explicit HTTP readiness with multiple public ports rejected: %v", err)
	}
}
