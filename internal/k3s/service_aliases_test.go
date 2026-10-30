package k3s

import (
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestTrustedServiceAliasesStayPrivateAndFitServiceQuota(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.PolicyRequest = isolation.Request{WorkloadProfile: isolation.WorkloadProfileWeb, Containers: command.Policy.Containers, ResourceLimits: command.Policy.ResourceLimits}
	for i := range command.PolicyRequest.Containers {
		command.PolicyRequest.Containers[i].ServiceAliases = []string{command.PolicyRequest.Containers[i].Name + "-compat"}
	}
	policy, err := isolation.NewStaticResolver().Resolve(command.PolicyRequest)
	if err != nil {
		t.Fatal(err)
	}
	command.Policy = policy
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	aliases := 0
	for _, service := range resources.Services {
		if service.Name == "web-compat" || service.Name == "internal-compat" {
			aliases++
			if service.Spec.Type != corev1.ServiceTypeClusterIP {
				t.Fatal("private service alias became public")
			}
			for _, port := range service.Spec.Ports {
				if port.NodePort != 0 {
					t.Fatal("alias received a NodePort")
				}
			}
		}
	}
	if aliases != 2 || len(resources.Services) != 4 {
		t.Fatalf("wrong services: aliases=%d total=%d", aliases, len(resources.Services))
	}
	quota := resources.ResourceQuota.Spec.Hard[corev1.ResourceServices]
	if quota.Value() != 4 {
		t.Fatal("service aliases were not included in quota")
	}
}
