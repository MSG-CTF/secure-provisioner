// afterimage-plan-check validates and renders an operator-owned plan offline.
// It has no Kubernetes client or network calls and never applies resources.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: afterimage-plan-check POLICY REQUEST")
	}
	catalog, err := httpapi.LoadImagePolicies(os.Args[1])
	must(err)
	raw, err := os.ReadFile(os.Args[2])
	must(err)
	var request httpapi.CreateWorkloadRequest
	must(json.Unmarshal(raw, &request))
	must(catalog.Apply(&request))
	must(request.Validate())
	command := request.ToCommand()
	command.Policy, err = isolation.NewStaticResolver().Resolve(command.PolicyRequest)
	must(err)
	// Secret resolution is deliberately absent. Dummy values exist only in this
	// in-memory plan; no Backend secret endpoint is called.
	for i := range command.Containers {
		command.Containers[i].SecretRef = ""
		if command.Containers[i].RequiresFlag {
			command.Containers[i].Env = map[string]string{"FLAG": "dryrun-sentinel"}
		}
	}
	cluster := k3s.Cluster{Config: k3s.ClusterConfig{TargetID: command.TargetID, Architecture: "AMD64", ExposureMode: k3s.ExposureModeNodePort, PublicGateway: "https://gateway.example.invalid", SecurityCapabilities: k3s.SecurityCapabilities{NetworkPolicyEnforced: true, SupplementalGroupsPolicyStrict: true, PodPIDLimitEnforced: true, NetworkPolicyProvider: "kube-router", DNSNamespace: "kube-system", DNSPodSelector: map[string]string{"k8s-app": "kube-dns"}, RuntimeClasses: []string{"gvisor"}}}}
	resources, err := k3s.BuildResourceSet(cluster, command)
	must(err)
	if len(resources.Deployments) != 8 || len(resources.Services) != 16 {
		panic("wrong Afterimage resource count")
	}
	public := 0
	for _, s := range resources.Services {
		if s.Spec.Type == "NodePort" {
			public++
		}
	}
	if public != 1 {
		panic("only portal may be public")
	}
	for _, d := range resources.Deployments {
		p := d.Spec.Template.Spec
		c := p.Containers[0]
		security := c.SecurityContext
		if security == nil || security.RunAsUser == nil || *security.RunAsUser != 10001 || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.Privileged != nil && *security.Privileged {
			panic("non-root baseline was relaxed")
		}
		if p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken {
			panic("API token automount enabled")
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "deployments": len(resources.Deployments), "services": len(resources.Services), "public_services": public, "network_policies": len(resources.NetworkPolicies), "cpu_millicores": command.ResourceLimits.CPUMillicores, "memory_mib": command.ResourceLimits.MemoryMiB, "applied_resources": 0, "source": "actual Runtime parser and K3s renderer"})
}
func must(err error) {
	if err != nil {
		panic(fmt.Errorf("offline plan validation: %w", err))
	}
}
