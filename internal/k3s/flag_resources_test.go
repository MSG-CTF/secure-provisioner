package k3s

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAddFlagResourcesCreatesNamespaceSecretAndContainerReference(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseFlagCatalog([]byte(testFlagJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := addFlagResources(&resources, command, catalog); err != nil {
		t.Fatal(err)
	}
	if resources.FlagSecret == nil || resources.FlagSecret.Namespace != resources.Namespace.Name ||
		string(resources.FlagSecret.Data["challenge"]) != testFlagValue ||
		resources.FlagSecret.Type != corev1.SecretTypeOpaque {
		t.Fatal("namespace FLAG Secret is missing or incorrect")
	}
	if resources.FlagSecret.Immutable == nil || !*resources.FlagSecret.Immutable {
		t.Fatal("FLAG Secret must be immutable")
	}
	envs := resources.Deployment.Spec.Template.Spec.Containers[0].Env
	if len(envs) != 1 || envs[0].Name != "FLAG" || envs[0].ValueFrom == nil ||
		envs[0].ValueFrom.SecretKeyRef == nil || envs[0].ValueFrom.SecretKeyRef.Name != resources.FlagSecret.Name ||
		envs[0].ValueFrom.SecretKeyRef.Key != "challenge" {
		t.Fatalf("container FLAG reference = %#v", envs)
	}
	if got := resources.ResourceQuota.Spec.Hard[corev1.ResourceName("count/secrets")]; got.Value() != 1 {
		t.Fatalf("Secret quota = %s, want 1", got.String())
	}
	encoded, err := json.Marshal(resources.Deployment)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testFlagValue) {
		t.Fatal("FLAG plaintext entered Deployment")
	}
}

func TestAddFlagResourcesKeepsUnmappedWorkloadsSecretFree(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if err := addFlagResources(&resources, command, nil); err != nil {
		t.Fatal(err)
	}
	if resources.FlagSecret != nil || len(resources.Deployment.Spec.Template.Spec.Containers[0].Env) != 0 {
		t.Fatal("unmapped workload gained FLAG resources")
	}
	if got := resources.ResourceQuota.Spec.Hard[corev1.ResourceName("count/secrets")]; !got.IsZero() {
		t.Fatalf("unmapped Secret quota = %s", got.String())
	}
}

func TestAddFlagResourcesInjectsOnlyMappedContainer(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers[0].Image = testFlagImage
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseFlagCatalog([]byte(testFlagJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := addFlagResources(&resources, command, catalog); err != nil {
		t.Fatal(err)
	}
	if len(resources.Deployments[0].Spec.Template.Spec.Containers[0].Env) != 1 ||
		len(resources.Deployments[1].Spec.Template.Spec.Containers[0].Env) != 0 ||
		len(resources.FlagSecret.Data) != 1 || string(resources.FlagSecret.Data["web"]) != testFlagValue {
		t.Fatal("FLAG leaked to an unmapped companion container")
	}
}
