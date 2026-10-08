package k3s

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestReplayCannotRunRequiredFlagImageWithoutBackendReference(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client)
	images := []string{command.Containers[0].Image}
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond, RequiredFlagImages: images})
	if err != nil {
		t.Fatal(err)
	}
	images[0] = "changed-after-construction"
	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "SECRET_RESOLUTION_FAILED" || len(client.Actions()) != 0 {
		t.Fatal("old queued FLAG command bypassed the Backend reference gate")
	}
}

func TestBackendSecretsStayInImmutableNamespaceSecret(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].SecretRef = testBackendSecretRef
	command.Containers[0].RequiresFlag = true
	command.Containers[0].Env = map[string]string{"APP_MODE": "ctf", "LITERAL": "$(APP_MODE)"}
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	before := resources.ExpectedSpecHash
	resolver := fixedTestSecretResolver{values: map[string]string{"FLAG": testBackendFlag, "INTERNAL_TOKEN": "local-token-fixture"}}
	if err := addSecretResources(context.Background(), &resources, command, resolver); err != nil {
		t.Fatal(err)
	}
	if resources.EnvSecret == nil || resources.EnvSecret.Immutable == nil || !*resources.EnvSecret.Immutable ||
		resources.EnvSecret.Namespace != resources.Namespace.Name ||
		string(resources.EnvSecret.Data["challenge.FLAG"]) != testBackendFlag {
		t.Fatal("immutable scoped Secret is missing")
	}
	env := resources.Deployment.Spec.Template.Spec.Containers[0].Env
	if len(env) != 4 || env[0].Name != "APP_MODE" || env[1].Value != "$$(APP_MODE)" ||
		env[2].ValueFrom.SecretKeyRef.Key != "challenge.FLAG" {
		t.Fatal("environment injection is incorrect")
	}
	encoded, _ := json.Marshal(command)
	deployment, _ := json.Marshal(resources.Deployment)
	if strings.Contains(string(encoded), testBackendFlag) || strings.Contains(string(deployment), testBackendFlag) {
		t.Fatal("plaintext secret escaped into command or Deployment")
	}
	if resources.ExpectedSpecHash != before {
		t.Fatal("secret resolution mutated the immutable command hash")
	}
	if quota := resources.ResourceQuota.Spec.Hard[corev1.ResourceName("count/secrets")]; quota.Value() != 1 {
		t.Fatal("Secret quota is missing")
	}
}

func TestSecretResolutionFailureCreatesNoKubernetesResources(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].SecretRef = testBackendSecretRef
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client))
	adapter.config.Secrets = fixedTestSecretResolver{err: newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)}
	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "SECRET_RESOLUTION_FAILED" {
		t.Fatal("resolution failure was lost")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			t.Fatal("a Kubernetes resource was created before secret resolution succeeded")
		}
	}
}

func TestSecretResourcesAreContainerScopedAndRequiredFlagFailsClosed(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers[0].SecretRef = testBackendSecretRef
	command.Containers[0].RequiresFlag = true
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if err := addSecretResources(context.Background(), &resources, command, fixedTestSecretResolver{values: map[string]string{"FLAG": testBackendFlag}}); err != nil {
		t.Fatal(err)
	}
	if len(resources.Deployments[0].Spec.Template.Spec.Containers[0].Env) != 1 ||
		len(resources.Deployments[1].Spec.Template.Spec.Containers[0].Env) != 0 {
		t.Fatal("secret reached a companion container")
	}
	resources, _ = BuildResourceSet(validCluster("aws-dev"), command)
	if err := addSecretResources(context.Background(), &resources, command, fixedTestSecretResolver{values: map[string]string{"INTERNAL_TOKEN": "only-token"}}); err == nil {
		t.Fatal("required FLAG was omitted")
	}
	resources, _ = BuildResourceSet(validCluster("aws-dev"), command)
	if err := addSecretResources(context.Background(), &resources, command, nil); err == nil {
		t.Fatal("missing resolver was accepted")
	}
}

func TestPlainEnvironmentChangesHashAndLegacyHashStaysStable(t *testing.T) {
	command := validCreateCommand("aws-dev")
	legacy, _ := BuildResourceSet(validCluster("aws-dev"), command)
	command.Containers[0].Env = map[string]string{"APP_MODE": "ctf"}
	changed, _ := BuildResourceSet(validCluster("aws-dev"), command)
	if legacy.ExpectedSpecHash == changed.ExpectedSpecHash {
		t.Fatal("environment was not included in immutable spec")
	}
	command.Containers[0].Env = map[string]string{"FLAG": "forbidden"}
	if _, err := BuildResourceSet(validCluster("aws-dev"), command); err == nil {
		t.Fatal("plain FLAG accepted from stored command")
	}
}
