package k3s

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBackendFlagFileIsReadOnlyAndContainerScoped(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers[0].SecretRef = testBackendSecretRef
	command.Containers[0].RequiresFlag = true
	command.Containers[0].FlagFilePath = "/home/ctf/flag.txt"
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	err = addSecretResources(context.Background(), &resources, command, fixedTestSecretResolver{values: map[string]string{"FLAG": testBackendFlag, "PRIVATE_KEY": "test-only"}})
	if err != nil {
		t.Fatal(err)
	}
	pod := resources.Deployments[0].Spec.Template.Spec
	volume := pod.Volumes[len(pod.Volumes)-1].Secret
	if volume == nil || volume.SecretName != environmentSecretName || len(volume.Items) != 1 || volume.Items[0].Key != command.Containers[0].Name+".FLAG" || *volume.DefaultMode != 0440 {
		t.Fatalf("unexpected FLAG projection: %+v", volume)
	}
	mount := pod.Containers[0].VolumeMounts[len(pod.Containers[0].VolumeMounts)-1]
	if !mount.ReadOnly || mount.SubPath != "flag" || mount.MountPath != command.Containers[0].FlagFilePath || *pod.SecurityContext.FSGroup != *pod.SecurityContext.RunAsGroup {
		t.Fatalf("unexpected FLAG mount: %+v", mount)
	}
	other := resources.Deployments[1].Spec.Template.Spec
	for _, v := range other.Volumes {
		if v.Secret != nil {
			t.Fatal("FLAG reached a companion Pod")
		}
	}
	encoded, _ := json.Marshal(resources.Deployments)
	if strings.Contains(string(encoded), testBackendFlag) {
		t.Fatal("FLAG leaked into Deployment")
	}
	changed := command
	changed.Containers = append(changed.Containers[:0:0], command.Containers...)
	changed.Containers[0].FlagFilePath = "/flag"
	otherResources, err := BuildResourceSet(validCluster("aws-dev"), changed)
	if err != nil {
		t.Fatal(err)
	}
	if resources.ExpectedSpecHashes[command.Containers[0].Name] == otherResources.ExpectedSpecHashes[command.Containers[0].Name] {
		t.Fatal("FLAG path missing from immutable spec hash")
	}
}

func TestFlagFileRejectsUnsafeOrUnboundStoredCommands(t *testing.T) {
	for _, filename := range []string{"/etc/passwd", "/proc/self/environ", "/home/ctf/../flag.txt", "/tmp/run", "/", "flag.txt"} {
		t.Run(filename, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			command.Containers[0].SecretRef = testBackendSecretRef
			command.Containers[0].RequiresFlag = true
			command.Containers[0].FlagFilePath = filename
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			if err := addSecretResources(context.Background(), &resources, command, fixedTestSecretResolver{values: map[string]string{"FLAG": testBackendFlag}}); err == nil {
				t.Fatal("unsafe FLAG file accepted")
			}
		})
	}
}

func TestQueuedCommandCannotSkipCurrentFlagFilePolicy(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].SecretRef = testBackendSecretRef
	command.Containers[0].RequiresFlag = true
	client := readyClient(t, command)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client)
	files := map[string]string{command.Containers[0].Image: "/flag"}
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond, RequiredFlagImages: []string{command.Containers[0].Image}, RequiredFlagFiles: files})
	if err != nil {
		t.Fatal(err)
	}
	files[command.Containers[0].Image] = ""
	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "SECRET_RESOLUTION_FAILED" {
		t.Fatal("queued command bypassed file policy")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("unapproved FLAG path mutated Kubernetes")
		}
	}
}
