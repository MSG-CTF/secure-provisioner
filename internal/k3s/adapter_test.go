package k3s

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func TestAdapterDoesNotCreateDeploymentWhenProtectionApplyFails(t *testing.T) {
	for _, resource := range []string{"serviceaccounts", "resourcequotas", "limitranges", "networkpolicies"} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			client.PrependReactor("create", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("protection apply failure")
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
			}
			assertCreateActionCount(t, client, "deployments", 0)
			assertDeleteActionCount(t, client, "namespaces", 1)
		})
	}
}

func TestAdapterClassifiesPermanentAndTransientKubernetesApplyErrors(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name: "invalid immutable field",
			err: apierrors.NewInvalid(
				schema.GroupKind{Group: "", Kind: "ServiceAccount"},
				"challenge-runtime",
				field.ErrorList{field.Invalid(field.NewPath("metadata", "name"), "challenge-runtime", "field is immutable")},
			),
			retryable: false,
		},
		{name: "forbidden", err: apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, "challenge-runtime", errors.New("denied")), retryable: false},
		{name: "unauthorized", err: apierrors.NewUnauthorized("authentication required"), retryable: false},
		{name: "bad request", err: apierrors.NewBadRequest("malformed request"), retryable: false},
		{name: "immutable admission error", err: errors.New("spec.clusterIP: field is immutable"), retryable: false},
		{name: "conflict", err: apierrors.NewConflict(schema.GroupResource{Resource: "serviceaccounts"}, "challenge-runtime", errors.New("stale")), retryable: true},
		{name: "timeout", err: apierrors.NewTimeoutError("temporary timeout", 1), retryable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			client.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, test.err
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			var runtimeErr *RuntimeError
			if !errors.As(err, &runtimeErr) || runtimeErr.Code() != "RESOURCE_APPLY_FAILED" || runtimeErr.Retryable() != test.retryable {
				t.Fatalf("error = %#v, want RESOURCE_APPLY_FAILED retryable=%t", err, test.retryable)
			}
			if err.Error() != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("Error() = %q, want stable public code", err.Error())
			}
		})
	}
}

func TestAdapterPreflightsOwnershipForEveryDesiredResourceBeforeAnyMutation(t *testing.T) {
	for _, foreignResource := range []string{
		"namespace",
		"serviceaccount",
		"resourcequota",
		"limitrange",
		"last-networkpolicy",
		"last-deployment",
		"last-service",
		"ingress",
	} {
		t.Run(foreignResource, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			command.Policy.InternalConnections = []isolation.InternalConnection{{
				SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
			}}
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			foreign := desiredObjectForPreflightCase(t, resources, foreignResource)
			foreign.(metav1.Object).GetLabels()["msgctf.io/instance-id"] = "018f3f1e-21b8-7a91-a30b-63b3400fd999"

			client := readyMultiContainerClient(t, command)
			if err := client.Tracker().Add(foreign); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err = adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
				t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
			}
			assertNoMutations(t, client.Actions())
		})
	}
}

func TestAdapterRejectsUnapprovedSemanticMetadataBeforeAnyMutation(t *testing.T) {
	tests := []struct {
		resource string
		mutate   func(runtime.Object)
	}{
		{resource: "namespace", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetAnnotations(map[string]string{"platform.example/unapproved": "true"})
		}},
		{resource: "serviceaccount", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetAnnotations(map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/foreign"})
		}},
		{resource: "resourcequota", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetAnnotations(map[string]string{"platform.example/unapproved": "true"})
		}},
		{resource: "limitrange", mutate: func(object runtime.Object) {
			labels := object.(metav1.Object).GetLabels()
			labels["platform.example/unapproved"] = "true"
		}},
		{resource: "last-networkpolicy", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetAnnotations(map[string]string{"platform.example/unapproved": "true"})
		}},
		{resource: "last-deployment", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetFinalizers([]string{"platform.example/unapproved"})
		}},
		{resource: "last-deployment", mutate: func(object runtime.Object) {
			annotations := object.(metav1.Object).GetAnnotations()
			annotations["deployment.kubernetes.io/revision"] = "not-a-positive-decimal"
		}},
		{resource: "last-service", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "foreign"}})
		}},
		{resource: "ingress", mutate: func(object runtime.Object) {
			object.(metav1.Object).SetAnnotations(map[string]string{
				"nginx.ingress.kubernetes.io/configuration-snippet": "proxy_set_header X-Injected true;",
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.resource, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			object := desiredObjectForPreflightCase(t, resources, test.resource)
			test.mutate(object)
			client := readyMultiContainerClient(t, command)
			if err := client.Tracker().Add(object); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err = adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
				t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
			}
			assertNoMutations(t, client.Actions())
		})
	}
}

func TestAdapterRejectsTerminatingOwnedNamespaceBeforeAnyMutation(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	namespace := resources.Namespace.DeepCopy()
	now := metav1.Now()
	namespace.DeletionTimestamp = &now
	client := readyClient(t, command)
	if err := client.Tracker().Add(namespace); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertNoMutations(t, client.Actions())
}

func TestAdapterRejectsPreexistingMatchingNamespaceBeforeAnyMutation(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	preexisting := resources.Namespace.DeepCopy()
	preexisting.UID = "preexisting-namespace-uid"
	preexisting.ResourceVersion = "7"
	client := readyClient(t, command)
	if err := client.Tracker().Add(preexisting); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertNoMutations(t, client.Actions())
}

func TestAdapterRejectsProtectionReadbackHashTamperingBeforeDeployment(t *testing.T) {
	for _, resource := range []string{"serviceaccounts", "resourcequotas", "limitranges", "networkpolicies"} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			installProtectionReadbackTamper(t, client, resource, func(object runtime.Object) {
				metadata := object.(metav1.Object)
				annotations := metadata.GetAnnotations()
				annotations[specHashAnnotation] = strings.Repeat("0", 64)
				metadata.SetAnnotations(annotations)
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
			}
			if err.Error() != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("Error() = %q, want stable non-sensitive code", err.Error())
			}
			assertCreateActionCount(t, client, "deployments", 0)
		})
	}
}

func TestAdapterRejectsProtectionReadbackSpecTamperingBeforeDeployment(t *testing.T) {
	tests := []struct {
		resource string
		tamper   func(runtime.Object)
	}{
		{resource: "serviceaccounts", tamper: func(object runtime.Object) {
			object.(*corev1.ServiceAccount).AutomountServiceAccountToken = ptr.To(true)
		}},
		{resource: "resourcequotas", tamper: func(object runtime.Object) {
			object.(*corev1.ResourceQuota).Spec.Hard[corev1.ResourcePods] = *resourceQuantityBytes(99)
		}},
		{resource: "limitranges", tamper: func(object runtime.Object) {
			object.(*corev1.LimitRange).Spec.Limits = nil
		}},
		{resource: "networkpolicies", tamper: func(object runtime.Object) {
			object.(*networkingv1.NetworkPolicy).Spec.PolicyTypes = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			installProtectionReadbackTamper(t, client, test.resource, test.tamper)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
			}
			if err.Error() != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("Error() = %q, want stable non-sensitive code", err.Error())
			}
			assertCreateActionCount(t, client, "deployments", 0)
		})
	}
}

func TestAdapterRejectsProtectionReadbackSemanticMetadataTamperingBeforeDeployment(t *testing.T) {
	for _, tamper := range []struct {
		name   string
		mutate func(metav1.Object)
	}{
		{name: "cloud identity annotation", mutate: func(object metav1.Object) {
			annotations := object.GetAnnotations()
			annotations["eks.amazonaws.com/role-arn"] = "arn:aws:iam::123456789012:role/injected"
			object.SetAnnotations(annotations)
		}},
		{name: "extra label", mutate: func(object metav1.Object) {
			labels := object.GetLabels()
			labels["platform.example/injected"] = "true"
			object.SetLabels(labels)
		}},
	} {
		t.Run(tamper.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			installProtectionReadbackTamper(t, client, "serviceaccounts", func(object runtime.Object) {
				tamper.mutate(object.(metav1.Object))
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
			}
			assertCreateActionCount(t, client, "deployments", 0)
		})
	}
}

func TestAdapterRejectsIngressControllerAnnotationAddedDuringCreate(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "ingresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ingress := action.(k8stesting.CreateAction).GetObject().(*networkingv1.Ingress).DeepCopy()
		ingress.Annotations = map[string]string{
			"nginx.ingress.kubernetes.io/configuration-snippet": "proxy_set_header X-Injected true;",
		}
		if err := client.Tracker().Create(action.GetResource(), ingress, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, ingress, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterRejectsDeploymentSpecTamperingOnFreshReadback(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*appsv1.Deployment)
	}{
		{name: "init container", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "injected-init", Image: "busybox:latest"}}
		}},
		{name: "ephemeral container", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "injected-debug", Image: "busybox:latest"},
			}}
		}},
		{name: "volume", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "injected", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}},
		{name: "host setting", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.HostNetwork = true
		}},
		{name: "pod-only enable service links default", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.EnableServiceLinks = ptr.To(true)
		}},
		{name: "unmaterialized preemption policy", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.PreemptionPolicy = ptr.To(corev1.PreemptLowerPriority)
		}},
		{name: "weakened security", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true)
		}},
		{name: "missing strict supplemental groups policy", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.SecurityContext.SupplementalGroupsPolicy = nil
		}},
		{name: "changed strict supplemental groups policy", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.SecurityContext.SupplementalGroupsPolicy = ptr.To(corev1.SupplementalGroupsPolicyMerge)
		}},
		{name: "sidecar", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{Name: "injected-sidecar", Image: "busybox:latest"})
		}},
		{name: "extra port", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.Containers[0].Ports = append(
				deployment.Spec.Template.Spec.Containers[0].Ports,
				corev1.ContainerPort{ContainerPort: 31337},
			)
		}},
		{name: "weakened resources", tamper: func(deployment *appsv1.Deployment) {
			deployment.Spec.Template.Spec.Containers[0].Resources = corev1.ResourceRequirements{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			installDeploymentReadbackTamper(t, client, test.tamper)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
				t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
			}
			assertCreateActionCount(t, client, "services", 0)
			assertDeleteActionCount(t, client, "namespaces", 1)
		})
	}
}

func TestAdapterRejectsDeploymentSpecTamperingDuringReadiness(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	var mutationSeen atomic.Bool
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
			mutationSeen.Store(true)
			return false, nil, nil
		})
	}
	postMutationGets := 0
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !mutationSeen.Load() {
			return false, nil, nil
		}
		postMutationGets++
		if postMutationGets == 1 {
			return false, nil, nil
		}
		get := action.(k8stesting.GetAction)
		tracked, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), get.GetName())
		if err != nil {
			return true, nil, err
		}
		readBack := tracked.(*appsv1.Deployment).DeepCopy()
		readBack.Spec.Template.Spec.HostPID = true
		return true, readBack, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterAcceptsNamespaceNameAdmissionLabel(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		namespace := action.(k8stesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		namespace.UID = "admission-labeled-namespace-uid"
		namespace.ResourceVersion = "1"
		namespace.Labels[corev1.LabelMetadataName] = namespace.Name
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, ""); err != nil {
			return true, nil, err
		}
		return true, namespace.DeepCopy(), nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatalf("namespace admission label was rejected: %v", err)
	}
}

func TestAdapterAcceptsDocumentedDeploymentAPIServerDefaults(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	defaulted := resources.Deployment.DeepCopy()
	applyDocumentedDeploymentDefaults(defaulted)
	if !sameDeploymentSpec(defaulted, resources.Deployment) {
		t.Fatalf("fixture is not normalized by documented defaults: actual=%#v desired=%#v", defaulted.Spec, resources.Deployment.Spec)
	}
	client := readyClient(t, command)
	installDeploymentReadbackTamper(t, client, applyDocumentedDeploymentDefaults)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatalf("documented API defaults were rejected: %v", err)
	}
}

func TestDefaultImagePullPolicyMatchesKubernetesTagAndDigestRules(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name  string
		image string
		want  corev1.PullPolicy
	}{
		{name: "latest tag with digest", image: "registry.example/challenge:latest@sha256:" + digest, want: corev1.PullAlways},
		{name: "version tag with digest", image: "registry.example/challenge:v2@sha256:" + digest, want: corev1.PullIfNotPresent},
		{name: "digest without tag", image: "registry.example/challenge@sha256:" + digest, want: corev1.PullIfNotPresent},
		{name: "registry port without tag", image: "registry.example:5000/challenge", want: corev1.PullAlways},
		{name: "registry port and digest without tag", image: "registry.example:5000/challenge@sha256:" + digest, want: corev1.PullIfNotPresent},
		{name: "registry port latest tag and digest", image: "registry.example:5000/challenge:latest@sha256:" + digest, want: corev1.PullAlways},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := defaultImagePullPolicy(test.image); got != test.want {
				t.Fatalf("defaultImagePullPolicy(%q) = %q, want %q", test.image, got, test.want)
			}
		})
	}

	container := corev1.Container{
		Image:           "registry.example/challenge:latest@sha256:" + digest,
		ImagePullPolicy: corev1.PullNever,
	}
	normalizeContainerAPIDefaults(&container)
	if container.ImagePullPolicy != corev1.PullNever {
		t.Fatalf("explicit imagePullPolicy = %q, want unchanged %q", container.ImagePullPolicy, corev1.PullNever)
	}
}

func TestAdapterAcceptsCanonicalNetworkPolicyReadbackAfterAPINormalizesEmptySlices(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	installProtectionReadbackTamper(t, client, "networkpolicies", func(object runtime.Object) {
		policy := object.(*networkingv1.NetworkPolicy)
		if policy.Name == "default-deny-all" {
			policy.Spec.Ingress = nil
			policy.Spec.Egress = nil
		}
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatalf("API-normalized NetworkPolicy was rejected: %v", err)
	}
}

func TestAdapterAppliesProtectionInExactOrderBeforeMultiContainerWorkload(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}}
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := readyMultiContainerClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"create namespaces/" + resources.Namespace.Name,
		"create serviceaccounts/" + resources.ServiceAccount.Name,
		"create resourcequotas/" + resources.ResourceQuota.Name,
		"create limitranges/" + resources.LimitRange.Name,
	}
	for _, policy := range resources.NetworkPolicies {
		want = append(want, "create networkpolicies/"+policy.Name)
	}
	for _, deployment := range resources.Deployments {
		want = append(want, "create deployments/"+deployment.Name)
	}
	for _, service := range resources.Services {
		want = append(want, "create services/"+service.Name)
	}
	want = append(want, "create ingresses/"+resources.Ingress.Name)
	if got := mutationSequence(client.Actions()); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutation sequence = %#v, want %#v", got, want)
	}
}

func TestAdapterRejectsDirectRetryWithoutChangingProtectionHashes(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	firstHashes := storedProtectionHashes(t, client, command)
	if _, err := adapter.CreateWorkload(context.Background(), command); runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("second direct CreateWorkload() error = %v, want RESOURCE_OWNERSHIP_CONFLICT", err)
	}
	if got := storedProtectionHashes(t, client, command); !reflect.DeepEqual(got, firstHashes) {
		t.Fatalf("protection hashes changed on identical retry: first = %#v, retry = %#v", firstHashes, got)
	}
	for resource, want := range map[string]int{
		"serviceaccounts": 1,
		"resourcequotas":  1,
		"limitranges":     1,
		"networkpolicies": len(firstHashes) - 3,
	} {
		assertCreateActionCount(t, client, resource, want)
	}
}

func TestProtectionHashIncludesApprovedSemanticMetadata(t *testing.T) {
	command := validCreateCommand("aws-dev")
	first, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	second.ServiceAccount.Annotations = map[string]string{"msgctf.io/policy-version": "2"}
	if err := prepareProtectionHashes(first); err != nil {
		t.Fatal(err)
	}
	if err := prepareProtectionHashes(second); err != nil {
		t.Fatal(err)
	}
	if first.ServiceAccount.Annotations[specHashAnnotation] == second.ServiceAccount.Annotations[specHashAnnotation] {
		t.Fatal("protection hash did not change with approved semantic metadata")
	}
}

func TestAdapterRollsBackNamespaceWhenCreateResponseHasUnapprovedMetadata(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		namespace := action.(k8stesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		namespace.UID = "created-uid"
		namespace.Annotations = map[string]string{"platform.example/injected": "true"}
		if err := client.Tracker().Create(action.GetResource(), namespace, ""); err != nil {
			t.Fatal(err)
		}
		return true, namespace.DeepCopy(), nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertNoChildResourceMutations(t, client.Actions())
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterRoutesEachTargetToItsOwnClient(t *testing.T) {
	awsClient := readyClient(t, validCreateCommand("aws-dev"))
	gcpClient := readyClient(t, validCreateCommand("gcp-dev"))
	registry := adapterRegistry(t, []ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, awsClient, gcpClient)
	adapter := newTestAdapter(t, registry)

	if _, err := adapter.CreateWorkload(context.Background(), validCreateCommand("aws-dev")); err != nil {
		t.Fatal(err)
	}
	assertNamespaceCreateCount(t, awsClient, 1)
	assertNamespaceCreateCount(t, gcpClient, 0)

	if _, err := adapter.CreateWorkload(context.Background(), validCreateCommand("gcp-dev")); err != nil {
		t.Fatal(err)
	}
	assertNamespaceCreateCount(t, awsClient, 1)
	assertNamespaceCreateCount(t, gcpClient, 1)
}

func TestAdapterRejectsTargetWithoutRequiredIsolationCapability(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*SecurityCapabilities)
	}{
		{name: "network policy enforcement", mutate: func(capabilities *SecurityCapabilities) {
			capabilities.NetworkPolicyEnforced = false
		}},
		{name: "strict supplemental groups policy", mutate: func(capabilities *SecurityCapabilities) {
			capabilities.SupplementalGroupsPolicyStrict = false
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			config := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
			test.mutate(&config.SecurityCapabilities)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))

			_, err := adapter.CreateWorkload(context.Background(), command)
			var runtimeErr *RuntimeError
			if !errors.As(err, &runtimeErr) || runtimeErr.Code() != "TARGET_CAPABILITY_MISMATCH" {
				t.Fatalf("error = %v, want TARGET_CAPABILITY_MISMATCH", err)
			}
			if runtimeErr.Retryable() {
				t.Fatal("TARGET_CAPABILITY_MISMATCH must not be retryable")
			}
			if got := len(client.Actions()); got != 0 {
				t.Fatalf("K3s client actions = %d, want 0", got)
			}
		})
	}
}

func TestAdapterAppliesAllContainerResources(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	client := readyMultiContainerClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(
		t,
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		client,
	))

	result, err := adapter.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if got := actionCount(client, "create", "deployments"); got != 2 {
		t.Fatalf("deployment create actions = %d, want 2", got)
	}
	if got := actionCount(client, "create", "services"); got != 2 {
		t.Fatalf("service create actions = %d, want 2", got)
	}
	if got := actionCount(client, "create", "ingresses"); got != 1 {
		t.Fatalf("ingress create actions = %d, want 1", got)
	}
	if len(result.Endpoints) != 1 ||
		result.Endpoints[0].ContainerName != "web" ||
		result.ServiceURL != result.Endpoints[0].ServiceURL {
		t.Fatalf("result = %#v", result)
	}
}

func TestAdapterReturnsKubernetesAllocatedNodePortURL(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	client := readyMultiContainerClient(t, command)
	installNodePortAllocator(t, client, 31042)
	config := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
	config.ExposureMode = ExposureModeNodePort
	config.PublicGateway = "http://203.0.113.10"
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))

	result, err := adapter.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.ServiceURL != "http://203.0.113.10:31042" {
		t.Fatalf("ServiceURL = %q", result.ServiceURL)
	}
	if len(result.Endpoints) != 1 || result.Endpoints[0].ContainerName != "web" || result.Endpoints[0].Port != 8080 || result.Endpoints[0].ServiceURL != result.ServiceURL {
		t.Fatalf("Endpoints = %#v", result.Endpoints)
	}
	if got := actionCount(client, "create", "ingresses"); got != 0 {
		t.Fatalf("ingress create actions = %d, want 0", got)
	}
}

func TestUpsertServicePreservesAllocatedNodePortOnReconcile(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	cluster.Config.PublicGateway = "http://203.0.113.10"
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	existing := resources.Services[0].DeepCopy()
	existing.Spec.Ports[0].NodePort = 31042
	client := fake.NewSimpleClientset(existing)

	if err := upsertService(context.Background(), client, resources.Services[0]); err != nil {
		t.Fatal(err)
	}
	stored, err := client.CoreV1().Services(existing.Namespace).Get(context.Background(), existing.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Spec.Ports[0].NodePort; got != 31042 {
		t.Fatalf("NodePort = %d, want 31042", got)
	}
	endpoints, err := BuildNodePortEndpoints(cluster.Config.PublicGateway, []*corev1.Service{stored})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].ServiceURL != "http://203.0.113.10:31042" {
		t.Fatalf("endpoints = %#v", endpoints)
	}
}

func TestAdapterRollsBackMultiContainerApplyFailure(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	client := readyMultiContainerClient(t, command)
	client.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		service := action.(k8stesting.CreateAction).GetObject().(*corev1.Service)
		if service.Name == "internal" {
			return true, nil, errors.New("internal service creation failed")
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(
		t,
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		client,
	))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
	if got := actionCount(client, "create", "ingresses"); got != 0 {
		t.Fatalf("ingress create actions = %d, want 0 after service failure", got)
	}
}

func TestAdapterWaitsForEveryContainerAndService(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	webDeployment := resources.Deployments[0]
	internalDeployment := resources.Deployments[1]
	webPod := readyPod(
		resources.Namespace.Name,
		resources.ExpectedSpecHashes[webDeployment.Name],
		"web-pod",
		"10.0.0.1",
		webDeployment.Spec.Template.Labels,
	)
	internalPod := readyPod(
		resources.Namespace.Name,
		resources.ExpectedSpecHashes[internalDeployment.Name],
		"internal-pod",
		"10.0.0.2",
		internalDeployment.Spec.Template.Labels,
	)
	client := fake.NewSimpleClientset(
		webPod,
		internalPod,
		readyEndpointSliceForService(resources.Namespace.Name, "web", webPod),
	)
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	internalEndpointListed := make(chan struct{}, 1)
	client.PrependReactor("list", "endpointslices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		selector := action.(k8stesting.ListAction).GetListRestrictions().Labels.String()
		if strings.Contains(selector, "internal") {
			select {
			case internalEndpointListed <- struct{}{}:
			default:
			}
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(
		t,
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		client,
	))
	result := make(chan createResult, 1)
	go func() {
		value, createErr := adapter.CreateWorkload(context.Background(), command)
		result <- createResult{result: value, err: createErr}
	}()

	<-internalEndpointListed
	assertNoCreateResult(t, result)
	if _, err := client.DiscoveryV1().EndpointSlices(resources.Namespace.Name).Create(
		context.Background(),
		readyEndpointSliceForService(resources.Namespace.Name, "internal", internalPod),
		metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("CreateWorkload did not finish after every service became ready")
	}
}

func TestWorkloadLockSetCancelsSameKeyWaiterAndCleansEntry(t *testing.T) {
	locks := newWorkloadLockSet()
	key := workloadLockKey("target", "same-workload")
	releaseFirst, err := locks.acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithCancel(context.Background())
	waitResult := make(chan error, 1)
	go func() {
		release, acquireErr := locks.acquire(waitCtx, key)
		if release != nil {
			release()
		}
		waitResult <- acquireErr
	}()
	waitForWorkloadLockRefs(t, locks, key, 2)
	cancelWait()
	if err := <-waitResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context cancellation", err)
	}
	releaseFirst()
	assertWorkloadLockEntries(t, locks, 0)
}

func TestWorkloadLockSetAllowsDifferentKeysInParallel(t *testing.T) {
	locks := newWorkloadLockSet()
	releaseFirst, err := locks.acquire(context.Background(), workloadLockKey("target", "first-workload"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releaseSecond, err := locks.acquire(ctx, workloadLockKey("target", "second-workload"))
	if err != nil {
		t.Fatalf("different key acquisition blocked: %v", err)
	}
	releaseSecond()
	releaseFirst()
	assertWorkloadLockEntries(t, locks, 0)
}

func TestAdapterSerializesSameWorkloadThroughFailureRollbackThenSuccess(t *testing.T) {
	command := validCreateCommand("aws-dev")
	baseClient := readyClient(t, command)
	deleteAccepted := make(chan struct{}, 1)
	postDeleteRead := make(chan struct{}, 1)
	deletionComplete := make(chan struct{})
	client := &coreOverrideClient{
		Interface: baseClient,
		core: &coreOverride{
			CoreV1Interface: baseClient.CoreV1(),
			namespaces: &asynchronousDeleteNamespaces{
				NamespaceInterface: baseClient.CoreV1().Namespaces(),
				deleteAccepted:     deleteAccepted,
				postDeleteRead:     postDeleteRead,
				deletionComplete:   deletionComplete,
			},
		},
	}
	firstApplyEntered := make(chan struct{})
	releaseFirstApply := make(chan struct{})
	applyFailure := errors.New("first operation deployment failure")
	var deploymentCreates atomic.Int32
	baseClient.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		attempt := deploymentCreates.Add(1)
		if attempt == 1 {
			close(firstApplyEntered)
			<-releaseFirstApply
		}
		if attempt <= maxReconcileAttempts {
			return true, nil, applyFailure
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	firstResult := make(chan createResult, 1)
	go func() {
		result, err := adapter.CreateWorkload(context.Background(), command)
		firstResult <- createResult{result: result, err: err}
	}()
	<-firstApplyEntered

	secondResult := make(chan createResult, 1)
	go func() {
		result, err := adapter.CreateWorkload(context.Background(), command)
		secondResult <- createResult{result: result, err: err}
	}()
	key := workloadLockKey(command.TargetID, command.InstanceID)
	waitForWorkloadLockRefs(t, adapter.workloadLocks, key, 2)
	if got := deploymentCreates.Load(); got != 1 {
		t.Fatalf("deployment creates before first rollback = %d, want 1", got)
	}
	close(releaseFirstApply)
	<-deleteAccepted
	<-postDeleteRead
	assertNoCreateResult(t, firstResult)
	if got := deploymentCreates.Load(); got != maxReconcileAttempts {
		t.Fatalf("deployment creates before asynchronous rollback completed = %d, want %d", got, maxReconcileAttempts)
	}
	close(deletionComplete)

	first := <-firstResult
	if runtimeErrorCode(t, first.err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("first code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, first.err))
	}
	second := <-secondResult
	if second.err != nil {
		t.Fatal(second.err)
	}
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{}); err != nil {
		t.Fatalf("successful second operation namespace missing: %v", err)
	}
	assertDeleteActionCount(t, baseClient, "namespaces", 1)
	assertWorkloadLockEntries(t, adapter.workloadLocks, 0)
}

func TestAdapterAllowsDifferentInstancesToCreateInParallel(t *testing.T) {
	firstCommand := validCreateCommand("aws-dev")
	secondCommand := validCreateCommand("aws-dev")
	secondCommand.InstanceID = "018f3f1e-21b8-7a91-a30b-63b3400fd002"
	firstResources, err := BuildResourceSet(validCluster("aws-dev"), firstCommand)
	if err != nil {
		t.Fatal(err)
	}
	secondResources, err := BuildResourceSet(validCluster("aws-dev"), secondCommand)
	if err != nil {
		t.Fatal(err)
	}
	firstPod := readyPod(firstResources.Namespace.Name, firstResources.ExpectedSpecHash, "first-pod", "10.0.0.1", firstResources.Deployment.Spec.Template.Labels)
	secondPod := readyPod(secondResources.Namespace.Name, secondResources.ExpectedSpecHash, "second-pod", "10.0.0.2", secondResources.Deployment.Spec.Template.Labels)
	baseClient := fake.NewSimpleClientset(firstPod, readyEndpointSlice(firstResources.Namespace.Name, firstPod), secondPod, readyEndpointSlice(secondResources.Namespace.Name, secondPod))
	installDeploymentController(baseClient, true)
	firstNamespaceEntered := make(chan struct{})
	releaseFirstNamespace := make(chan struct{})
	secondNamespaceEntered := make(chan struct{}, 1)
	client := &coreOverrideClient{
		Interface: baseClient,
		core: &coreOverride{
			CoreV1Interface: baseClient.CoreV1(),
			namespaces: &parallelCreateNamespaces{
				NamespaceInterface:    baseClient.CoreV1().Namespaces(),
				blockedName:           firstResources.Namespace.Name,
				parallelName:          secondResources.Namespace.Name,
				blockedCreateEntered:  firstNamespaceEntered,
				releaseBlockedCreate:  releaseFirstNamespace,
				parallelCreateEntered: secondNamespaceEntered,
			},
		},
	}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	firstResult := make(chan createResult, 1)
	go func() {
		result, createErr := adapter.CreateWorkload(context.Background(), firstCommand)
		firstResult <- createResult{result: result, err: createErr}
	}()
	<-firstNamespaceEntered

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	secondResult := make(chan createResult, 1)
	go func() {
		result, createErr := adapter.CreateWorkload(secondCtx, secondCommand)
		secondResult <- createResult{result: result, err: createErr}
	}()
	select {
	case <-secondNamespaceEntered:
	case got := <-secondResult:
		close(releaseFirstNamespace)
		t.Fatalf("different instance did not reach Kubernetes in parallel: %#v", got)
	}
	second := <-secondResult
	if second.err != nil {
		close(releaseFirstNamespace)
		t.Fatal(second.err)
	}
	close(releaseFirstNamespace)
	if first := <-firstResult; first.err != nil {
		t.Fatal(first.err)
	}
	assertWorkloadLockEntries(t, adapter.workloadLocks, 0)
}

func TestAdapterReturnsOnlyAfterReadyPodAndEndpointSlice(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset()
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	resourcesApplied := actionSignal(client, "create", "ingresses")
	podListed := actionSignal(client, "list", "pods")
	result := make(chan createResult, 1)
	go func() {
		value, err := adapter.CreateWorkload(context.Background(), command)
		result <- createResult{value, err}
	}()
	<-resourcesApplied
	namespace := resources.Namespace.Name
	pod := readyPod(namespace, resources.ExpectedSpecHash, "ready-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	if _, err := client.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	<-podListed
	assertNoCreateResult(t, result)
	if _, err := client.DiscoveryV1().EndpointSlices(namespace).Create(context.Background(), readyEndpointSlice(namespace, pod), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.result.RuntimeWorkloadID != resources.RuntimeWorkloadID || got.result.ServiceURL != resources.ServiceURL {
		t.Fatalf("CreateWorkload() = %#v, want workload ID and URL from resource set", got.result)
	}
}

func TestAdapterReturnsExactNamespaceUIDAfterFinalReadback(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	installNamespaceCreateMetadata(t, client, "created-namespace-uid", "11")
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	result, err := adapter.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.NamespaceUID != "created-namespace-uid" {
		t.Fatalf("NamespaceUID = %q, want exact server UID", result.NamespaceUID)
	}
}

func TestAdapterRejectsNamespaceReplacementAtFinalReadback(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := readyClient(t, command)
	installNamespaceCreateMetadata(t, client, "created-namespace-uid", "11")
	getCount := 0
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		if getCount < 3 {
			return false, nil, nil
		}
		replacement := resources.Namespace.DeepCopy()
		replacement.UID = "replacement-namespace-uid"
		replacement.ResourceVersion = "12"
		return true, replacement, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("code = %q, want RUNTIME_IDENTITY_MISMATCH", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterWaitsForLatestRevisionPodAndItsEndpoint(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	oldPod := readyPod(resources.Namespace.Name, "old-spec-hash", "old-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	oldEndpoint := readyEndpointSlice(resources.Namespace.Name, oldPod)
	client := fake.NewSimpleClientset(oldPod, oldEndpoint)
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	podListed := make(chan struct{})
	firstListRelease := make(chan struct{})
	listCount := 0
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		listCount++
		podListed <- struct{}{}
		if listCount == 1 {
			<-firstListRelease
		}
		return false, nil, nil
	})
	endpointListed := actionSignal(client, "list", "endpointslices")
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan createResult, 1)
	go func() {
		value, createErr := adapter.CreateWorkload(ctx, command)
		result <- createResult{value, createErr}
	}()

	<-podListed
	close(firstListRelease)
	select {
	case got := <-result:
		t.Fatalf("CreateWorkload returned for old revision: %#v", got)
	case <-podListed:
	}
	newPod := readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "new-pod", "10.0.0.2", resources.Deployment.Spec.Template.Labels)
	if _, err := client.CoreV1().Pods(resources.Namespace.Name).Create(context.Background(), newPod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for waitingForEndpoint := true; waitingForEndpoint; {
		select {
		case <-podListed:
		case <-endpointListed:
			waitingForEndpoint = false
		}
	}
	assertNoCreateResult(t, result)
	oldEndpoint.Endpoints = append(oldEndpoint.Endpoints, matchingEndpoint(newPod))
	if _, err := client.DiscoveryV1().EndpointSlices(resources.Namespace.Name).Update(context.Background(), oldEndpoint, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	var got createResult
	for waitingForResult := true; waitingForResult; {
		select {
		case <-podListed:
		case got = <-result:
			waitingForResult = false
		}
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
}

func TestAdapterRejectsEndpointForDifferentReadyPod(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	pod := readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "expected-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	otherPod := readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "other-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	endpoint := readyEndpointSlice(resources.Namespace.Name, otherPod)
	client := fake.NewSimpleClientset(pod, endpoint)
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	assertNotReadyAfterGate(t, adapter, client, command, "list", "endpointslices")
}

func TestReadyEndpointRequiresNonblankAddressEvenWithMatchingTargetRef(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	pod := readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "ready-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	endpointSlice := readyEndpointSlice(resources.Namespace.Name, pod)
	endpointSlice.Endpoints[0].Addresses = []string{"", "   "}
	client := fake.NewSimpleClientset(endpointSlice)

	ready, err := hasReadyEndpointForPods(context.Background(), client, resources.Namespace.Name, []corev1.Pod{*pod})
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("matching TargetRef without a nonblank address was accepted")
	}
}

func TestAdapterAcceptsPodIPMatchedEndpointWithoutTargetRef(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	pod := readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "ready-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	endpoint := readyEndpointSlice(resources.Namespace.Name, pod)
	endpoint.Endpoints[0].TargetRef = nil
	client := fake.NewSimpleClientset(pod, endpoint)
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterWaitsForCurrentDeploymentRollout(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	installDeploymentController(client, false)
	readinessGet := make(chan struct{}, 1)
	getCount := 0
	client.PrependReactor("get", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		if getCount == 2 {
			readinessGet <- struct{}{}
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan createResult, 1)
	go func() {
		value, createErr := adapter.CreateWorkload(ctx, command)
		result <- createResult{value, createErr}
	}()

	select {
	case got := <-result:
		cancel()
		t.Fatalf("CreateWorkload returned before Deployment rollout: %#v", got)
	case <-readinessGet:
		cancel()
	}
	got := <-result
	if runtimeErrorCode(t, got.err) != "OPERATION_CANCELLED" {
		t.Fatalf("code = %q, want OPERATION_CANCELLED", runtimeErrorCode(t, got.err))
	}
}

func TestAdapterRejectsDeploymentSupersededAfterApply(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	getCount := 0
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		if getCount <= 2 {
			return false, nil, nil
		}
		tracked, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), resourceName)
		if err != nil {
			return true, nil, err
		}
		superseded := tracked.(*appsv1.Deployment).DeepCopy()
		superseded.Generation = 2
		superseded.Annotations[specHashAnnotation] = "superseding-spec-hash"
		superseded.Status.ObservedGeneration = 2
		superseded.Status.UpdatedReplicas = 1
		superseded.Status.AvailableReplicas = 1
		return true, superseded, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterDoesNotReturnWithOnlyReadyPod(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Tracker().Delete(discoveryv1.SchemeGroupVersion.WithResource("endpointslices"), namespace, resourceName); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	assertNotReadyAfterGate(t, adapter, client, command, "list", "endpointslices")
}

func TestAdapterDoesNotReturnWithOnlyReadyEndpointSlice(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), namespace, "ready-pod"); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	assertNotReadyAfterGate(t, adapter, client, command, "list", "pods")
}

func TestAdapterRejectsDirectRetryWithoutDuplicateResources(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CreateWorkload(context.Background(), command); runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("second direct CreateWorkload() error = %v, want RESOURCE_OWNERSHIP_CONFLICT", err)
	}
	for _, resource := range []string{"namespaces", "deployments", "services", "ingresses"} {
		assertCreateActionCount(t, client, resource, 1)
	}
}

func TestAdapterReconcilesAlreadyExistsRaceForEveryResource(t *testing.T) {
	for _, resource := range []string{
		"serviceaccounts",
		"resourcequotas",
		"limitranges",
		"networkpolicies",
		"deployments",
		"services",
		"ingresses",
	} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			client := readyClient(t, command)
			installCreateErrorAfterCommit(t, client, resource, func(action k8stesting.Action) error {
				object := action.(k8stesting.CreateAction).GetObject().(metav1.Object)
				return apierrors.NewAlreadyExists(action.GetResource().GroupResource(), object.GetName())
			})
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			wantCreates := 1
			if resource == "networkpolicies" {
				resources, buildErr := BuildResourceSet(validCluster("aws-dev"), command)
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				wantCreates = len(resources.NetworkPolicies)
			}
			assertCreateActionCount(t, client, resource, wantCreates)
		})
	}
}

func TestAdapterDoesNotAdoptNamespaceAfterAlreadyExistsCreate(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	installCreateErrorAfterCommit(t, client, "namespaces", func(action k8stesting.Action) error {
		object := action.(k8stesting.CreateAction).GetObject().(metav1.Object)
		return apierrors.NewAlreadyExists(action.GetResource().GroupResource(), object.GetName())
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
	assertNoChildResourceMutations(t, client.Actions())
}

func TestAdapterDoesNotRollbackNamespaceWhenFailedCreateCannotProveOwnership(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	installCreateErrorAfterCommit(t, client, "namespaces", func(k8stesting.Action) error {
		return context.DeadlineExceeded
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertCreateActionCount(t, client, "namespaces", 1)
	assertDeleteActionCount(t, client, "namespaces", 0)
	assertNoChildResourceMutations(t, client.Actions())

	if _, err := adapter.CreateWorkload(context.Background(), command); runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("independent retry error = %v, want RESOURCE_OWNERSHIP_CONFLICT", err)
	}
	assertCreateActionCount(t, client, "namespaces", 1)
	assertCreateActionCount(t, client, "deployments", 0)
}

func TestAdapterDoesNotReadBackOrRollbackNamespaceAfterFailedCreate(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	getCount := 0
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		return false, nil, nil
	})
	installCreateErrorAfterCommit(t, client, "namespaces", func(k8stesting.Action) error {
		return context.DeadlineExceeded
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	if getCount != 2 {
		t.Fatalf("namespace get actions = %d, want preflight and pre-create reads only", getCount)
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterRetriesDeploymentUpdateConflictWithLatestResourceVersion(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Deployment.ResourceVersion = "1"
	client := readyClient(t, command)
	if err := client.Tracker().Add(resources.Deployment); err != nil {
		t.Fatal(err)
	}
	conflicts := 0
	client.PrependReactor("update", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		conflicts++
		if conflicts == 1 {
			latest, trackerErr := client.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("deployments"), resources.Namespace.Name, resourceName)
			if trackerErr != nil {
				t.Fatal(trackerErr)
			}
			latestDeployment := latest.(*appsv1.Deployment).DeepCopy()
			latestDeployment.ResourceVersion = "2"
			if trackerErr := client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("deployments"), latestDeployment, resources.Namespace.Name); trackerErr != nil {
				t.Fatal(trackerErr)
			}
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), resourceName, errors.New("stale resource version"))
		}
		if got := action.(k8stesting.UpdateAction).GetObject().(*appsv1.Deployment).ResourceVersion; got != "2" {
			t.Fatalf("retried ResourceVersion = %q, want latest 2", got)
		}
		return false, nil, nil
	})
	if _, err := upsertDeployment(context.Background(), client, resources.Deployment); err != nil {
		t.Fatal(err)
	}
	if got := actionCount(client, "update", "deployments"); got != 2 {
		t.Fatalf("deployment update actions = %d, want 2", got)
	}
}

func TestAdapterWorkloadUpdatesPreserveApprovedServerFields(t *testing.T) {
	for _, resource := range []string{"deployments", "services", "ingresses"} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			client := readyClient(t, command)
			for _, object := range []runtime.Object{resources.Deployment, resources.Service, resources.Ingress} {
				metadata := object.(metav1.Object)
				metadata.SetUID(types.UID("server-" + metadata.GetName()))
				metadata.SetResourceVersion("7")
				metadata.SetGeneration(3)
				metadata.SetCreationTimestamp(metav1.Unix(123, 0))
				metadata.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "kube-apiserver"}})
				if deployment, ok := object.(*appsv1.Deployment); ok {
					deployment.Annotations["deployment.kubernetes.io/revision"] = "4"
				}
				if err := client.Tracker().Add(object); err != nil {
					t.Fatal(err)
				}
			}

			var inspected atomic.Bool
			client.PrependReactor("update", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				metadata := action.(k8stesting.UpdateAction).GetObject().(metav1.Object)
				if metadata.GetUID() != types.UID("server-"+metadata.GetName()) ||
					metadata.GetResourceVersion() != "7" || metadata.GetGeneration() != 3 ||
					!metadata.GetCreationTimestamp().Time.Equal(time.Unix(123, 0)) ||
					!reflect.DeepEqual(metadata.GetManagedFields(), []metav1.ManagedFieldsEntry{{Manager: "kube-apiserver"}}) {
					t.Fatalf("approved server fields were dropped from %s update: %#v", resource, metadata)
				}
				if resource == "deployments" && metadata.GetAnnotations()["deployment.kubernetes.io/revision"] != "4" {
					t.Fatalf("Deployment controller revision was dropped: %#v", metadata.GetAnnotations())
				}
				inspected.Store(true)
				return false, nil, nil
			})
			var updateErr error
			switch resource {
			case "deployments":
				_, updateErr = upsertDeployment(context.Background(), client, resources.Deployment)
			case "services":
				updateErr = upsertService(context.Background(), client, resources.Service)
			case "ingresses":
				updateErr = upsertIngress(context.Background(), client, resources.Ingress)
			}
			if updateErr != nil {
				t.Fatal(updateErr)
			}
			if !inspected.Load() {
				t.Fatalf("%s update was not inspected", resource)
			}
		})
	}
}

func TestAdapterRetriesProtectionUpdateConflictWithLatestResourceVersion(t *testing.T) {
	for _, resource := range []string{"serviceaccounts", "resourcequotas", "limitranges", "networkpolicies"} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareProtectionHashes(resources); err != nil {
				t.Fatal(err)
			}
			client := readyClient(t, command)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
				t.Fatal(err)
			}

			gvr, existing := trackedProtection(t, client, resources, resource)
			metadata := existing.(metav1.Object)
			metadata.SetResourceVersion("1")
			annotations := metadata.GetAnnotations()
			annotations[specHashAnnotation] = "stale"
			metadata.SetAnnotations(annotations)
			if err := client.Tracker().Update(gvr, existing, resources.Namespace.Name); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()

			conflicts := 0
			client.PrependReactor("update", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.UpdateAction).GetObject().(metav1.Object).GetName() != metadata.GetName() {
					return false, nil, nil
				}
				conflicts++
				if conflicts == 1 {
					latest, trackerErr := client.Tracker().Get(gvr, action.GetNamespace(), metadata.GetName())
					if trackerErr != nil {
						t.Fatal(trackerErr)
					}
					latest.(metav1.Object).SetResourceVersion("2")
					if trackerErr := client.Tracker().Update(gvr, latest, action.GetNamespace()); trackerErr != nil {
						t.Fatal(trackerErr)
					}
					return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), metadata.GetName(), errors.New("stale resource version"))
				}
				if got := action.(k8stesting.UpdateAction).GetObject().(metav1.Object).GetResourceVersion(); got != "2" {
					t.Fatalf("retried ResourceVersion = %q, want latest 2", got)
				}
				return false, nil, nil
			})

			if err := applyProtectionResourceSet(context.Background(), client, resources); err != nil {
				t.Fatal(err)
			}
			if conflicts != 2 {
				t.Fatalf("%s target update actions = %d, want 2", resource, conflicts)
			}
		})
	}
}

func TestAdapterProtectionUpdatesPreserveApprovedServerFields(t *testing.T) {
	for _, resource := range []string{"serviceaccounts", "resourcequotas", "limitranges", "networkpolicies"} {
		t.Run(resource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareProtectionHashes(resources); err != nil {
				t.Fatal(err)
			}
			client := readyClient(t, command)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
				t.Fatal(err)
			}

			gvr, existing := trackedProtection(t, client, resources, resource)
			metadata := existing.(metav1.Object)
			metadata.SetUID("server-uid")
			metadata.SetResourceVersion("7")
			annotations := metadata.GetAnnotations()
			annotations[specHashAnnotation] = "stale"
			metadata.SetAnnotations(annotations)
			switch object := existing.(type) {
			case *corev1.ServiceAccount:
				object.Secrets = []corev1.ObjectReference{{Name: "server-populated-secret"}}
				object.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "server-pull-secret"}}
			case *corev1.ResourceQuota:
				object.Status.Used = corev1.ResourceList{corev1.ResourcePods: *resourceQuantityBytes(1)}
			}
			if err := client.Tracker().Update(gvr, existing, resources.Namespace.Name); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()

			updated := make(chan runtime.Object, 1)
			client.PrependReactor("update", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				object := action.(k8stesting.UpdateAction).GetObject()
				if object.(metav1.Object).GetName() != metadata.GetName() {
					return false, nil, nil
				}
				updated <- object.DeepCopyObject()
				return false, nil, nil
			})
			if err := applyProtectionResourceSet(context.Background(), client, resources); err != nil {
				t.Fatal(err)
			}

			candidate := <-updated
			candidateMetadata := candidate.(metav1.Object)
			if candidateMetadata.GetUID() != "server-uid" || candidateMetadata.GetResourceVersion() != "7" {
				t.Fatalf("server metadata was not preserved: %#v", candidateMetadata)
			}
			switch object := candidate.(type) {
			case *corev1.ServiceAccount:
				if !reflect.DeepEqual(object.Secrets, []corev1.ObjectReference{{Name: "server-populated-secret"}}) ||
					!reflect.DeepEqual(object.ImagePullSecrets, []corev1.LocalObjectReference{{Name: "server-pull-secret"}}) {
					t.Fatalf("ServiceAccount server fields were not preserved: %#v", object)
				}
			case *corev1.ResourceQuota:
				if got := object.Status.Used[corev1.ResourcePods]; got.Cmp(*resourceQuantityBytes(1)) != 0 {
					t.Fatalf("ResourceQuota status was not preserved: %#v", object.Status)
				}
			}
		})
	}
}

func TestUpsertServiceStopsAfterThreePersistentUpdateConflicts(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(resources.Service)
	client.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), resourceName, errors.New("persistent conflict"))
	})
	err = upsertService(context.Background(), client, resources.Service)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	if got := actionCount(client, "update", "services"); got != 3 {
		t.Fatalf("service update actions = %d, want bounded 3", got)
	}
}

func TestAdapterDoesNotRetryOrDeleteForeignDeploymentFromAlreadyExistsRace(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		foreign := action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).DeepCopy()
		foreign.Labels["msgctf.io/instance-id"] = "018f3f1e-21b8-7a91-a30b-63b3400fd999"
		if err := client.Tracker().Create(action.GetResource(), foreign, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(action.GetResource().GroupResource(), foreign.Name)
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertCreateActionCount(t, client, "deployments", 1)
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterDoesNotSanitizeForeignProtectionFromAlreadyExistsRace(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		foreign := action.(k8stesting.CreateAction).GetObject().(*corev1.ServiceAccount).DeepCopy()
		foreign.Labels["msgctf.io/instance-id"] = "018f3f1e-21b8-7a91-a30b-63b3400fd999"
		if err := client.Tracker().Create(action.GetResource(), foreign, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(action.GetResource().GroupResource(), foreign.Name)
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertCreateActionCount(t, client, "serviceaccounts", 1)
	if got := actionCount(client, "update", "serviceaccounts"); got != 0 {
		t.Fatalf("serviceaccount update actions = %d, want 0", got)
	}
	assertCreateActionCount(t, client, "deployments", 0)
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterRejectsServiceAccountSemanticMetadataFromAlreadyExistsRaceWithoutUpdate(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		account := action.(k8stesting.CreateAction).GetObject().(*corev1.ServiceAccount).DeepCopy()
		account.Annotations["eks.amazonaws.com/role-arn"] = "arn:aws:iam::123456789012:role/injected"
		if err := client.Tracker().Create(action.GetResource(), account, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(action.GetResource().GroupResource(), account.Name)
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	if got := actionCount(client, "update", "serviceaccounts"); got != 0 {
		t.Fatalf("serviceaccount update actions = %d, want 0", got)
	}
	assertCreateActionCount(t, client, "deployments", 0)
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterRechecksResourceQuotaSemanticMetadataAfterUpdateConflict(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareProtectionHashes(resources); err != nil {
		t.Fatal(err)
	}
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}

	gvr, quota := trackedProtection(t, client, resources, "resourcequotas")
	metadata := quota.(metav1.Object)
	metadata.SetResourceVersion("1")
	annotations := metadata.GetAnnotations()
	annotations[specHashAnnotation] = "stale"
	metadata.SetAnnotations(annotations)
	if err := client.Tracker().Update(gvr, quota, resources.Namespace.Name); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()

	client.PrependReactor("update", "resourcequotas", func(action k8stesting.Action) (bool, runtime.Object, error) {
		latest, trackerErr := client.Tracker().Get(gvr, action.GetNamespace(), metadata.GetName())
		if trackerErr != nil {
			t.Fatal(trackerErr)
		}
		latestMetadata := latest.(metav1.Object)
		latestLabels := latestMetadata.GetLabels()
		latestLabels["platform.example/injected"] = "true"
		latestMetadata.SetLabels(latestLabels)
		latestMetadata.SetResourceVersion("2")
		if trackerErr := client.Tracker().Update(gvr, latest, action.GetNamespace()); trackerErr != nil {
			t.Fatal(trackerErr)
		}
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), metadata.GetName(), errors.New("stale resource version"))
	})

	err = applyProtectionResourceSet(context.Background(), client, resources)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	if got := actionCount(client, "update", "resourcequotas"); got != 1 {
		t.Fatalf("resourcequota update actions = %d, want only the pre-conflict update", got)
	}
	stored, err := client.Tracker().Get(gvr, resources.Namespace.Name, metadata.GetName())
	if err != nil {
		t.Fatal(err)
	}
	if stored.(metav1.Object).GetLabels()["platform.example/injected"] != "true" {
		t.Fatal("latest ResourceQuota metadata was sanitized after conflict")
	}
	if got := actionCount(client, "update", "deployments"); got != 0 {
		t.Fatalf("deployment update actions = %d, want 0", got)
	}
}

func TestAdapterPreflightsForeignServiceAndIngressBeforeAnyChildWrite(t *testing.T) {
	for _, foreignResource := range []string{"services", "ingresses"} {
		t.Run(foreignResource, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			existingDeployment := resources.Deployment.DeepCopy()
			existingDeployment.Spec.Template.Spec.Containers[0].Image = "existing-image"
			objects := []runtime.Object{resources.Namespace, existingDeployment}
			if foreignResource == "services" {
				foreignService := resources.Service.DeepCopy()
				foreignService.Labels["msgctf.io/instance-id"] = "018f3f1e-21b8-7a91-a30b-63b3400fd999"
				objects = append(objects, foreignService)
			} else {
				foreignIngress := resources.Ingress.DeepCopy()
				foreignIngress.Labels["msgctf.io/instance-id"] = "018f3f1e-21b8-7a91-a30b-63b3400fd999"
				objects = append(objects, resources.Service, foreignIngress)
			}
			client := fake.NewSimpleClientset(objects...)
			client.ClearActions()
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

			_, err = adapter.CreateWorkload(context.Background(), command)
			if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
				t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
			}
			assertNoChildWrites(t, client.Actions())
			stored, getErr := client.AppsV1().Deployments(resources.Namespace.Name).Get(context.Background(), resourceName, metav1.GetOptions{})
			if getErr != nil {
				t.Fatal(getErr)
			}
			if got := stored.Spec.Template.Spec.Containers[0].Image; got != "existing-image" {
				t.Fatalf("existing Deployment image = %q, want unchanged", got)
			}
			assertDeleteActionCount(t, client, "namespaces", 0)
		})
	}
}

func TestAdapterPreflightAPIErrorReturnsWithoutAnyMutation(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(resources.Namespace, resources.Deployment)
	client.PrependReactor("get", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("service preflight failure")
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	assertNoChildWrites(t, client.Actions())
	assertNoMutations(t, client.Actions())
}

func TestAdapterPreservesServiceClusterAllocationOnRetry(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Service.Spec.ClusterIP = "10.0.0.42"
	resources.Service.Spec.ClusterIPs = []string{"10.0.0.42"}
	client := fake.NewSimpleClientset(resources.Service)
	updatedService := make(chan *corev1.Service, 1)
	client.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updatedService <- action.(k8stesting.UpdateAction).GetObject().(*corev1.Service).DeepCopy()
		return false, nil, nil
	})
	if err := upsertService(context.Background(), client, resources.Service); err != nil {
		t.Fatal(err)
	}
	got := <-updatedService
	if got.Spec.ClusterIP != "10.0.0.42" || len(got.Spec.ClusterIPs) != 1 || got.Spec.ClusterIPs[0] != "10.0.0.42" {
		t.Fatalf("updated service allocation = %#v, want preserved ClusterIP and ClusterIPs", got.Spec)
	}
}

func TestAdapterRollsBackOwnedNamespaceWhenResourceApplyFails(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("https://cluster.example.invalid deployment failure")
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	namespace, namespaceErr := NamespaceForInstance(command.InstanceID)
	if namespaceErr != nil {
		t.Fatal(namespaceErr)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
	if _, getErr := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{}); !apierrors.IsNotFound(getErr) {
		t.Fatalf("namespace get error = %v, want NotFound", getErr)
	}
}

func TestAdapterRollbackUsesNamespaceUIDAndResourceVersionPreconditions(t *testing.T) {
	command := validCreateCommand("aws-dev")
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset()
	const ownedResourceVersion = "17"
	ownedUID := types.UID("owned-namespace")
	client.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		created := action.(k8stesting.CreateAction).GetObject().(*corev1.Namespace)
		created.UID = ownedUID
		created.ResourceVersion = ownedResourceVersion
		return false, nil, nil
	})
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("deployment apply failure")
	})
	foreignUID := types.UID("foreign-namespace")
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		options := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != ownedUID || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != ownedResourceVersion {
			t.Errorf("rollback delete preconditions = %#v, want UID %q and ResourceVersion %q", options.Preconditions, ownedUID, ownedResourceVersion)
		}
		foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:            namespace,
			UID:             foreignUID,
			ResourceVersion: "18",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "secure-provisioner",
				"app.kubernetes.io/name":       resourceName,
				"msgctf.io/instance-id":        "018f3f1e-21b8-7a91-a30b-63b3400fd002",
				"msgctf.io/team-id":            "42",
			},
		}}
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), foreign, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, namespace, errors.New("precondition mismatch"))
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "ROLLBACK_FAILED" {
		t.Fatalf("code = %q, want ROLLBACK_FAILED", runtimeErrorCode(t, err))
	}
	remaining, getErr := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if getErr != nil {
		t.Fatal(getErr)
	}
	if remaining.UID != foreignUID || remaining.ResourceVersion != "18" {
		t.Fatalf("remaining namespace = UID %q ResourceVersion %q, want foreign namespace", remaining.UID, remaining.ResourceVersion)
	}
}

func TestAdapterRollbackFailurePreservesOriginalAndRollbackCauses(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	originalCause := errors.New("original apply failure")
	rollbackCause := errors.New("rollback delete failure")
	client := fake.NewSimpleClientset(resources.Namespace)
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, rollbackCause
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	err = adapter.failWithRollback(client, resources.Namespace, "RESOURCE_APPLY_FAILED", originalCause)
	if runtimeErrorCode(t, err) != "ROLLBACK_FAILED" {
		t.Fatalf("code = %q, want ROLLBACK_FAILED", runtimeErrorCode(t, err))
	}
	if !errors.Is(err, originalCause) || !errors.Is(err, rollbackCause) {
		t.Fatalf("error chain = %v, want original and rollback causes", err)
	}
}

func TestAdapterProtectionFailureAndRollbackFailurePreserveBothCauses(t *testing.T) {
	command := validCreateCommand("aws-dev")
	applyCause := errors.New("service account apply failure")
	rollbackCause := errors.New("namespace cleanup failure")
	client := readyClient(t, command)
	client.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, applyCause
	})
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, rollbackCause
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "ROLLBACK_FAILED" || err.Error() != "ROLLBACK_FAILED" {
		t.Fatalf("error = %v, want stable ROLLBACK_FAILED", err)
	}
	if !errors.Is(err, applyCause) || !errors.Is(err, rollbackCause) {
		t.Fatalf("error chain = %v, want apply and rollback causes", err)
	}
	assertCreateActionCount(t, client, "deployments", 0)
}

func TestRollbackNamespaceWaitsUntilAsynchronousDeletionCompletes(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(resources.Namespace)
	var deleteAccepted atomic.Bool
	var postDeleteGets atomic.Int32
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		deleteAccepted.Store(true)
		return true, nil, nil
	})
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if !deleteAccepted.Load() {
			return false, nil, nil
		}
		if postDeleteGets.Add(1) == 1 {
			terminating := resources.Namespace.DeepCopy()
			now := metav1.Now()
			terminating.DeletionTimestamp = &now
			return true, terminating, nil
		}
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, resources.Namespace.Name)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := rollbackNamespace(ctx, client, resources.Namespace, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := postDeleteGets.Load(); got != 2 {
		t.Fatalf("post-delete namespace GETs = %d, want 2 through NotFound", got)
	}
}

func TestRollbackNamespaceRetriesResourceVersionConflictWhileUIDIsStable(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Namespace.DeepCopy()
	desired.UID = "owned-uid"
	desired.ResourceVersion = "1"
	client := fake.NewSimpleClientset(desired.DeepCopy())
	deleteCalls := 0
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		options := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != desired.UID {
			t.Fatalf("delete preconditions = %#v, want stable UID %q", options.Preconditions, desired.UID)
		}
		if deleteCalls == 1 {
			latest := desired.DeepCopy()
			latest.ResourceVersion = "2"
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), latest, ""); err != nil {
				t.Fatal(err)
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, desired.Name, errors.New("stale resource version"))
		}
		if options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != "2" {
			t.Fatalf("retried preconditions = %#v, want ResourceVersion 2", options.Preconditions)
		}
		return false, nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rollbackNamespace(ctx, client, desired, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if deleteCalls != 2 {
		t.Fatalf("delete calls = %d, want 2", deleteCalls)
	}
}

func TestRollbackNamespaceRetriesTransientGetBeforeDelete(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Namespace.DeepCopy()
	desired.UID = "owned-uid"
	client := fake.NewSimpleClientset(desired.DeepCopy())
	getCalls := 0
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCalls++
		if getCalls == 1 {
			return true, nil, apierrors.NewServerTimeout(schema.GroupResource{Resource: "namespaces"}, "get", 1)
		}
		return false, nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rollbackNamespace(ctx, client, desired, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if getCalls < 2 {
		t.Fatalf("get calls = %d, want retry before delete", getCalls)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestRollbackNamespaceAbortsBeforeDeleteWhenUIDChanged(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Namespace.DeepCopy()
	desired.UID = "created-uid"
	replacement := resources.Namespace.DeepCopy()
	replacement.UID = "replacement-uid"
	client := fake.NewSimpleClientset(replacement)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rollbackNamespace(ctx, client, desired, time.Millisecond); err == nil {
		t.Fatal("expected namespace identity failure")
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestRollbackNamespaceAbortsRetryWhenUIDChangesAfterConflict(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Namespace.DeepCopy()
	desired.UID = "created-uid"
	desired.ResourceVersion = "1"
	client := fake.NewSimpleClientset(desired.DeepCopy())
	deleteCalls := 0
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		replacement := desired.DeepCopy()
		replacement.UID = "replacement-uid"
		replacement.ResourceVersion = "2"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), replacement, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), desired.Name, errors.New("stale resource version"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rollbackNamespace(ctx, client, desired, time.Millisecond); err == nil {
		t.Fatal("expected namespace identity failure")
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want no delete attempt against replacement UID", deleteCalls)
	}
}

func TestAdapterClassifiesPermanentRollbackFailureAsNonRetryable(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apply failed")
	})
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "owned", errors.New("denied"))
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Code() != "ROLLBACK_FAILED" || runtimeErr.Retryable() {
		t.Fatalf("error = %#v, want non-retryable ROLLBACK_FAILED", err)
	}
}

func TestAdapterRollbackGetIsBoundedByIndependentTimeout(t *testing.T) {
	command := validCreateCommand("aws-dev")
	originalCause := errors.New("deployment apply failure")
	baseClient := fake.NewSimpleClientset()
	baseClient.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, originalCause
	})
	observed := make(chan error, 1)
	blockingNamespaces := &deadlineObservingNamespaces{
		NamespaceInterface: baseClient.CoreV1().Namespaces(),
		observed:           observed,
	}
	client := &coreOverrideClient{
		Interface: baseClient,
		core: &coreOverride{
			CoreV1Interface: baseClient.CoreV1(),
			namespaces:      blockingNamespaces,
		},
	}
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond, RollbackTimeout: 2 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "ROLLBACK_FAILED" {
		t.Fatalf("code = %q, want ROLLBACK_FAILED", runtimeErrorCode(t, err))
	}
	if observedErr := <-observed; !errors.Is(observedErr, context.DeadlineExceeded) {
		t.Fatalf("rollback context error = %v, want deadline exceeded", observedErr)
	}
	if !errors.Is(err, originalCause) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error chain = %v, want apply failure and rollback deadline", err)
	}
}

func TestNewAdapterDefaultsAndValidatesRollbackTimeout(t *testing.T) {
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, fake.NewSimpleClientset())
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.config.RollbackTimeout != 30*time.Second {
		t.Fatalf("default RollbackTimeout = %s, want 30s", adapter.config.RollbackTimeout)
	}

	if _, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond, RollbackTimeout: -time.Second}); runtimeErrorCode(t, err) != "CONFIG_INVALID" {
		t.Fatalf("negative timeout code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
	}
	const customTimeout = 3 * time.Second
	adapter, err = NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond, RollbackTimeout: customTimeout})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.config.RollbackTimeout != customTimeout {
		t.Fatalf("RollbackTimeout = %s, want %s", adapter.config.RollbackTimeout, customTimeout)
	}
}

func TestAdapterRejectsPreexistingOwnedNamespaceBeforeResourceApply(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(resources.Namespace, resources.Deployment)
	client.PrependReactor("create", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("service apply failure")
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterRollsBackOwnedNamespaceWhenReadinessTimesOut(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Millisecond, PollInterval: time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "WORKLOAD_NOT_READY" {
		t.Fatalf("code = %q, want WORKLOAD_NOT_READY", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterRejectsPreexistingOwnedNamespaceBeforeReadiness(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(resources.Namespace, resources.Deployment)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Millisecond, PollInterval: time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterClassifiesParentDeadlineAsOperationCancelled(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	_, err = adapter.CreateWorkload(ctx, command)
	if runtimeErrorCode(t, err) != "OPERATION_CANCELLED" {
		t.Fatalf("code = %q, want OPERATION_CANCELLED", runtimeErrorCode(t, err))
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || !runtimeErr.Retryable() || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want retryable OPERATION_CANCELLED wrapping parent deadline", err)
	}
}

func TestAdapterClassifiesParentCancellationDuringNamespaceLookup(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(ctx, command)
	if runtimeErrorCode(t, err) != "OPERATION_CANCELLED" {
		t.Fatalf("code = %q, want OPERATION_CANCELLED", runtimeErrorCode(t, err))
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || !runtimeErr.Retryable() || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want retryable OPERATION_CANCELLED wrapping parent cancellation", err)
	}
}

func TestAdapterClassifiesPodListDeadlineAsResourceApplyFailure(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	installDeploymentController(client, true)
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, context.DeadlineExceeded
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	assertResourceApplyFailureFromActiveReadyContext(t, err)
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterClassifiesEndpointSliceListDeadlineAsResourceApplyFailure(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(readyPod(resources.Namespace.Name, resources.ExpectedSpecHash, "ready-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels))
	installDeploymentController(client, true)
	client.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, context.DeadlineExceeded
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	assertResourceApplyFailureFromActiveReadyContext(t, err)
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func assertResourceApplyFailureFromActiveReadyContext(t *testing.T, err error) {
	t.Helper()
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || !runtimeErr.Retryable() || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want retryable RESOURCE_APPLY_FAILED wrapping List deadline", err)
	}
	if err.Error() != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("Error() = %q, want stable code only", err.Error())
	}
}

func TestAdapterDoesNotDeleteNamespaceOwnedByAnotherInstance(t *testing.T) {
	command := validCreateCommand("aws-dev")
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner",
			"app.kubernetes.io/name":       resourceName,
			"msgctf.io/instance-id":        "018f3f1e-21b8-7a91-a30b-63b3400fd002",
			"msgctf.io/team-id":            "42",
		},
	}})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterDoesNotExposeKubeconfigOrAPIServerInErrors(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("https://api.private.example.invalid kubeconfig=/private/kubeconfig")
	})
	config := validClusterConfig("aws-dev", ProviderAWS, "/private/kubeconfig")
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if err == nil || err.Error() != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("error = %v, want RESOURCE_APPLY_FAILED", err)
	}
	for _, secret := range []string{"api.private.example.invalid", "/private/kubeconfig", "kubeconfig="} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposes %q: %v", secret, err)
		}
	}
}

type createResult struct {
	result provisioner.CreateWorkloadResult
	err    error
}

func assertNotReadyAfterGate(t *testing.T, adapter *Adapter, client *fake.Clientset, command provisioner.CreateWorkloadCommand, verb, resource string) {
	t.Helper()
	gateReached := actionSignal(client, verb, resource)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan createResult, 1)
	go func() {
		value, err := adapter.CreateWorkload(ctx, command)
		result <- createResult{value, err}
	}()
	<-gateReached
	assertNoCreateResult(t, result)
	cancel()
	got := <-result
	if runtimeErrorCode(t, got.err) != "OPERATION_CANCELLED" {
		t.Fatalf("code = %q, want OPERATION_CANCELLED", runtimeErrorCode(t, got.err))
	}
	var runtimeErr *RuntimeError
	if !errors.As(got.err, &runtimeErr) || !runtimeErr.Retryable() || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("error = %v, want retryable OPERATION_CANCELLED wrapping parent cancellation", got.err)
	}
}

func actionSignal(client *fake.Clientset, verb, resource string) <-chan struct{} {
	signal := make(chan struct{}, 1)
	client.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		select {
		case signal <- struct{}{}:
		default:
		}
		return false, nil, nil
	})
	return signal
}

func assertNoCreateResult(t *testing.T, result <-chan createResult) {
	t.Helper()
	select {
	case got := <-result:
		t.Fatalf("CreateWorkload returned early: %#v", got)
	default:
	}
}

func readyPod(namespace, specHash string, uid types.UID, podIP string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        string(uid),
			UID:         uid,
			Labels:      copyLabels(podLabels),
			Annotations: map[string]string{specHashAnnotation: specHash},
		},
		Status: corev1.PodStatus{
			PodIP:      podIP,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

func readyEndpointSlice(namespace string, pod *corev1.Pod) *discoveryv1.EndpointSlice {
	return readyEndpointSliceForService(namespace, resourceName, pod)
}

func readyEndpointSliceForService(namespace, serviceName string, pod *corev1.Pod) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: namespace, Name: serviceName, Labels: map[string]string{discoveryv1.LabelServiceName: serviceName}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{matchingEndpoint(pod)},
	}
}

func matchingEndpoint(pod *corev1.Pod) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{pod.Status.PodIP},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID},
	}
}

func TestAdapterRejectsUnknownAndDisabledTargetWithoutCallingAnyClient(t *testing.T) {
	activeClient := readyClient(t, validCreateCommand("aws-dev"))
	disabled := validClusterConfig("retired", ProviderNCP, "unused-kubeconfig")
	disabled.Enabled = false
	registry := adapterRegistry(t, []ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		disabled,
	}, activeClient, fake.NewSimpleClientset())
	adapter := newTestAdapter(t, registry)

	for _, targetID := range []string{"missing", "retired"} {
		command := validCreateCommand(targetID)
		_, err := adapter.CreateWorkload(context.Background(), command)
		if err == nil {
			t.Fatalf("CreateWorkload(%q) error = nil", targetID)
		}
	}
	if got := len(activeClient.Actions()); got != 0 {
		t.Fatalf("active client actions = %d, want 0", got)
	}
}

func newTestAdapter(t *testing.T, registry *Registry) *Adapter {
	t.Helper()
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func adapterRegistry(t *testing.T, configs []ClusterConfig, clients ...kubernetes.Interface) *Registry {
	t.Helper()
	registry, err := NewRegistry(configs, &sequenceFactory{clients: clients})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func readyClient(t *testing.T, command provisioner.CreateWorkloadCommand) *fake.Clientset {
	t.Helper()
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := BuildResourceSet(validCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	pod := readyPod(namespace, resources.ExpectedSpecHash, "ready-pod", "10.0.0.1", resources.Deployment.Spec.Template.Labels)
	client := fake.NewSimpleClientset(pod, readyEndpointSlice(namespace, pod))
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	return client
}

func readyMultiContainerClient(t *testing.T, command provisioner.CreateWorkloadCommand) *fake.Clientset {
	t.Helper()
	resources, err := BuildResourceSet(validCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	objects := make([]runtime.Object, 0, len(resources.Deployments)*2)
	for index, deployment := range resources.Deployments {
		pod := readyPod(
			resources.Namespace.Name,
			resources.ExpectedSpecHashes[deployment.Name],
			types.UID(deployment.Name+"-pod"),
			fmt.Sprintf("10.0.0.%d", index+1),
			deployment.Spec.Template.Labels,
		)
		objects = append(objects, pod, readyEndpointSliceForService(resources.Namespace.Name, deployment.Name, pod))
	}
	client := fake.NewSimpleClientset(objects...)
	installNamespaceCreateMetadata(t, client, "test-namespace-uid", "1")
	installDeploymentController(client, true)
	return client
}

func installNamespaceCreateMetadata(t *testing.T, client *fake.Clientset, uid types.UID, resourceVersion string) {
	t.Helper()
	client.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		namespace := action.(k8stesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		namespace.UID = uid
		namespace.ResourceVersion = resourceVersion
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, ""); err != nil {
			return true, nil, err
		}
		return true, namespace.DeepCopy(), nil
	})
}

func installDeploymentController(client *fake.Clientset, ready bool) {
	setStatus := func(deployment *appsv1.Deployment) *appsv1.Deployment {
		deployment = deployment.DeepCopy()
		deployment.UID = "deployment-uid"
		if deployment.Generation == 0 {
			deployment.Generation = 1
		}
		if ready {
			deployment.Status.ObservedGeneration = deployment.Generation
			deployment.Status.UpdatedReplicas = 1
			deployment.Status.AvailableReplicas = 1
		}
		return deployment
	}
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deployment := setStatus(action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment))
		if err := client.Tracker().Create(appsv1.SchemeGroupVersion.WithResource("deployments"), deployment, deployment.Namespace); err != nil {
			return true, nil, err
		}
		return true, deployment.DeepCopy(), nil
	})
	client.PrependReactor("update", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deployment := setStatus(action.(k8stesting.UpdateAction).GetObject().(*appsv1.Deployment))
		if err := client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("deployments"), deployment, deployment.Namespace); err != nil {
			return true, nil, err
		}
		return true, deployment.DeepCopy(), nil
	})
}

func installNodePortAllocator(t *testing.T, client *fake.Clientset, nodePort int32) {
	t.Helper()
	client.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		service := action.(k8stesting.CreateAction).GetObject().(*corev1.Service).DeepCopy()
		if service.Spec.Type == corev1.ServiceTypeNodePort {
			for index := range service.Spec.Ports {
				service.Spec.Ports[index].NodePort = nodePort + int32(index)
			}
		}
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("services"), service, service.Namespace); err != nil {
			return true, nil, err
		}
		return true, service.DeepCopy(), nil
	})
}

func assertNamespaceCreateCount(t *testing.T, client *fake.Clientset, want int) {
	t.Helper()
	assertCreateActionCount(t, client, "namespaces", want)
}

func assertCreateActionCount(t *testing.T, client *fake.Clientset, resource string, want int) {
	t.Helper()
	got := actionCount(client, "create", resource)
	if got != want {
		t.Fatalf("%s create actions = %d, want %d", resource, got, want)
	}
}

func assertDeleteActionCount(t *testing.T, client *fake.Clientset, resource string, want int) {
	t.Helper()
	got := actionCount(client, "delete", resource)
	if got != want {
		t.Fatalf("%s delete actions = %d, want %d", resource, got, want)
	}
}

func actionCount(client *fake.Clientset, verb, resource string) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == verb && action.GetResource().Resource == resource {
			count++
		}
	}
	return count
}

func assertNoChildWrites(t *testing.T, actions []k8stesting.Action) {
	t.Helper()
	for _, action := range actions {
		if action.GetVerb() != "create" && action.GetVerb() != "update" {
			continue
		}
		switch action.GetResource().Resource {
		case "deployments", "services", "ingresses":
			t.Fatalf("unexpected child write: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func assertNoChildResourceMutations(t *testing.T, actions []k8stesting.Action) {
	t.Helper()
	for _, action := range actions {
		switch action.GetVerb() {
		case "create", "update", "patch", "delete", "deletecollection":
		default:
			continue
		}
		if action.GetResource().Resource != "namespaces" {
			t.Fatalf("unexpected child mutation: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func assertNoMutations(t *testing.T, actions []k8stesting.Action) {
	t.Helper()
	for _, action := range actions {
		switch action.GetVerb() {
		case "create", "update", "patch", "delete", "deletecollection":
			t.Fatalf("unexpected mutation: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func desiredObjectForPreflightCase(t *testing.T, resources ResourceSet, resource string) runtime.Object {
	t.Helper()
	switch resource {
	case "namespace":
		return resources.Namespace.DeepCopy()
	case "serviceaccount":
		return resources.ServiceAccount.DeepCopy()
	case "resourcequota":
		return resources.ResourceQuota.DeepCopy()
	case "limitrange":
		return resources.LimitRange.DeepCopy()
	case "last-networkpolicy":
		return resources.NetworkPolicies[len(resources.NetworkPolicies)-1].DeepCopy()
	case "last-deployment":
		return resources.Deployments[len(resources.Deployments)-1].DeepCopy()
	case "last-service":
		return resources.Services[len(resources.Services)-1].DeepCopy()
	case "ingress":
		return resources.Ingress.DeepCopy()
	default:
		t.Fatalf("unknown preflight case %q", resource)
		return nil
	}
}

func trackedProtection(
	t *testing.T,
	client *fake.Clientset,
	resources ResourceSet,
	resource string,
) (schema.GroupVersionResource, runtime.Object) {
	t.Helper()
	var gvr schema.GroupVersionResource
	var name string
	switch resource {
	case "serviceaccounts":
		gvr = corev1.SchemeGroupVersion.WithResource(resource)
		name = resources.ServiceAccount.Name
	case "resourcequotas":
		gvr = corev1.SchemeGroupVersion.WithResource(resource)
		name = resources.ResourceQuota.Name
	case "limitranges":
		gvr = corev1.SchemeGroupVersion.WithResource(resource)
		name = resources.LimitRange.Name
	case "networkpolicies":
		gvr = networkingv1.SchemeGroupVersion.WithResource(resource)
		name = resources.NetworkPolicies[0].Name
	default:
		t.Fatalf("unknown protection resource %q", resource)
	}
	object, err := client.Tracker().Get(gvr, resources.Namespace.Name, name)
	if err != nil {
		t.Fatal(err)
	}
	return gvr, object.DeepCopyObject()
}

func installProtectionReadbackTamper(
	t *testing.T,
	client *fake.Clientset,
	resource string,
	tamper func(runtime.Object),
) {
	t.Helper()
	var mutationSeen atomic.Bool
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			mutationSeen.Store(true)
			return false, nil, nil
		})
	}
	client.PrependReactor("get", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !mutationSeen.Load() {
			return false, nil, nil
		}
		get := action.(k8stesting.GetAction)
		tracked, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), get.GetName())
		if err != nil {
			return true, nil, err
		}
		readBack := tracked.DeepCopyObject()
		tamper(readBack)
		return true, readBack, nil
	})
}

func installDeploymentReadbackTamper(t *testing.T, client *fake.Clientset, tamper func(*appsv1.Deployment)) {
	t.Helper()
	var mutationSeen atomic.Bool
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
			mutationSeen.Store(true)
			return false, nil, nil
		})
	}
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !mutationSeen.Load() {
			return false, nil, nil
		}
		get := action.(k8stesting.GetAction)
		tracked, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), get.GetName())
		if err != nil {
			return true, nil, err
		}
		readBack := tracked.(*appsv1.Deployment).DeepCopy()
		tamper(readBack)
		return true, readBack, nil
	})
}

func applyDocumentedDeploymentDefaults(deployment *appsv1.Deployment) {
	deployment.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
	podSpec := &deployment.Spec.Template.Spec
	if len(podSpec.Volumes) == 0 {
		podSpec.Volumes = nil
	}
	podSpec.RestartPolicy = corev1.RestartPolicyAlways
	podSpec.DNSPolicy = corev1.DNSClusterFirst
	podSpec.SchedulerName = corev1.DefaultSchedulerName
	podSpec.TerminationGracePeriodSeconds = ptr.To[int64](30)
	for index := range podSpec.Containers {
		container := &podSpec.Containers[index]
		if len(container.VolumeMounts) == 0 {
			container.VolumeMounts = nil
		}
		container.ImagePullPolicy = corev1.PullIfNotPresent
		container.TerminationMessagePath = corev1.TerminationMessagePathDefault
		container.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		for portIndex := range container.Ports {
			container.Ports[portIndex].Protocol = corev1.ProtocolTCP
		}
	}
}

func mutationSequence(actions []k8stesting.Action) []string {
	sequence := make([]string, 0)
	for _, action := range actions {
		if action.GetVerb() != "create" && action.GetVerb() != "update" {
			continue
		}
		var name string
		switch action := action.(type) {
		case k8stesting.CreateAction:
			name = action.GetObject().(metav1.Object).GetName()
		case k8stesting.UpdateAction:
			name = action.GetObject().(metav1.Object).GetName()
		}
		sequence = append(sequence, action.GetVerb()+" "+action.GetResource().Resource+"/"+name)
	}
	return sequence
}

func storedProtectionHashes(t *testing.T, client *fake.Clientset, command provisioner.CreateWorkloadCommand) map[string]string {
	t.Helper()
	resources, err := BuildResourceSet(validCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	objects := make([]metav1.Object, 0, len(resources.NetworkPolicies)+3)
	serviceAccount, err := client.CoreV1().ServiceAccounts(resources.Namespace.Name).Get(ctx, resources.ServiceAccount.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	objects = append(objects, serviceAccount)
	quota, err := client.CoreV1().ResourceQuotas(resources.Namespace.Name).Get(ctx, resources.ResourceQuota.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	objects = append(objects, quota)
	limitRange, err := client.CoreV1().LimitRanges(resources.Namespace.Name).Get(ctx, resources.LimitRange.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	objects = append(objects, limitRange)
	for _, desired := range resources.NetworkPolicies {
		policy, getErr := client.NetworkingV1().NetworkPolicies(resources.Namespace.Name).Get(ctx, desired.Name, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		objects = append(objects, policy)
	}

	hashes := make(map[string]string, len(objects))
	for _, object := range objects {
		hash := object.GetAnnotations()[specHashAnnotation]
		decoded, decodeErr := hex.DecodeString(hash)
		if decodeErr != nil || len(decoded) != 32 {
			t.Fatalf("%T %q spec hash = %q, want SHA-256 hex", object, object.GetName(), hash)
		}
		key := fmt.Sprintf("%T/%s", object, object.GetName())
		hashes[key] = hash
	}
	return hashes
}

func installCreateErrorAfterCommit(t *testing.T, client *fake.Clientset, resource string, failure func(k8stesting.Action) error) {
	t.Helper()
	client.PrependReactor("create", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		object := action.(k8stesting.CreateAction).GetObject()
		if err := client.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, nil, failure(action)
	})
}

func waitForWorkloadLockRefs(t *testing.T, locks *workloadLockSet, key workloadKey, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		locks.mu.Lock()
		entry := locks.entries[key]
		got := 0
		if entry != nil {
			got = entry.refs
		}
		locks.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock refs for target/instance = %d, want %d", got, want)
		}
		goruntime.Gosched()
	}
}

func assertWorkloadLockEntries(t *testing.T, locks *workloadLockSet, want int) {
	t.Helper()
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if got := len(locks.entries); got != want {
		t.Fatalf("workload lock entries = %d, want %d", got, want)
	}
}

type coreOverrideClient struct {
	kubernetes.Interface
	core typedcorev1.CoreV1Interface
}

func (c *coreOverrideClient) CoreV1() typedcorev1.CoreV1Interface {
	return c.core
}

type coreOverride struct {
	typedcorev1.CoreV1Interface
	namespaces typedcorev1.NamespaceInterface
}

func (c *coreOverride) Namespaces() typedcorev1.NamespaceInterface {
	return c.namespaces
}

type deadlineObservingNamespaces struct {
	typedcorev1.NamespaceInterface
	getCount int
	observed chan<- error
}

type asynchronousDeleteNamespaces struct {
	typedcorev1.NamespaceInterface
	deleting         atomic.Bool
	deleteAccepted   chan<- struct{}
	postDeleteRead   chan<- struct{}
	deletionComplete <-chan struct{}
	deleteOptions    metav1.DeleteOptions
}

func (n *asynchronousDeleteNamespaces) Delete(_ context.Context, _ string, options metav1.DeleteOptions) error {
	n.deleteOptions = options
	n.deleting.Store(true)
	n.deleteAccepted <- struct{}{}
	return nil
}

func (n *asynchronousDeleteNamespaces) Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Namespace, error) {
	if !n.deleting.Load() {
		return n.NamespaceInterface.Get(ctx, name, options)
	}
	select {
	case <-n.deletionComplete:
		if n.deleting.CompareAndSwap(true, false) {
			if err := n.NamespaceInterface.Delete(ctx, name, n.deleteOptions); err != nil {
				return nil, err
			}
		}
		return n.NamespaceInterface.Get(ctx, name, options)
	default:
		current, err := n.NamespaceInterface.Get(ctx, name, options)
		if err != nil {
			return nil, err
		}
		now := metav1.Now()
		current.DeletionTimestamp = &now
		select {
		case n.postDeleteRead <- struct{}{}:
		default:
		}
		return current, nil
	}
}

type parallelCreateNamespaces struct {
	typedcorev1.NamespaceInterface
	blockedName           string
	parallelName          string
	blockedCreateEntered  chan<- struct{}
	releaseBlockedCreate  <-chan struct{}
	parallelCreateEntered chan<- struct{}
}

func (n *parallelCreateNamespaces) Create(ctx context.Context, namespace *corev1.Namespace, options metav1.CreateOptions) (*corev1.Namespace, error) {
	switch namespace.Name {
	case n.blockedName:
		n.blockedCreateEntered <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.releaseBlockedCreate:
		}
	case n.parallelName:
		n.parallelCreateEntered <- struct{}{}
	}
	namespace = namespace.DeepCopy()
	namespace.UID = types.UID("test-" + namespace.Name)
	namespace.ResourceVersion = "1"
	return n.NamespaceInterface.Create(ctx, namespace, options)
}

func (n *deadlineObservingNamespaces) Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Namespace, error) {
	n.getCount++
	if n.getCount <= 2 {
		return n.NamespaceInterface.Get(ctx, name, options)
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		n.observed <- errors.New("rollback context has no deadline")
		return nil, errors.New("rollback context has no deadline")
	}
	<-ctx.Done()
	select {
	case n.observed <- ctx.Err():
	default:
	}
	return nil, ctx.Err()
}
