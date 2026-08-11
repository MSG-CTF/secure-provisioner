package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	managedByLabel = "secure-provisioner"
	instanceKey    = "ctf.msg/instance-key"
	instanceIDKey  = "ctf.msg/instance-id"
)

type KubernetesOptions struct {
	Kubeconfig       string
	PublicHost       string
	VerificationHost string
}

type kubernetesCluster struct {
	client           kubernetes.Interface
	publicHost       string
	verificationHost string
	httpClient       *http.Client
	mu               sync.RWMutex
	resources        map[string]RuntimeResources
}

func NewKubernetesService(
	mockURL string,
	logger *slog.Logger,
	expirationInterval time.Duration,
	options KubernetesOptions,
) (*Service, error) {
	cluster, err := newKubernetesCluster(options)
	if err != nil {
		return nil, err
	}
	return newService(mockURL, logger, expirationInterval, cluster), nil
}

func NewPostgresKubernetesService(
	ctx context.Context,
	mockURL string,
	logger *slog.Logger,
	expirationInterval time.Duration,
	options KubernetesOptions,
	dsn string,
) (*Service, error) {
	service, err := NewKubernetesService(mockURL, logger, expirationInterval, options)
	if err != nil {
		return nil, err
	}
	store, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		return nil, err
	}
	service.store = store
	return service, nil
}

func newKubernetesCluster(options KubernetesOptions) (*kubernetesCluster, error) {
	if strings.TrimSpace(options.PublicHost) == "" {
		return nil, errors.New("K3S_PUBLIC_HOST is required for the Kubernetes cluster mode")
	}

	config, err := kubernetesConfig(options.Kubeconfig)
	if err != nil {
		return nil, err
	}
	config.QPS = 20
	config.Burst = 40

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}

	verificationHost := strings.TrimSpace(options.VerificationHost)
	if verificationHost == "" {
		verificationHost = "127.0.0.1"
	}

	return &kubernetesCluster{
		client:           client,
		publicHost:       strings.TrimSpace(options.PublicHost),
		verificationHost: verificationHost,
		httpClient:       &http.Client{Timeout: 2 * time.Second},
		resources:        make(map[string]RuntimeResources),
	}, nil
}

func kubernetesConfig(kubeconfig string) (*rest.Config, error) {
	if strings.TrimSpace(kubeconfig) != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
		return config, nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster Kubernetes config: %w", err)
	}
	return config, nil
}

func (cluster *kubernetesCluster) create(
	ctx context.Context,
	instance Instance,
	challenge Challenge,
	reservation Reservation,
) (RuntimeResources, error) {
	if !hasImmutableSHA256Digest(challenge.Image) {
		return RuntimeResources{}, errors.New("challenge image must use an immutable sha256 digest")
	}
	if challenge.ContainerPort < 1 || challenge.ContainerPort > 65535 {
		return RuntimeResources{}, errors.New("challenge container port is invalid")
	}
	if reservation.CPUMillicores < 20 || reservation.MemoryMiB < 32 || reservation.EphemeralStorageMiB < 32 {
		return RuntimeResources{}, errors.New("scheduler reservation is too small")
	}

	if err := cluster.validateRuntimeClass(ctx, challenge.RuntimeClass); err != nil {
		return RuntimeResources{}, err
	}

	namespace := namespaceFor(instance)
	labels := map[string]string{
		"app.kubernetes.io/managed-by": managedByLabel,
		instanceKey:                    stableLabel(instance.InstanceID),
	}
	annotations := map[string]string{
		instanceIDKey:          instance.InstanceID,
		"ctf.msg/team-id":      strconv.FormatInt(instance.TeamID, 10),
		"ctf.msg/challenge-id": instance.ChallengeID,
	}

	if err := cluster.ensureNamespace(ctx, namespace, labels, annotations); err != nil {
		return RuntimeResources{}, err
	}
	if err := cluster.ensureRuntimeResources(ctx, namespace, labels, instance, challenge, reservation); err != nil {
		return RuntimeResources{}, err
	}
	if err := cluster.waitForDeployment(ctx, namespace); err != nil {
		return RuntimeResources{}, err
	}

	service, err := cluster.client.CoreV1().Services(namespace).Get(ctx, "challenge", metav1.GetOptions{})
	if err != nil {
		return RuntimeResources{}, fmt.Errorf("get challenge Service: %w", err)
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].NodePort == 0 {
		return RuntimeResources{}, errors.New("challenge Service has no allocated NodePort")
	}

	nodePort := service.Spec.Ports[0].NodePort
	resources := RuntimeResources{
		InstanceID:               instance.InstanceID,
		Namespace:                namespace,
		Image:                    challenge.Image,
		ContainerPort:            challenge.ContainerPort,
		RuntimeClass:             challenge.RuntimeClass,
		ResourceQuotaApplied:     true,
		LimitRangeApplied:        true,
		DefaultDenyNetworkPolicy: true,
		DNSOnlyEgress:            false,
		ServiceAccountAutomount:  false,
		AllowPrivilegeEscalation: false,
		Privileged:               false,
		HostNetwork:              false,
		HostPID:                  false,
		HostIPC:                  false,
		HostPathAllowed:          false,
		DropAllCapabilities:      true,
		SeccompProfile:           "RuntimeDefault",
		Endpoint:                 httpEndpoint(cluster.publicHost, nodePort, "/"),
		NodePort:                 nodePort,
	}

	cluster.mu.Lock()
	cluster.resources[instance.InstanceID] = resources
	cluster.mu.Unlock()
	return resources, nil
}

func (cluster *kubernetesCluster) verify(ctx context.Context, resources RuntimeResources) error {
	endpoint := httpEndpoint(cluster.verificationHost, resources.NodePort, "/health")
	return wait.PollUntilContextTimeout(ctx, time.Second, 45*time.Second, true, func(ctx context.Context) (bool, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return false, err
		}
		response, err := cluster.httpClient.Do(request)
		if err != nil {
			return false, nil
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode == http.StatusOK, nil
	})
}

func (cluster *kubernetesCluster) delete(ctx context.Context, instanceID string) error {
	namespace, err := cluster.findNamespace(ctx, instanceID)
	if err != nil {
		return err
	}
	if namespace == "" {
		cluster.forget(instanceID)
		return nil
	}

	policy := metav1.DeletePropagationForeground
	err = cluster.client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{PropagationPolicy: &policy})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete instance Namespace: %w", err)
	}

	err = wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := cluster.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	if err != nil {
		return fmt.Errorf("wait for instance Namespace deletion: %w", err)
	}

	cluster.forget(instanceID)
	return nil
}

func (cluster *kubernetesCluster) get(instanceID string) (RuntimeResources, bool) {
	cluster.mu.RLock()
	defer cluster.mu.RUnlock()
	resources, exists := cluster.resources[instanceID]
	return resources, exists
}

func (cluster *kubernetesCluster) validateRuntimeClass(ctx context.Context, runtimeClass string) error {
	if runtimeClass == "" || runtimeClass == "runc" {
		return nil
	}
	_, err := cluster.client.NodeV1().RuntimeClasses().Get(ctx, runtimeClass, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: %s", ErrRuntimeClassUnavailable, runtimeClass)
	}
	if err != nil {
		return fmt.Errorf("get RuntimeClass %s: %w", runtimeClass, err)
	}
	return nil
}

func (cluster *kubernetesCluster) ensureNamespace(
	ctx context.Context,
	name string,
	labels map[string]string,
	annotations map[string]string,
) error {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:        name,
		Labels:      labels,
		Annotations: annotations,
	}}
	namespace.Labels["pod-security.kubernetes.io/enforce"] = "restricted"
	namespace.Labels["pod-security.kubernetes.io/enforce-version"] = "latest"

	_, err := cluster.client.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create instance Namespace: %w", err)
	}

	existing, err := cluster.client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get existing instance Namespace: %w", err)
	}
	if existing.Annotations[instanceIDKey] != annotations[instanceIDKey] {
		return errors.New("instance Namespace is owned by another instance")
	}
	return nil
}

func (cluster *kubernetesCluster) ensureRuntimeResources(
	ctx context.Context,
	namespace string,
	labels map[string]string,
	instance Instance,
	challenge Challenge,
	reservation Reservation,
) error {
	objects := cluster.runtimeObjects(namespace, labels, instance, challenge, reservation)

	if _, err := cluster.client.CoreV1().ResourceQuotas(namespace).Create(ctx, objects.quota, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ResourceQuota: %w", err)
	}
	if _, err := cluster.client.CoreV1().LimitRanges(namespace).Create(ctx, objects.limitRange, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create LimitRange: %w", err)
	}
	if _, err := cluster.client.CoreV1().ServiceAccounts(namespace).Create(ctx, objects.serviceAccount, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ServiceAccount: %w", err)
	}
	if _, err := cluster.client.NetworkingV1().NetworkPolicies(namespace).Create(ctx, objects.defaultDeny, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create default-deny NetworkPolicy: %w", err)
	}
	if _, err := cluster.client.NetworkingV1().NetworkPolicies(namespace).Create(ctx, objects.allowIngress, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ingress NetworkPolicy: %w", err)
	}
	if _, err := cluster.client.AppsV1().Deployments(namespace).Create(ctx, objects.deployment, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create challenge Deployment: %w", err)
	}
	if _, err := cluster.client.CoreV1().Services(namespace).Create(ctx, objects.service, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create challenge Service: %w", err)
	}
	return nil
}

type runtimeObjectSet struct {
	quota          *corev1.ResourceQuota
	limitRange     *corev1.LimitRange
	serviceAccount *corev1.ServiceAccount
	defaultDeny    *networkingv1.NetworkPolicy
	allowIngress   *networkingv1.NetworkPolicy
	deployment     *appsv1.Deployment
	service        *corev1.Service
}

func (cluster *kubernetesCluster) runtimeObjects(
	namespace string,
	labels map[string]string,
	instance Instance,
	challenge Challenge,
	reservation Reservation,
) runtimeObjectSet {
	falseValue := false
	trueValue := true
	replicas := int32(1)
	terminationGracePeriod := int64(5)
	cpuLimit := *resource.NewMilliQuantity(int64(reservation.CPUMillicores), resource.DecimalSI)
	cpuRequest := *resource.NewMilliQuantity(int64(max(reservation.CPUMillicores/2, 10)), resource.DecimalSI)
	memoryLimit := resource.MustParse(fmt.Sprintf("%dMi", reservation.MemoryMiB))
	memoryRequest := resource.MustParse(fmt.Sprintf("%dMi", max(reservation.MemoryMiB/2, 16)))
	ephemeralLimit := resource.MustParse(fmt.Sprintf("%dMi", reservation.EphemeralStorageMiB))
	ephemeralRequest := resource.MustParse(fmt.Sprintf("%dMi", max(reservation.EphemeralStorageMiB/2, 16)))
	containerPort := int32(challenge.ContainerPort)
	podLabels := map[string]string{
		"app.kubernetes.io/name":       "ctf-challenge",
		"app.kubernetes.io/managed-by": managedByLabel,
		instanceKey:                    labels[instanceKey],
	}

	var runtimeClassName *string
	if challenge.RuntimeClass != "" && challenge.RuntimeClass != "runc" {
		runtimeClassName = &challenge.RuntimeClass
	}

	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "instance-quota", Namespace: namespace},
		Spec: corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{
			corev1.ResourceRequestsCPU:              cpuLimit,
			corev1.ResourceRequestsMemory:           memoryLimit,
			corev1.ResourceRequestsEphemeralStorage: ephemeralLimit,
			corev1.ResourceLimitsCPU:                cpuLimit,
			corev1.ResourceLimitsMemory:             memoryLimit,
			corev1.ResourceLimitsEphemeralStorage:   ephemeralLimit,
			corev1.ResourcePods:                     resource.MustParse("2"),
			corev1.ResourceServices:                 resource.MustParse("2"),
		}},
	}
	limitRange := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "instance-defaults", Namespace: namespace},
		Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
			Type: corev1.LimitTypeContainer,
			DefaultRequest: corev1.ResourceList{
				corev1.ResourceCPU:              cpuRequest,
				corev1.ResourceMemory:           memoryRequest,
				corev1.ResourceEphemeralStorage: ephemeralRequest,
			},
			Default: corev1.ResourceList{
				corev1.ResourceCPU:              cpuLimit,
				corev1.ResourceMemory:           memoryLimit,
				corev1.ResourceEphemeralStorage: ephemeralLimit,
			},
		}}},
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: "challenge-runtime", Namespace: namespace},
		AutomountServiceAccountToken: &falseValue,
	}
	defaultDeny := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny-all", Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	allowIngress := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-challenge-ingress", Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "ctf-challenge"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{
				Protocol: pointer(corev1.ProtocolTCP),
				Port:     pointer(intstr.FromInt32(containerPort)),
			}}}},
		},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge", Namespace: namespace, Labels: podLabels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: podLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					ServiceAccountName:            "challenge-runtime",
					AutomountServiceAccountToken:  &falseValue,
					EnableServiceLinks:            &falseValue,
					RuntimeClassName:              runtimeClassName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &trueValue,
						RunAsUser:      pointer(int64(10001)),
						RunAsGroup:     pointer(int64(10001)),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            "challenge",
						Image:           challenge.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         challenge.Command,
						Env: []corev1.EnvVar{
							{Name: "INSTANCE_ID", Value: instance.InstanceID},
							{Name: "TEAM_ID", Value: strconv.FormatInt(instance.TeamID, 10)},
							{Name: "CHALLENGE_ID", Value: instance.ChallengeID},
						},
						Ports: []corev1.ContainerPort{{Name: "challenge", ContainerPort: containerPort, Protocol: corev1.ProtocolTCP}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:              cpuRequest,
								corev1.ResourceMemory:           memoryRequest,
								corev1.ResourceEphemeralStorage: ephemeralRequest,
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:              cpuLimit,
								corev1.ResourceMemory:           memoryLimit,
								corev1.ResourceEphemeralStorage: ephemeralLimit,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falseValue,
							ReadOnlyRootFilesystem:   &trueValue,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromString("challenge")}},
							InitialDelaySeconds: 1,
							PeriodSeconds:       2,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromString("challenge")}},
							InitialDelaySeconds: 5,
							PeriodSeconds:       10,
						},
					}},
				},
			},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge", Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: podLabels,
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       80,
				TargetPort: intstr.FromString("challenge"),
			}},
		},
	}

	return runtimeObjectSet{
		quota:          quota,
		limitRange:     limitRange,
		serviceAccount: serviceAccount,
		defaultDeny:    defaultDeny,
		allowIngress:   allowIngress,
		deployment:     deployment,
		service:        service,
	}
}

func (cluster *kubernetesCluster) waitForDeployment(ctx context.Context, namespace string) error {
	err := wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		deployment, err := cluster.client.AppsV1().Deployments(namespace).Get(ctx, "challenge", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return deployment.Status.ObservedGeneration >= deployment.Generation && deployment.Status.AvailableReplicas == 1, nil
	})
	if err != nil {
		return fmt.Errorf("wait for challenge Deployment: %w", err)
	}
	return nil
}

func (cluster *kubernetesCluster) findNamespace(ctx context.Context, instanceID string) (string, error) {
	cluster.mu.RLock()
	resources, exists := cluster.resources[instanceID]
	cluster.mu.RUnlock()
	if exists {
		return resources.Namespace, nil
	}

	namespaces, err := cluster.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: instanceKey + "=" + stableLabel(instanceID),
	})
	if err != nil {
		return "", fmt.Errorf("find instance Namespace: %w", err)
	}
	for _, namespace := range namespaces.Items {
		if namespace.Annotations[instanceIDKey] == instanceID {
			return namespace.Name, nil
		}
	}
	return "", nil
}

func (cluster *kubernetesCluster) forget(instanceID string) {
	cluster.mu.Lock()
	delete(cluster.resources, instanceID)
	cluster.mu.Unlock()
}

func stableLabel(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:16]
}

func httpEndpoint(host string, port int32, path string) string {
	scheme := "http"
	hostname := strings.TrimSpace(host)
	if parsed, err := url.Parse(hostname); err == nil && parsed.Hostname() != "" {
		scheme = parsed.Scheme
		hostname = parsed.Hostname()
	}
	return scheme + "://" + net.JoinHostPort(hostname, strconv.Itoa(int(port))) + path
}

func pointer[T any](value T) *T {
	return &value
}
