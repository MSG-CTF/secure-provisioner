package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ImagePolicyCatalog is an operator-owned, immutable-at-runtime set of
// requirements for published challenge images. It contains no secret values.
type ImagePolicyCatalog struct {
	managed                  map[string]struct{}
	images                   map[string]ImagePolicy
	graphByImage             map[string]*isolation.WorkloadNetwork
	graphManagedRepositories map[string]struct{}
}

type ImagePolicy struct {
	Image            string                     `json:"image"`
	Container        string                     `json:"container"`
	IsolationProfile string                     `json:"isolation_profile"`
	Status           string                     `json:"status"`
	BlockedReason    string                     `json:"blocked_reason,omitempty"`
	RequiresFlag     bool                       `json:"requires_flag,omitempty"`
	CISmokeEnabled   bool                       `json:"ci_smoke_enabled,omitempty"`
	RunAsUser        int64                      `json:"run_as_user"`
	Ports            []int                      `json:"ports"`
	ExposedPorts     []int                      `json:"exposed_ports"`
	WritablePaths    []WritablePath             `json:"writable_paths"`
	ReadinessHTTP    *provisioner.HTTPReadiness `json:"readiness_http,omitempty"`
}

func (catalog *ImagePolicyCatalog) RequiredFlagImages() []string {
	if catalog == nil {
		return nil
	}
	images := make([]string, 0)
	for image, policy := range catalog.images {
		if policy.RequiresFlag && policy.Status == "create_enabled" {
			images = append(images, image)
		}
	}
	slices.Sort(images)
	return images
}

func (catalog *ImagePolicyCatalog) AllowsFlag(image string) bool {
	if catalog == nil {
		return false
	}
	policy, found := catalog.images[image]
	return found && policy.RequiresFlag
}

type imagePolicyFile struct {
	SchemaVersion       int                         `json:"schema_version"`
	ManagedRepositories []string                    `json:"managed_repositories"`
	Images              []ImagePolicy               `json:"images"`
	WorkloadNetworks    []isolation.WorkloadNetwork `json:"workload_networks,omitempty"`
}

var ErrImagePolicyRejected = errors.New("image policy rejected")

func LoadImagePolicies(filename string) (*ImagePolicyCatalog, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(contents) > 1<<20 {
		return nil, errors.New("image policy file exceeds 1 MiB")
	}
	return ParseImagePolicies(contents)
}

func ParseImagePolicies(contents []byte) (*ImagePolicyCatalog, error) {
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return nil, fmt.Errorf("invalid image policy JSON: %w", err)
	}
	var config imagePolicyFile
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid image policy JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("image policy file must contain one JSON object")
	}
	if (config.SchemaVersion != 1 && config.SchemaVersion != 2) || len(config.ManagedRepositories) == 0 || len(config.Images) == 0 || (config.SchemaVersion == 1 && config.WorkloadNetworks != nil) {
		return nil, errors.New("image policy file requires schema_version 1 or 2, managed_repositories, and images; networks require version 2")
	}
	catalog := &ImagePolicyCatalog{managed: make(map[string]struct{}), images: make(map[string]ImagePolicy), graphByImage: make(map[string]*isolation.WorkloadNetwork), graphManagedRepositories: make(map[string]struct{})}
	for _, repository := range config.ManagedRepositories {
		if repository == "" || repository != strings.ToLower(repository) || strings.ContainsAny(repository, "@: \t\r\n") {
			return nil, fmt.Errorf("invalid managed image repository %q", repository)
		}
		if _, exists := catalog.managed[repository]; exists {
			return nil, fmt.Errorf("duplicate managed image repository %q", repository)
		}
		catalog.managed[repository] = struct{}{}
	}
	for _, policy := range config.Images {
		if !validImmutableImageReference(policy.Image) {
			return nil, fmt.Errorf("image policy requires an immutable image: %q", policy.Image)
		}
		repository, _, _ := strings.Cut(policy.Image, "@sha256:")
		if _, managed := catalog.managed[repository]; !managed {
			return nil, fmt.Errorf("image policy repository is not managed: %q", repository)
		}
		if _, exists := catalog.images[policy.Image]; exists {
			return nil, fmt.Errorf("duplicate image policy for %q", policy.Image)
		}
		if errs := validation.IsDNS1123Label(policy.Container); len(errs) != 0 {
			return nil, fmt.Errorf("invalid image policy container %q", policy.Container)
		}
		if policy.IsolationProfile != "WEB" && policy.IsolationProfile != "PWN" {
			return nil, fmt.Errorf("invalid image policy isolation profile %q", policy.IsolationProfile)
		}
		if policy.Status != "create_enabled" && policy.Status != "blocked" {
			return nil, fmt.Errorf("invalid image policy status %q", policy.Status)
		}
		if policy.Status == "blocked" && strings.TrimSpace(policy.BlockedReason) == "" {
			return nil, fmt.Errorf("blocked image policy needs a reason: %q", policy.Image)
		}
		if policy.Status == "create_enabled" && policy.BlockedReason != "" {
			return nil, fmt.Errorf("enabled image policy has a blocked reason: %q", policy.Image)
		}
		if policy.CISmokeEnabled && (policy.Status != "create_enabled" || policy.IsolationProfile != "WEB" || policy.RequiresFlag) {
			return nil, fmt.Errorf("CI smoke image must be an enabled WEB image without FLAG: %q", policy.Image)
		}
		if err := validateImagePolicyRequirements(policy); err != nil {
			return nil, fmt.Errorf("invalid image policy %q: %w", policy.Image, err)
		}
		catalog.images[policy.Image] = policy
	}
	seenGraphIDs := make(map[string]struct{}, len(config.WorkloadNetworks))
	for index := range config.WorkloadNetworks {
		graph := &config.WorkloadNetworks[index]
		if _, duplicate := seenGraphIDs[graph.ID]; duplicate {
			return nil, fmt.Errorf("duplicate workload network id %q", graph.ID)
		}
		seenGraphIDs[graph.ID] = struct{}{}
		requirements := make([]isolation.ContainerRequirement, 0, len(graph.Containers))
		for _, identity := range graph.Containers {
			image, known := catalog.images[identity.Image]
			if !known || image.Status != "create_enabled" || image.Container != identity.Name || image.IsolationProfile != string(graph.IsolationProfile) || !samePolicyPorts(image.Ports, identity.Ports) {
				return nil, fmt.Errorf("workload network %q identity lacks an enabled matching image policy", graph.ID)
			}
			if _, duplicate := catalog.graphByImage[identity.Image]; duplicate {
				return nil, fmt.Errorf("image belongs to more than one workload network: %q", identity.Image)
			}
			requirements = append(requirements, isolation.ContainerRequirement{Name: identity.Name, Ports: slices.Clone(identity.Ports)})
		}
		if err := isolation.ValidateWorkloadNetwork(graph, graph.IsolationProfile, requirements); err != nil {
			return nil, fmt.Errorf("invalid workload network %q: %w", graph.ID, err)
		}
		for _, identity := range graph.Containers {
			catalog.graphByImage[identity.Image] = isolation.CloneWorkloadNetwork(graph)
			catalog.graphManagedRepositories[imageRepository(identity.Image)] = struct{}{}
		}
	}
	return catalog, nil
}

func samePolicyPorts(first, second []int) bool {
	if len(first) != len(second) {
		return false
	}
	a, b := slices.Clone(first), slices.Clone(second)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (catalog *ImagePolicyCatalog) AllowsCISmoke(image string) bool {
	if catalog == nil {
		return false
	}
	policy, found := catalog.images[image]
	return found && policy.CISmokeEnabled && policy.Status == "create_enabled" && policy.IsolationProfile == "WEB" && !policy.RequiresFlag
}

func validateImagePolicyRequirements(policy ImagePolicy) error {
	if policy.RunAsUser <= 0 || len(policy.Ports) == 0 || policy.ExposedPorts == nil || len(policy.WritablePaths) == 0 {
		return errors.New("run_as_user, ports, exposed_ports, and writable_paths are required")
	}
	seenPorts := make(map[int]struct{}, len(policy.Ports))
	for _, port := range policy.Ports {
		if !validPort(port) {
			return errors.New("port must be between 1 and 65535")
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return errors.New("duplicate port")
		}
		seenPorts[port] = struct{}{}
	}
	if policy.ReadinessHTTP != nil {
		if _, declared := seenPorts[policy.ReadinessHTTP.Port]; !declared || !validHTTPReadinessPath(policy.ReadinessHTTP.Path) {
			return errors.New("HTTP readiness path and port must match a declared container port")
		}
	}
	seenPublic := make(map[int]struct{}, len(policy.ExposedPorts))
	for _, port := range policy.ExposedPorts {
		if _, declared := seenPorts[port]; !declared {
			return errors.New("exposed port is not declared")
		}
		if _, duplicate := seenPublic[port]; duplicate {
			return errors.New("duplicate exposed port")
		}
		seenPublic[port] = struct{}{}
	}
	paths := make([]string, 0, len(policy.WritablePaths))
	for _, writable := range policy.WritablePaths {
		if writable.SizeMiB <= 0 || writable.Path == "/" || !strings.HasPrefix(writable.Path, "/") || path.Clean(writable.Path) != writable.Path {
			return errors.New("invalid writable path or size")
		}
		for _, reserved := range []string{"/proc", "/sys", "/dev", "/var/run/secrets"} {
			if writable.Path == reserved || strings.HasPrefix(writable.Path, reserved+"/") {
				return errors.New("reserved writable path")
			}
		}
		for _, existing := range paths {
			if writable.Path == existing || strings.HasPrefix(writable.Path, existing+"/") || strings.HasPrefix(existing, writable.Path+"/") {
				return errors.New("duplicate or nested writable path")
			}
		}
		if policy.IsolationProfile == "PWN" && writable.Path != "/tmp" && !strings.HasPrefix(writable.Path, "/tmp/") {
			return errors.New("PWN writable path must be under /tmp")
		}
		paths = append(paths, writable.Path)
	}
	return nil
}

// Apply replaces caller-supplied requirements only for exact, reviewed image
// digests. Unknown digests in managed repositories fail closed.
func (catalog *ImagePolicyCatalog) Apply(request *CreateWorkloadRequest) error {
	if catalog == nil || request == nil {
		return nil
	}
	request.workloadNetwork = nil
	if request.Workload.Image != "" {
		if _, managed := catalog.managed[imageRepository(request.Workload.Image)]; managed {
			return fmt.Errorf("%w: managed images require containers[]", ErrImagePolicyRejected)
		}
	}
	selected := make(map[int]ImagePolicy)
	for index, container := range request.Workload.Containers {
		policy, known := catalog.images[container.Image]
		if !known {
			if _, managed := catalog.managed[imageRepository(container.Image)]; managed {
				return fmt.Errorf("%w: image digest has no reviewed policy", ErrImagePolicyRejected)
			}
			continue
		}
		if _, graphManaged := catalog.graphManagedRepositories[imageRepository(container.Image)]; graphManaged && catalog.graphByImage[container.Image] == nil {
			return fmt.Errorf("%w: graph-managed repository requires an exact workload network", ErrImagePolicyRejected)
		}
		if policy.Status != "create_enabled" {
			return fmt.Errorf("%w: image is not ready for deployment", ErrImagePolicyRejected)
		}
		if policy.Container != container.Name || policy.IsolationProfile != request.IsolationProfile || !slices.Equal(policy.Ports, container.Ports) {
			return fmt.Errorf("%w: image, container, profile, or ports do not match", ErrImagePolicyRejected)
		}
		selected[index] = policy
	}
	if len(selected) != 0 && len(selected) != len(request.Workload.Containers) {
		return fmt.Errorf("%w: managed images cannot run with unreviewed companion containers", ErrImagePolicyRejected)
	}
	var graph *isolation.WorkloadNetwork
	for _, container := range request.Workload.Containers {
		candidate := catalog.graphByImage[container.Image]
		if candidate == nil {
			continue
		}
		if graph != nil && graph.ID != candidate.ID {
			return fmt.Errorf("%w: mixed workload network image sets", ErrImagePolicyRejected)
		}
		graph = candidate
	}
	if graph != nil {
		if len(request.Workload.Containers) != len(graph.Containers) || request.IsolationProfile != string(graph.IsolationProfile) {
			return fmt.Errorf("%w: incomplete workload network image set", ErrImagePolicyRejected)
		}
		expected := make(map[string]isolation.NetworkIdentity, len(graph.Containers))
		for _, identity := range graph.Containers {
			expected[identity.Name] = identity
		}
		seen := make(map[string]struct{}, len(request.Workload.Containers))
		for _, container := range request.Workload.Containers {
			identity, found := expected[container.Name]
			if !found || identity.Image != container.Image || !samePolicyPorts(identity.Ports, container.Ports) {
				return fmt.Errorf("%w: workload network image identity mismatch", ErrImagePolicyRejected)
			}
			if _, duplicate := seen[container.Name]; duplicate {
				return fmt.Errorf("%w: duplicate workload network container", ErrImagePolicyRejected)
			}
			seen[container.Name] = struct{}{}
		}
		request.workloadNetwork = isolation.CloneWorkloadNetwork(graph)
	}
	for index, policy := range selected {
		container := &request.Workload.Containers[index]
		container.requiresFlag = policy.RequiresFlag
		container.RunAsUser = policy.RunAsUser
		container.Expose = false
		container.ExposedPorts = slices.Clone(policy.ExposedPorts)
		container.WritablePaths = slices.Clone(policy.WritablePaths)
		if policy.ReadinessHTTP != nil {
			readiness := *policy.ReadinessHTTP
			container.readinessHTTP = &readiness
		}
	}
	return nil
}

func validHTTPReadinessPath(value string) bool {
	return provisioner.ValidHTTPReadinessPath(value)
}

func imageRepository(image string) string {
	repository, _, _ := strings.Cut(image, "@sha256:")
	return repository
}
