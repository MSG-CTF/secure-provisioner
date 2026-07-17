package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

var ErrRuntimeClassUnavailable = errors.New("runtime class is unavailable")

type fakeCluster struct {
	mu             sync.RWMutex
	challengeURL   string
	resources      map[string]RuntimeResources
	runtimeClasses map[string]bool
}

func newFakeCluster(challengeURL string) *fakeCluster {
	return &fakeCluster{
		challengeURL: strings.TrimRight(challengeURL, "/"),
		resources:    make(map[string]RuntimeResources),
		runtimeClasses: map[string]bool{
			"":     true,
			"runc": true,
		},
	}
}

func (cluster *fakeCluster) create(_ context.Context, instance Instance, challenge Challenge) (RuntimeResources, error) {
	if !cluster.runtimeClasses[challenge.RuntimeClass] {
		return RuntimeResources{}, fmt.Errorf("%w: %s", ErrRuntimeClassUnavailable, challenge.RuntimeClass)
	}

	if !hasImmutableSHA256Digest(challenge.Image) {
		return RuntimeResources{}, errors.New("challenge image must use an immutable sha256 digest")
	}

	cluster.mu.Lock()
	defer cluster.mu.Unlock()

	if resources, exists := cluster.resources[instance.InstanceID]; exists {
		return resources, nil
	}

	resources := RuntimeResources{
		InstanceID:               instance.InstanceID,
		Namespace:                namespaceFor(instance),
		Image:                    challenge.Image,
		ContainerPort:            challenge.ContainerPort,
		RuntimeClass:             challenge.RuntimeClass,
		ResourceQuotaApplied:     true,
		LimitRangeApplied:        true,
		DefaultDenyNetworkPolicy: true,
		DNSOnlyEgress:            true,
		ServiceAccountAutomount:  false,
		AllowPrivilegeEscalation: false,
		Privileged:               false,
		HostNetwork:              false,
		HostPID:                  false,
		HostIPC:                  false,
		HostPathAllowed:          false,
		DropAllCapabilities:      true,
		SeccompProfile:           "RuntimeDefault",
		Endpoint:                 cluster.challengeURL + "/mock/v1/challenges/" + url.PathEscape(instance.InstanceID),
	}
	cluster.resources[instance.InstanceID] = resources

	return resources, nil
}

func (cluster *fakeCluster) delete(_ context.Context, instanceID string) error {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()

	delete(cluster.resources, instanceID)
	return nil
}

func (cluster *fakeCluster) get(instanceID string) (RuntimeResources, bool) {
	cluster.mu.RLock()
	defer cluster.mu.RUnlock()

	resources, exists := cluster.resources[instanceID]
	return resources, exists
}

func namespaceFor(instance Instance) string {
	digest := sha256.Sum256([]byte(instance.TeamID + "\x00" + instance.ChallengeID + "\x00" + instance.InstanceID))
	return "ctf-" + hex.EncodeToString(digest[:])[:16]
}

func hasImmutableSHA256Digest(image string) bool {
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}
