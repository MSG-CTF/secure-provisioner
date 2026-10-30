package gateway

import (
	"context"
	"maps"
	"net/http"
	"slices"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

// PublicOrigin does not publish a route or select an upstream. The authenticated
// Gateway derives the same hostname that a later HTTP Put must return.
func (c *Client) PublicOrigin(ctx context.Context, id string) (string, error) {
	var result struct {
		InstanceID string `json:"instance_id"`
		Hostname   string `json:"hostname"`
		Port       int    `json:"port"`
		TLS        *bool  `json:"tls"`
		URL        string `json:"url"`
	}
	if err := c.callRoute(ctx, http.MethodGet, id, "/origin", nil, &result); err != nil {
		return "", err
	}
	if result.InstanceID != id || !validHostname.MatchString(result.Hostname) || result.Port != 443 || result.TLS == nil || !*result.TLS || result.URL != "https://"+result.Hostname {
		return "", &APIError{Code: "GATEWAY_INVALID_RESPONSE"}
	}
	return result.URL, nil
}

func (a *Adapter) bindPublicOrigin(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadCommand, error) {
	needed := false
	for _, container := range command.Containers {
		needed = needed || container.PublicOriginEnv != ""
	}
	if !needed {
		return command, nil
	}
	resolver, ok := a.remote.(interface {
		PublicOrigin(context.Context, string) (string, error)
	})
	if !ok || command.RuntimeType != provisioner.RuntimeTypeKubernetes || !a.backend.Enabled(command.TargetID) {
		return command, operations.NewExecutionError("GATEWAY_ORIGIN_REQUIRED", false, nil)
	}
	origin, err := resolver.PublicOrigin(ctx, command.InstanceID)
	if err != nil {
		return command, hold("GATEWAY_ORIGIN_UNAVAILABLE", err)
	}
	command.Containers = slices.Clone(command.Containers)
	for i, container := range command.Containers {
		if container.PublicOriginEnv == "" {
			continue
		}
		if container.PublicOriginEnv != "PUBLIC_ORIGIN" {
			return command, operations.NewExecutionError("GATEWAY_ORIGIN_REQUIRED", false, nil)
		}
		container.Env = maps.Clone(container.Env)
		if container.Env == nil {
			container.Env = make(map[string]string)
		}
		container.Env[container.PublicOriginEnv] = origin
		command.Containers[i] = container
	}
	return command, nil
}

func publicOriginMatches(command provisioner.CreateWorkloadCommand, route Route) bool {
	for _, container := range command.Containers {
		if container.PublicOriginEnv != "" && (route.Protocol != "http" || !route.TLS || route.Port != 443 || route.URL == nil || container.Env[container.PublicOriginEnv] != *route.URL) {
			return false
		}
	}
	return true
}
