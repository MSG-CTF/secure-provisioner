package isolation

// ValidateServiceAliases validates only operator-approved names. Request JSON
// has no corresponding field; aliases become part of the immutable policy.
func ValidateServiceAliases(containers []ContainerRequirement) error {
	seen := make(map[string]bool)
	for _, container := range containers {
		seen[container.Name] = true
	}
	for _, container := range containers {
		if len(container.ServiceAliases) > 1 {
			return rejected("at most one service alias is supported")
		}
		for _, alias := range container.ServiceAliases {
			if !validNetworkID(alias) || seen[alias] {
				return rejected("invalid or duplicate service alias")
			}
			seen[alias] = true
		}
	}
	return nil
}
