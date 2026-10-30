package httpapi

import "github.com/MSG-CTF/secure-provisioner/internal/provisioner"

func (catalog *ImagePolicyCatalog) StartupCPUProfiles() map[string]provisioner.StartupCPUProfile {
	profiles := make(map[string]provisioner.StartupCPUProfile)
	if catalog != nil {
		for image, policy := range catalog.images {
			if policy.Status == "create_enabled" && policy.StartupCPUMillicores > 0 {
				profiles[image] = provisioner.StartupCPUProfile{Steady: policy.SteadyCPUMillicores, Peak: policy.StartupCPUMillicores}
			}
		}
	}
	return profiles
}
