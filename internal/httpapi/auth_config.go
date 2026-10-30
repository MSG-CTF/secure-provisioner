package httpapi

import "github.com/MSG-CTF/secure-provisioner/internal/provisioner"

type ServiceAuthConfig struct {
	CurrentToken         string
	PreviousToken        string
	CheckerToken         string
	CheckerBackendTokens map[string]string
	WindowsRecoveryToken string
	CISmokeToken         string
	CISmokeTeamID        provisioner.TeamID
	CISmokeTargetID      string
}
