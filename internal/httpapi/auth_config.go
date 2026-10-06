package httpapi

import "github.com/MSG-CTF/secure-provisioner/internal/provisioner"

type ServiceAuthConfig struct {
	CurrentToken    string
	PreviousToken   string
	CISmokeToken    string
	CISmokeTeamID   provisioner.TeamID
	CISmokeTargetID string
}
