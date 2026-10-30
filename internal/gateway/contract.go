package gateway

import (
	"errors"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

// PublicTransport opts new TCP intents into the unapproved owner contract draft.
// Legacy requests omit both draft fields and remain compatible with Gateway v1.
type PublicTransport string

const (
	TransportLegacy PublicTransport = ""
	TransportTLS    PublicTransport = "tls"
	TransportPlain  PublicTransport = "plain"
)

func ParseTCPTransport(value string) (PublicTransport, error) {
	switch strings.TrimSpace(value) {
	case "", "legacy":
		return TransportLegacy, nil
	case "tls":
		return TransportTLS, nil
	case "plain":
		return TransportPlain, nil
	default:
		return TransportLegacy, errors.New("Gateway TCP transport must be legacy, tls, or plain")
	}
}

func (d Destination) validDraft() bool {
	if d.PublicTransport == TransportLegacy && d.OwnerTeamID == "" {
		return true
	}
	return d.Protocol == "tcp" && (d.PublicTransport == TransportTLS || d.PublicTransport == TransportPlain) && provisioner.TeamID(d.OwnerTeamID).Valid()
}
