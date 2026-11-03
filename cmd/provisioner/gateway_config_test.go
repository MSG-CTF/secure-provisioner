package main

import (
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
)

func TestGatewayTCPDraftOptionDefaultsToLegacyAndParsesExplicitModes(t *testing.T) {
	for input, want := range map[string]gateway.PublicTransport{"": gateway.TransportLegacy, "legacy": gateway.TransportLegacy, "tls": gateway.TransportTLS, "plain": gateway.TransportPlain} {
		values := map[string]string{"PROVISIONER_CLUSTER_REGISTRY": "clusters.json", "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE": "/synthetic/token", "PROVISIONER_GATEWAY_TCP_TRANSPORT": input}
		c, err := loadConfig(environment(values))
		if err != nil || c.GatewayTCPTransport != want {
			t.Fatalf("mode=%q got=%q want=%q err=%v", input, c.GatewayTCPTransport, want, err)
		}
	}
}

func TestGatewayConfigIsOffByDefaultAndRequiresLongTimeout(t *testing.T) {
	values := map[string]string{"PROVISIONER_CLUSTER_REGISTRY": "clusters.json", "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken}
	c, err := loadConfig(environment(values))
	if err != nil || c.GatewayTokenFile != "" || c.GatewayTimeout != 90*time.Second || c.GatewayMaxInflight != 1 {
		t.Fatal(c, err)
	}
	values["PROVISIONER_GATEWAY_REQUEST_TIMEOUT"] = "74s"
	if _, err = loadConfig(environment(values)); err == nil {
		t.Fatal("short Gateway timeout accepted")
	}
}

func TestGatewayTCPDraftOptionRejectsInvalidValuesAndRequiresToken(t *testing.T) {
	for _, mode := range []string{"unsupported", "PLAIN", "plain", "tls"} {
		values := map[string]string{"PROVISIONER_CLUSTER_REGISTRY": "clusters.json", "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_GATEWAY_TCP_TRANSPORT": mode}
		if _, err := loadConfig(environment(values)); err == nil {
			t.Fatalf("accepted mode %q without the required contract configuration", mode)
		}
	}
}
