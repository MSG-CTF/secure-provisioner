package main

import (
	"testing"
	"time"
)

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
