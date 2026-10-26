package main

import (
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"strings"
	"testing"
	"time"
)

func TestImagePreparationDisabledDefaultAndCredentialsSeparated(t *testing.T) {
	cfg, err := loadImagePreparationConfig(func(string) string { return "" }, httpapi.ServiceAuthConfig{})
	if err != nil || cfg.Auth.Enabled || cfg.Worker.TTL != time.Minute || cfg.Worker.ObserveInterval != 30*time.Second {
		t.Fatalf("defaults=%+v %v", cfg, err)
	}
	env := map[string]string{"PROVISIONER_IMAGE_PREFETCH_ENABLED": "true", "PROVISIONER_IMAGE_PREFETCH_NODES": "/etc/nodes.json", "PROVISIONER_IMAGE_PREPARATION_TOKEN": strings.Repeat("a", 43), "PROVISIONER_IMAGE_READINESS_TOKEN": strings.Repeat("b", 43)}
	get := func(k string) string { return env[k] }
	if _, err := loadImagePreparationConfig(get, httpapi.ServiceAuthConfig{CurrentToken: env["PROVISIONER_IMAGE_PREPARATION_TOKEN"]}); err == nil {
		t.Fatal("full credential implicitly granted")
	}
	if _, err := loadImagePreparationConfig(get, httpapi.ServiceAuthConfig{}); err != nil {
		t.Fatal(err)
	}
	env["PROVISIONER_IMAGE_PREFETCH_READINESS_TTL"] = "10s"
	if _, err := loadImagePreparationConfig(get, httpapi.ServiceAuthConfig{}); err == nil {
		t.Fatal("TTL shorter than observe interval accepted")
	}
}
