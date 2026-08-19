package main

import "testing"

func TestLoadRuntimeStoreConfigRequiresDatabaseURLForPostgres(t *testing.T) {
	if _, err := loadRuntimeStoreConfig(environment(map[string]string{"PROVISIONER_STORE_MODE": "postgres"})); err == nil {
		t.Fatal("missing database URL was accepted")
	}
}

func TestLoadRuntimeStoreConfigRejectsInvalidWorkerSettings(t *testing.T) {
	for _, values := range []map[string]string{
		{"PROVISIONER_STORE_MODE": "unknown"},
		{"PROVISIONER_STORE_MODE": "memory", "PROVISIONER_WORKERS": "0"},
		{"PROVISIONER_STORE_MODE": "memory", "PROVISIONER_LEASE_DURATION": "1m", "PROVISIONER_LEASE_RENEW_INTERVAL": "1m"},
		{"PROVISIONER_STORE_MODE": "memory", "PROVISIONER_LEASE_DURATION": "1m", "PROVISIONER_LEASE_RENEW_INTERVAL": "2m"},
	} {
		if config, err := loadRuntimeStoreConfig(environment(values)); err == nil {
			t.Fatalf("invalid config accepted: %#v", config)
		}
	}
}
