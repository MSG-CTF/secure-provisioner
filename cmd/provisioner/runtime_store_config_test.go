package main

import "testing"

func TestLoadRuntimeStoreConfigRequiresDatabaseURLByDefault(t *testing.T) {
	if _, err := loadRuntimeStoreConfig(environment(map[string]string{})); err == nil {
		t.Fatal("store without a database URL started with an implicit memory store")
	}
}

func TestLoadRuntimeStoreConfigUsesPostgresByDefault(t *testing.T) {
	config, err := loadRuntimeStoreConfig(environment(map[string]string{
		"PROVISIONER_DATABASE_URL": "postgres://provisioner:password@localhost/provisioner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != "postgres" {
		t.Fatalf("store mode = %q, want postgres", config.Mode)
	}
}

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
