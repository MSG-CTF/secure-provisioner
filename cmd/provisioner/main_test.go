package main

import (
	"testing"
	"time"
)

func TestLoadRuntimeConfigDefaultsToMemoryAndTenWorkers(t *testing.T) {
	t.Setenv("PROVISIONER_STORE_MODE", "")
	t.Setenv("PROVISIONER_DATABASE_URL", "")
	t.Setenv("PROVISIONER_WORKERS", "")
	config, err := loadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.StoreMode != "memory" {
		t.Fatalf("store mode = %q, want memory", config.StoreMode)
	}
	if config.WorkerOptions.Concurrency != 10 {
		t.Fatalf("workers = %d, want 10", config.WorkerOptions.Concurrency)
	}
	if config.WorkerOptions.PollInterval != 200*time.Millisecond || config.WorkerOptions.LeaseDuration != 3*time.Minute {
		t.Fatalf("worker durations = %+v", config.WorkerOptions)
	}
}

func TestLoadRuntimeConfigRequiresDSNForPostgres(t *testing.T) {
	t.Setenv("PROVISIONER_STORE_MODE", "postgres")
	t.Setenv("PROVISIONER_DATABASE_URL", "")
	if _, err := loadRuntimeConfig(); err == nil {
		t.Fatal("postgres store without PROVISIONER_DATABASE_URL must fail")
	}
}

func TestLoadRuntimeConfigRejectsUnsupportedStoreMode(t *testing.T) {
	t.Setenv("PROVISIONER_STORE_MODE", "redis")
	if _, err := loadRuntimeConfig(); err == nil {
		t.Fatal("unsupported store mode must fail")
	}
}
