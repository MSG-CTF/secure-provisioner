package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

func TestCheckerBackendSettingsMatchAuthenticatedBackends(t *testing.T) {
	// These are configuration identities, not request-selected callback URLs.
	checker := windowsruntime.CheckerRuntimeConfig{Backends: map[string]string{"internal": "https://internal.example", "external": "https://external.example"}}
	auth := httpapi.ServiceAuthConfig{CheckerBackendTokens: map[string]string{"internal": validInternalCheckerToken, "external": validExternalCheckerToken}}
	if err := validateCheckerBackendSettings(checker, auth); err != nil {
		t.Fatal(err)
	}
	delete(auth.CheckerBackendTokens, "external")
	if err := validateCheckerBackendSettings(checker, auth); err == nil {
		t.Fatal("missing external token accepted")
	}
	auth.CheckerBackendTokens["external"] = validExternalCheckerToken
	checker.Backends["external"] = ""
	if err := validateCheckerBackendSettings(checker, auth); err == nil {
		t.Fatal("missing external origin accepted")
	}
}

func TestWindowsConfigRequiresPostgresAndAbsolutePath(t *testing.T) {
	base := map[string]string{"PROVISIONER_CLUSTER_REGISTRY": "clusters.json", "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_WINDOWS_CONFIG": filepath.Join(t.TempDir(), "windows.json")}
	if _, err := loadConfig(environment(base)); err == nil {
		t.Fatal("enabled Windows accepted in memory mode")
	}
	base["PROVISIONER_STORE_MODE"] = "postgres"
	base["PROVISIONER_DATABASE_URL"] = "postgres://localhost/test"
	got, err := loadConfig(environment(base))
	if err != nil || got.WindowsConfigPath != base["PROVISIONER_WINDOWS_CONFIG"] {
		t.Fatal(got.WindowsConfigPath, err)
	}
	base["PROVISIONER_WINDOWS_CONFIG"] = "relative.json"
	if _, err := loadConfig(environment(base)); err == nil {
		t.Fatal("relative config accepted")
	}
}
func TestWindowsWorkerFailureCancelsOtherWorker(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	failure := errors.New("worker failure")
	base := func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return nil }
	windows := func(context.Context) error { <-started; return failure }
	if err := runCombinedWorkers(context.Background(), base, windows); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("other worker still active")
	}
}
