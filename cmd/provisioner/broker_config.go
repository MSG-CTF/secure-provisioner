package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
)

func loadBrokerConfig(getenv func(string) string) (k3s.BrokerSyncConfig, error) {
	config := k3s.BrokerSyncConfig{
		BaseURL:        strings.TrimSpace(getenv("PROVISIONER_BROKER_BASE_URL")),
		TokenFile:      strings.TrimSpace(getenv("PROVISIONER_BROKER_TOKEN_FILE")),
		PolicyPath:     strings.TrimSpace(getenv("PROVISIONER_BROKER_TARGET_POLICY")),
		StateDirectory: strings.TrimSpace(getenv("PROVISIONER_BROKER_STATE_DIRECTORY")),
		Interval:       time.Minute, RequestTimeout: 10 * time.Second, SyncTimeout: 2 * time.Minute,
	}
	if config.BaseURL == "" && config.TokenFile == "" && config.PolicyPath == "" && config.StateDirectory == "" {
		return k3s.BrokerSyncConfig{}, nil
	}
	if !filepath.IsAbs(config.TokenFile) || !filepath.IsAbs(config.PolicyPath) || !filepath.IsAbs(config.StateDirectory) {
		return k3s.BrokerSyncConfig{}, errors.New("Broker discovery requires absolute token, fleet policy and private state paths")
	}
	config.BaseURL = valueOrDefault(config.BaseURL, "https://broker.mjsec.kr/api")
	var err error
	if config.Interval, err = positiveDurationSetting(getenv, "PROVISIONER_BROKER_SYNC_INTERVAL", config.Interval); err != nil {
		return k3s.BrokerSyncConfig{}, err
	}
	if config.RequestTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_BROKER_REQUEST_TIMEOUT", config.RequestTimeout); err != nil {
		return k3s.BrokerSyncConfig{}, err
	}
	if config.SyncTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_BROKER_SYNC_TIMEOUT", config.SyncTimeout); err != nil {
		return k3s.BrokerSyncConfig{}, err
	}
	return config, nil
}

func reportBrokerSync(result k3s.BrokerSyncResult, err error) {
	if err != nil {
		slog.Warn("Broker target refresh failed; previous snapshot preserved", "code", err.Error())
		return
	}
	slog.Info("Broker targets refreshed", "ready", result.Ready, "retired", result.Retired, "rejected", result.Rejected)
}

// One cancellation boundary covers workers and discovery. Discovery finishes
// before the caller closes durable stores during a release handoff.
func runWorkers(ctx context.Context, app *application) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	if app.syncTargets != nil {
		go func() { defer close(done); app.syncTargets(runCtx) }()
	} else {
		close(done)
	}
	err := app.runWorker(runCtx)
	cancel()
	<-done
	return err
}
