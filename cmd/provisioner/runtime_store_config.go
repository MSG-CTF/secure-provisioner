package main

import (
	"errors"
	"strings"
	"time"
)

type runtimeStoreConfig struct {
	Mode           string
	DatabaseURL    string
	Workers        int
	PollInterval   time.Duration
	LeaseDuration  time.Duration
	RenewInterval  time.Duration
	RetryBaseDelay time.Duration
}

func loadRuntimeStoreConfig(getenv func(string) string) (runtimeStoreConfig, error) {
	if getenv == nil {
		return runtimeStoreConfig{}, errors.New("environment reader is required")
	}
	config := runtimeStoreConfig{
		Mode:        strings.ToLower(valueOrDefault(getenv("PROVISIONER_STORE_MODE"), "memory")),
		DatabaseURL: strings.TrimSpace(getenv("PROVISIONER_DATABASE_URL")),
		Workers:     10, PollInterval: 200 * time.Millisecond, LeaseDuration: 3 * time.Minute,
		RenewInterval: time.Minute, RetryBaseDelay: time.Second,
	}
	if config.Mode != "memory" && config.Mode != "postgres" {
		return runtimeStoreConfig{}, errors.New("PROVISIONER_STORE_MODE must be memory or postgres")
	}
	if config.Mode == "postgres" && config.DatabaseURL == "" {
		return runtimeStoreConfig{}, errors.New("PROVISIONER_DATABASE_URL is required for postgres mode")
	}
	var err error
	if config.Workers, err = positiveIntSetting(getenv, "PROVISIONER_WORKERS", config.Workers); err != nil {
		return runtimeStoreConfig{}, err
	}
	if config.PollInterval, err = positiveDurationSetting(getenv, "PROVISIONER_POLL_INTERVAL", config.PollInterval); err != nil {
		return runtimeStoreConfig{}, err
	}
	if config.LeaseDuration, err = positiveDurationSetting(getenv, "PROVISIONER_LEASE_DURATION", config.LeaseDuration); err != nil {
		return runtimeStoreConfig{}, err
	}
	if config.RenewInterval, err = positiveDurationSetting(getenv, "PROVISIONER_LEASE_RENEW_INTERVAL", config.RenewInterval); err != nil {
		return runtimeStoreConfig{}, err
	}
	if config.RetryBaseDelay, err = positiveDurationSetting(getenv, "PROVISIONER_RETRY_BASE_DELAY", config.RetryBaseDelay); err != nil {
		return runtimeStoreConfig{}, err
	}
	if config.RenewInterval >= config.LeaseDuration {
		return runtimeStoreConfig{}, errors.New("PROVISIONER_LEASE_RENEW_INTERVAL must be shorter than PROVISIONER_LEASE_DURATION")
	}
	return config, nil
}
