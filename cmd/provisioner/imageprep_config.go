package main

import (
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"strconv"
	"strings"
	"time"
)

type imagePreparationConfig struct {
	Auth      httpapi.PreparationAuth
	Worker    imageprep.Config
	NodesPath string
}

func loadImagePreparationConfig(getenv func(string) string, existing httpapi.ServiceAuthConfig) (imagePreparationConfig, error) {
	c := imagePreparationConfig{Auth: httpapi.PreparationAuth{Existing: existing}, Worker: imageprep.Config{TTL: time.Minute, ObserveInterval: 30 * time.Second, MaxAttempts: 3, Concurrency: 2}, NodesPath: strings.TrimSpace(getenv("PROVISIONER_IMAGE_PREFETCH_NODES"))}
	var err error
	if value := getenv("PROVISIONER_IMAGE_PREFETCH_ENABLED"); value != "" {
		c.Auth.Enabled, err = strconv.ParseBool(value)
		if err != nil {
			return c, errors.New("invalid image prefetch enabled setting")
		}
	}
	if c.Auth.ManagerToken, err = readServiceTokenSetting(getenv, "PROVISIONER_IMAGE_PREPARATION_TOKEN", "PROVISIONER_IMAGE_PREPARATION_TOKEN_FILE", c.Auth.Enabled); err != nil {
		return c, err
	}
	if c.Auth.ReadinessToken, err = readServiceTokenSetting(getenv, "PROVISIONER_IMAGE_READINESS_TOKEN", "PROVISIONER_IMAGE_READINESS_TOKEN_FILE", c.Auth.Enabled); err != nil {
		return c, err
	}
	if c.Auth.ManagerToken != "" && c.Auth.ManagerToken == c.Auth.ReadinessToken {
		return c, errors.New("preparation and readiness credentials must differ")
	}
	for _, token := range []string{c.Auth.ManagerToken, c.Auth.ReadinessToken} {
		if token != "" && (token == existing.CurrentToken || token == existing.PreviousToken || token == existing.CISmokeToken) {
			return c, errors.New("image credentials must differ from existing service credentials")
		}
	}
	if c.Worker.TTL, err = positiveDurationSetting(getenv, "PROVISIONER_IMAGE_PREFETCH_READINESS_TTL", c.Worker.TTL); err != nil {
		return c, err
	}
	if c.Worker.ObserveInterval, err = positiveDurationSetting(getenv, "PROVISIONER_IMAGE_PREFETCH_OBSERVE_INTERVAL", c.Worker.ObserveInterval); err != nil {
		return c, err
	}
	if c.Worker.MaxAttempts, err = positiveIntSetting(getenv, "PROVISIONER_IMAGE_PREFETCH_MAX_ATTEMPTS", c.Worker.MaxAttempts); err != nil {
		return c, err
	}
	if c.Worker.Concurrency, err = positiveIntSetting(getenv, "PROVISIONER_IMAGE_PREFETCH_WORKERS", c.Worker.Concurrency); err != nil {
		return c, err
	}
	if c.Worker.TTL <= c.Worker.ObserveInterval || c.Worker.TTL > 5*time.Minute || c.Worker.MaxAttempts > 10 || c.Worker.Concurrency > 16 {
		return c, errors.New("invalid image prefetch bounds (TTL > interval, TTL <= 5m, attempts <= 10, workers <= 16)")
	}
	if c.Auth.Enabled && c.NodesPath == "" {
		return c, errors.New("enabled image prefetch requires trusted node configuration")
	}
	return c, nil
}
