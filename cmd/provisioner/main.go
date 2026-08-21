package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func main() {
	runtimeConfig, err := loadRuntimeConfig()
	if err != nil {
		slog.Error("load runtime config", "error", err)
		os.Exit(1)
	}
	address := envOrDefault("PROVISIONER_ADDR", "127.0.0.1:8080")
	mockURL := envOrDefault("CTF_MOCK_URL", "http://127.0.0.1:18080")
	expirationInterval := durationEnvOrDefault("PROVISIONER_EXPIRATION_INTERVAL", 5*time.Second)
	logger := newLogger(envOrDefault("PROVISIONER_LOG_LEVEL", "info"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var service *provisioner.Service
	switch envOrDefault("PROVISIONER_CLUSTER_MODE", "fake") {
	case "fake":
		if runtimeConfig.StoreMode == "postgres" {
			service, err = provisioner.NewPostgresService(ctx, mockURL, logger, expirationInterval, runtimeConfig.DatabaseURL)
		} else {
			service = provisioner.NewService(mockURL, logger, expirationInterval)
		}
	case "k3s":
		kubernetesOptions := provisioner.KubernetesOptions{
			Kubeconfig:       envOrDefault("K3S_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml"),
			PublicHost:       os.Getenv("K3S_PUBLIC_HOST"),
			VerificationHost: envOrDefault("K3S_VERIFICATION_HOST", "127.0.0.1"),
		}
		if runtimeConfig.StoreMode == "postgres" {
			service, err = provisioner.NewPostgresKubernetesService(ctx, mockURL, logger, expirationInterval, kubernetesOptions, runtimeConfig.DatabaseURL)
		} else {
			service, err = provisioner.NewKubernetesService(mockURL, logger, expirationInterval, kubernetesOptions)
		}
		if err != nil {
			logger.Error("initialize K3s adapter", "error", err)
			os.Exit(1)
		}
	default:
		logger.Error("unsupported PROVISIONER_CLUSTER_MODE")
		os.Exit(1)
	}
	defer func() { _ = service.Close() }()
	service.StartWithOptions(ctx, runtimeConfig.WorkerOptions)

	server := &http.Server{
		Addr:              address,
		Handler:           provisioner.NewHandler(service),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("starting MVP provisioner", "address", address, "mockUrl", mockURL)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

type runtimeConfig struct {
	StoreMode     string
	DatabaseURL   string
	WorkerOptions provisioner.WorkerOptions
}

func loadRuntimeConfig() (runtimeConfig, error) {
	storeMode := envOrDefault("PROVISIONER_STORE_MODE", "memory")
	databaseURL := os.Getenv("PROVISIONER_DATABASE_URL")
	if storeMode != "memory" && storeMode != "postgres" {
		return runtimeConfig{}, fmt.Errorf("unsupported PROVISIONER_STORE_MODE %q", storeMode)
	}
	if storeMode == "postgres" && databaseURL == "" {
		return runtimeConfig{}, errors.New("PROVISIONER_DATABASE_URL is required for postgres store")
	}
	return runtimeConfig{
		StoreMode:   storeMode,
		DatabaseURL: databaseURL,
		WorkerOptions: provisioner.WorkerOptions{
			Concurrency:    intEnvOrDefault("PROVISIONER_WORKERS", 10),
			PollInterval:   durationEnvOrDefault("PROVISIONER_POLL_INTERVAL", 200*time.Millisecond),
			LeaseDuration:  durationEnvOrDefault("PROVISIONER_LEASE_DURATION", 3*time.Minute),
			MaximumRetries: intEnvOrDefault("PROVISIONER_MAX_RETRIES", 3),
			RetryBaseDelay: durationEnvOrDefault("PROVISIONER_RETRY_BASE_DELAY", time.Second),
		},
	}, nil
}

func envOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func intEnvOrDefault(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func durationEnvOrDefault(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func newLogger(level string) *slog.Logger {
	logLevel := slog.LevelInfo
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
}
