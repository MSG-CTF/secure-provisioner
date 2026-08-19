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
	"strings"
	"syscall"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

type appConfig struct {
	Address               string
	RegistryPath          string
	ServiceAuth           httpapi.ServiceAuthConfig
	WorkerConcurrency     int
	MaxAttempts           int
	ReadyTimeout          time.Duration
	PollInterval          time.Duration
	RollbackTimeout       time.Duration
	DeleteTimeout         time.Duration
	WorkerShutdownTimeout time.Duration
}

type application struct {
	handler   http.Handler
	runWorker func(context.Context) error
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid secure provisioner configuration", "error", err)
		os.Exit(1)
	}
	app, err := newApplication(config, k3s.KubeconfigClientFactory{})
	if err != nil {
		logger.Error("secure provisioner initialization failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runApplication(ctx, config, app, logger); err != nil {
		logger.Error("secure provisioner stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig(getenv func(string) string) (appConfig, error) {
	if getenv == nil {
		return appConfig{}, errors.New("environment reader is required")
	}
	config := appConfig{
		Address:           valueOrDefault(getenv("PROVISIONER_ADDR"), "127.0.0.1:8080"),
		RegistryPath:      strings.TrimSpace(getenv("PROVISIONER_CLUSTER_REGISTRY")),
		WorkerConcurrency: 4,
		MaxAttempts:       3,
		ReadyTimeout:      2 * time.Minute,
		PollInterval:      time.Second,
		RollbackTimeout:   30 * time.Second,
		DeleteTimeout:     time.Minute,
	}
	if config.RegistryPath == "" {
		return appConfig{}, errors.New("PROVISIONER_CLUSTER_REGISTRY is required")
	}

	var err error
	if config.ServiceAuth, err = loadServiceAuthConfig(getenv); err != nil {
		return appConfig{}, err
	}
	if config.WorkerConcurrency, err = positiveIntSetting(getenv, "PROVISIONER_WORKER_CONCURRENCY", config.WorkerConcurrency); err != nil {
		return appConfig{}, err
	}
	if config.MaxAttempts, err = positiveIntSetting(getenv, "PROVISIONER_MAX_ATTEMPTS", config.MaxAttempts); err != nil {
		return appConfig{}, err
	}
	if config.ReadyTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_READY_TIMEOUT", config.ReadyTimeout); err != nil {
		return appConfig{}, err
	}
	if config.PollInterval, err = positiveDurationSetting(getenv, "PROVISIONER_POLL_INTERVAL", config.PollInterval); err != nil {
		return appConfig{}, err
	}
	if config.RollbackTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_ROLLBACK_TIMEOUT", config.RollbackTimeout); err != nil {
		return appConfig{}, err
	}
	if config.DeleteTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_DELETE_TIMEOUT", config.DeleteTimeout); err != nil {
		return appConfig{}, err
	}
	config.WorkerShutdownTimeout = config.RollbackTimeout + 10*time.Second
	if config.WorkerShutdownTimeout, err = positiveDurationSetting(
		getenv,
		"PROVISIONER_WORKER_SHUTDOWN_TIMEOUT",
		config.WorkerShutdownTimeout,
	); err != nil {
		return appConfig{}, err
	}
	if config.WorkerShutdownTimeout < config.RollbackTimeout {
		return appConfig{}, errors.New("PROVISIONER_WORKER_SHUTDOWN_TIMEOUT must be at least PROVISIONER_ROLLBACK_TIMEOUT")
	}
	return config, nil
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func positiveIntSetting(getenv func(string) string, key string, fallback int) (int, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func positiveDurationSetting(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func newApplication(config appConfig, factory k3s.ClientFactory) (*application, error) {
	registry, err := k3s.LoadRegistry(config.RegistryPath, factory)
	if err != nil {
		return nil, err
	}
	createAdapter, err := k3s.NewAdapter(registry, k3s.AdapterConfig{
		ReadyTimeout:    config.ReadyTimeout,
		PollInterval:    config.PollInterval,
		RollbackTimeout: config.RollbackTimeout,
	})
	if err != nil {
		return nil, err
	}
	deleteAdapter, err := k3s.NewDeleteAdapterForCreateAdapter(createAdapter, k3s.DeleteAdapterConfig{
		DeleteTimeout: config.DeleteTimeout,
		PollInterval:  config.PollInterval,
	})
	if err != nil {
		return nil, err
	}
	statusReader, err := k3s.NewStatusReader(registry)
	if err != nil {
		return nil, err
	}
	service, err := runtimeops.NewService(
		createAdapter,
		statusReader,
		deleteAdapter,
		runtimebinding.NewMemoryStore(),
		operations.NewMemoryStore(nil),
		isolation.NewStaticResolver(),
		runtimeops.Config{
			MaxAttempts:    config.MaxAttempts,
			CleanupTimeout: config.RollbackTimeout,
			Worker: operations.WorkerConfig{
				Concurrency: config.WorkerConcurrency,
				Backoff:     operationBackoff,
			},
		},
	)
	if err != nil {
		return nil, err
	}
	return &application{
		handler:   httpapi.NewHandlerWithRuntime(service, service, config.ServiceAuth),
		runWorker: service.Run,
	}, nil
}

func operationBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	exponent := min(attempt-1, 5)
	return time.Second * time.Duration(1<<exponent)
}

func runApplication(ctx context.Context, config appConfig, app *application, logger *slog.Logger) error {
	if ctx == nil || app == nil || app.handler == nil || app.runWorker == nil || logger == nil {
		return errors.New("application dependencies are required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{
		Addr:              config.Address,
		Handler:           app.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErrors := make(chan error, 1)
	workerErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	go func() { workerErrors <- app.runWorker(runCtx) }()
	logger.Info("starting secure provisioner", "address", config.Address)

	var runErr error
	workerStopped := false
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("http server: %w", err)
		}
	case err := <-workerErrors:
		workerStopped = true
		if err != nil {
			runErr = fmt.Errorf("runtime worker: %w", err)
		} else if ctx.Err() == nil {
			runErr = errors.New("runtime worker stopped unexpectedly")
		}
	}

	cancel()
	httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer httpShutdownCancel()
	if err := server.Shutdown(httpShutdownCtx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("graceful shutdown: %w", err))
	}
	if !workerStopped {
		workerShutdownCtx, workerShutdownCancel := context.WithTimeout(context.Background(), config.WorkerShutdownTimeout)
		defer workerShutdownCancel()
		select {
		case err := <-workerErrors:
			if err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("runtime worker shutdown: %w", err))
			}
		case <-workerShutdownCtx.Done():
			runErr = errors.Join(runErr, errors.New("runtime worker shutdown timed out"))
		}
	}
	return runErr
}
