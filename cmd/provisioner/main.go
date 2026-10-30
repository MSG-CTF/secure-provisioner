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

	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
	"github.com/MSG-CTF/secure-provisioner/internal/vm"
	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type appConfig struct {
	ImagePreparation      imagePreparationConfig
	APIOnly               bool
	Address               string
	RegistryPath          string
	Broker                k3s.BrokerSyncConfig
	VMTargetsPath         string
	WindowsConfigPath     string
	ImagePoliciesPath     string
	BackendSecretURL      string
	BackendSecretToken    string
	ServiceAuth           httpapi.ServiceAuthConfig
	RuntimeStore          runtimeStoreConfig
	WorkerConcurrency     int
	MaxAttempts           int
	ReadyTimeout          time.Duration
	PollInterval          time.Duration
	RollbackTimeout       time.Duration
	DeleteTimeout         time.Duration
	WorkerShutdownTimeout time.Duration
	GatewayBaseURL        string
	GatewayTokenFile      string
	GatewayTimeout        time.Duration
	GatewayMaxInflight    int
	GatewayTCPTransport   gateway.PublicTransport
}

type application struct {
	handler     http.Handler
	runWorker   func(context.Context) error
	syncTargets func(context.Context)
	close       func() error
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if len(os.Args) > 1 && os.Args[1] == "--validate-registry" {
		if err := validateRegistryCommand(os.Args[2:], os.Stdout); err != nil {
			logger.Error("registry validation failed")
			os.Exit(1)
		}
		return
	}
	mode, err := deploymentMode(os.Args[1:])
	if err != nil {
		logger.Error("invalid startup mode")
		os.Exit(2)
	}
	if mode == "capabilities" {
		fmt.Println(`{"protocol":1,"api_only":true,"handoff_lock":true}`)
		return
	}
	if mode == "handoff" {
		if err := runHandoff(os.Getenv, os.Stdin, os.Stdout); err != nil {
			logger.Error("deployment handoff was not completed")
			os.Exit(1)
		}
		return
	}
	config, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid secure provisioner configuration", "error", err)
		os.Exit(1)
	}
	if mode == "api-only" {
		config.APIOnly = true
		config.Address = "127.0.0.1:18080"
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
		VMTargetsPath:      strings.TrimSpace(getenv("PROVISIONER_VM_TARGETS")),
		WindowsConfigPath:  strings.TrimSpace(getenv("PROVISIONER_WINDOWS_CONFIG")),
		Address:            valueOrDefault(getenv("PROVISIONER_ADDR"), "127.0.0.1:8080"),
		RegistryPath:       strings.TrimSpace(getenv("PROVISIONER_CLUSTER_REGISTRY")),
		ImagePoliciesPath:  strings.TrimSpace(getenv("PROVISIONER_IMAGE_POLICIES")),
		BackendSecretURL:   strings.TrimSpace(getenv("PROVISIONER_BACKEND_SECRET_URL")),
		BackendSecretToken: strings.TrimSpace(getenv("PROVISIONER_BACKEND_SECRET_TOKEN")),
		WorkerConcurrency:  10,
		MaxAttempts:        4,
		ReadyTimeout:       2 * time.Minute,
		PollInterval:       time.Second,
		RollbackTimeout:    30 * time.Second,
		DeleteTimeout:      time.Minute,
		GatewayBaseURL:     valueOrDefault(getenv("PROVISIONER_GATEWAY_BASE_URL"), "https://gate.msgctf.kr"),
		GatewayTokenFile:   strings.TrimSpace(getenv("PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE")),
		GatewayTimeout:     90 * time.Second, GatewayMaxInflight: 1,
	}
	if config.RegistryPath == "" {
		return appConfig{}, errors.New("PROVISIONER_CLUSTER_REGISTRY is required")
	}
	if strings.TrimSpace(getenv("PROVISIONER_FLAG_FILE")) != "" {
		return appConfig{}, errors.New("PROVISIONER_FLAG_FILE has been replaced by Backend secret references")
	}
	if config.BackendSecretURL != "" || config.BackendSecretToken != "" {
		if _, err := k3s.NewBackendSecretResolver(config.BackendSecretURL, config.BackendSecretToken); err != nil {
			return appConfig{}, err
		}
	}

	var err error
	if config.Broker, err = loadBrokerConfig(getenv); err != nil {
		return appConfig{}, err
	}
	if config.ServiceAuth, err = loadServiceAuthConfig(getenv); err != nil {
		return appConfig{}, err
	}
	if config.ImagePreparation, err = loadImagePreparationConfig(getenv, config.ServiceAuth); err != nil {
		return appConfig{}, err
	}
	if config.RuntimeStore, err = loadRuntimeStoreConfig(getenv); err != nil {
		return appConfig{}, err
	}
	if err = validateWindowsSettings(config.WindowsConfigPath, config.RuntimeStore.Mode); err != nil {
		return appConfig{}, err
	}
	config.WorkerConcurrency = config.RuntimeStore.Workers
	if config.GatewayTimeout, err = positiveDurationSetting(getenv, "PROVISIONER_GATEWAY_REQUEST_TIMEOUT", config.GatewayTimeout); err != nil || config.GatewayTimeout < 75*time.Second {
		return appConfig{}, errors.New("PROVISIONER_GATEWAY_REQUEST_TIMEOUT must be at least 75s")
	}
	if config.GatewayMaxInflight, err = positiveIntSetting(getenv, "PROVISIONER_GATEWAY_MAX_INFLIGHT", config.GatewayMaxInflight); err != nil {
		return appConfig{}, err
	}
	if config.GatewayTCPTransport, err = gateway.ParseTCPTransport(getenv("PROVISIONER_GATEWAY_TCP_TRANSPORT")); err != nil {
		return appConfig{}, fmt.Errorf("PROVISIONER_GATEWAY_TCP_TRANSPORT: %w", err)
	}
	if config.GatewayTCPTransport != gateway.TransportLegacy && config.GatewayTokenFile == "" {
		return appConfig{}, errors.New("Gateway TCP contract draft requires PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE")
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
	cleanupBudget := config.RollbackTimeout
	if config.GatewayTokenFile != "" {
		cleanupBudget = max(cleanupBudget, config.GatewayTimeout+config.DeleteTimeout+10*time.Second)
	}
	config.WorkerShutdownTimeout = cleanupBudget + 10*time.Second
	if config.WorkerShutdownTimeout, err = positiveDurationSetting(
		getenv,
		"PROVISIONER_WORKER_SHUTDOWN_TIMEOUT",
		config.WorkerShutdownTimeout,
	); err != nil {
		return appConfig{}, err
	}
	if config.WorkerShutdownTimeout < cleanupBudget {
		return appConfig{}, errors.New("PROVISIONER_WORKER_SHUTDOWN_TIMEOUT must cover rollback and Gateway cleanup budget")
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
	if config.APIOnly && config.RuntimeStore.Mode != "postgres" {
		return nil, errors.New("deployment API bridge requires the PostgreSQL store")
	}
	registry, err := k3s.LoadRegistry(config.RegistryPath, factory)
	if err != nil {
		return nil, err
	}
	var broker *k3s.BrokerSync
	if config.Broker.BaseURL != "" {
		config.Broker.ReadOnly = config.APIOnly
		broker, err = k3s.NewBrokerSync(registry, config.Broker)
		if err != nil {
			return nil, err
		}
		if broker.RequiresGateway() && config.GatewayTokenFile == "" {
			return nil, errors.New("Broker Gateway targets require PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE")
		}
		if !config.APIOnly {
			result, syncErr := broker.Sync(context.Background())
			reportBrokerSync(result, syncErr)
		}
	}
	var imagePolicies *httpapi.ImagePolicyCatalog
	if config.ImagePoliciesPath != "" {
		imagePolicies, err = httpapi.LoadImagePolicies(config.ImagePoliciesPath)
		if err != nil {
			return nil, fmt.Errorf("load image policies: %w", err)
		}
	}
	var secretResolver k3s.SecretResolver
	if config.BackendSecretURL != "" {
		secretResolver, err = k3s.NewBackendSecretResolver(config.BackendSecretURL, config.BackendSecretToken)
		if err != nil {
			return nil, err
		}
	}
	if len(imagePolicies.RequiredFlagImages()) > 0 && secretResolver == nil {
		return nil, errors.New("enabled FLAG images require a Backend secret resolver")
	}
	// Assigned once below, before workers or HTTP handlers can run. The closure
	// also protects queued K3s commands when the local catalog predates VM scopes.
	var vmRoute *vm.Router
	var preparation *imageprep.Service
	createAdapter, err := k3s.NewAdapter(registry, k3s.AdapterConfig{
		ReadyImageNodes: func(ctx context.Context, target, arch string, images []string) []string {
			return preparation.ReadyNodes(ctx, target, arch, images)
		},
		ReadyTimeout:       config.ReadyTimeout,
		PollInterval:       config.PollInterval,
		RollbackTimeout:    config.RollbackTimeout,
		Secrets:            secretResolver,
		RequiredFlagImages: imagePolicies.RequiredFlagImages(),
		RequiredFlagFiles:  imagePolicies.RequiredFlagFiles(),
		StartupCPUProfiles: imagePolicies.StartupCPUProfiles(),
		RequiresVMImage: func(image string) bool {
			return imagePolicies.RequiresVMImage(image) || vmRoute.RequiresVMImage(image)
		},
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
	var bindingStore runtimebinding.Store = runtimebinding.NewMemoryStore()
	var operationStore operations.Store = operations.NewMemoryStore(nil)
	var deleteCoordinator runtimeops.DeleteCoordinator
	var closeStore func() error
	var preparationStore imageprep.Store
	var gatewayJournal gateway.Journal
	liveGatewayRoutes := false
	var windowsStore *windowsruntime.PostgresStore
	readiness := httpapi.ReadinessConfig{StoreMode: config.RuntimeStore.Mode, APIOnly: config.APIOnly}
	if config.RuntimeStore.Mode == "postgres" {
		openStore := runtimepg.Open
		if config.APIOnly {
			openStore = runtimepg.OpenExisting
		}
		database, openErr := openStore(context.Background(), config.RuntimeStore.DatabaseURL)
		if openErr != nil {
			return nil, openErr
		}
		bindingStore = database.Bindings()
		operationStore = database.Operations()
		deleteCoordinator = database.DeleteCoordinator()
		closeStore = database.Close
		readiness.CheckDatabase = database.CheckReadiness
		preparationStore = database.ImagePreparations()
		gatewayJournal = database.GatewayJournal()
		liveGatewayRoutes, err = database.GatewayJournal().HasLiveRoutes(context.Background())
		if err != nil {
			_ = database.Close()
			return nil, err
		}
		if config.WindowsConfigPath != "" {
			windowsStore = database.WindowsExecutions()
			checkWindowsSchema := windowsStore.Check
			if config.APIOnly {
				checkWindowsSchema = windowsStore.CheckBridge
			}
			readiness.CheckDatabase = func(ctx context.Context) error {
				if err := database.CheckReadiness(ctx); err != nil {
					return err
				}
				return checkWindowsSchema(ctx)
			}
		}
	}
	var create runtimeops.CreateAdapter = createAdapter
	var status runtimeops.StatusSource = statusReader
	var deleteWorkload runtimeops.DeleteAdapter = deleteAdapter
	var resolver isolation.Resolver = isolation.NewStaticResolver()
	var vmPolicy func(*httpapi.CreateWorkloadRequest) error
	if config.VMTargetsPath != "" {
		route, routeErr := vm.Load(config.VMTargetsPath, secretResolver, createAdapter, statusReader, deleteAdapter)
		if routeErr != nil {
			if closeStore != nil {
				_ = closeStore()
			}
			return nil, routeErr
		}
		create, status, deleteWorkload, resolver, vmPolicy = route, route, route, route, route.Apply
		vmRoute = route
	}
	if len(registry.GatewayTargets()) > 0 || config.GatewayTokenFile != "" || liveGatewayRoutes {
		if gatewayJournal == nil {
			if closeStore != nil {
				_ = closeStore()
			}
			return nil, errors.New("Gateway requires PostgreSQL durable store")
		}
		for _, ip := range registry.GatewayTargets() {
			if _, err := gateway.PublicIP(ip); err != nil {
				_ = closeStore()
				return nil, errors.New("Gateway target requires a public upstream IP")
			}
		}
		client, clientErr := gateway.NewClient(config.GatewayBaseURL, config.GatewayTokenFile, config.GatewayTimeout, nil, config.GatewayMaxInflight)
		if clientErr != nil {
			_ = closeStore()
			return nil, clientErr
		}
		adapter := gateway.NewAdapter(&gateway.KubernetesBackend{Registry: registry, Create: create, Delete: deleteWorkload, TCPTransport: config.GatewayTCPTransport}, client, gatewayJournal)
		create, deleteWorkload = adapter, adapter
		config.RollbackTimeout = max(config.RollbackTimeout, config.GatewayTimeout+config.DeleteTimeout+10*time.Second)
	}
	service, err := runtimeops.NewService(
		create,
		status,
		deleteWorkload,
		bindingStore,
		operationStore,
		resolver,
		runtimeops.Config{
			MaxAttempts:       config.MaxAttempts,
			CleanupTimeout:    config.RollbackTimeout,
			DeleteCoordinator: deleteCoordinator,
			Worker: operations.WorkerConfig{
				Concurrency: config.WorkerConcurrency,
				Backoff: func(attempt int) time.Duration {
					return config.RuntimeStore.RetryBaseDelay * time.Duration(1<<min(max(attempt-1, 0), 5))
				},
				WorkerID:      "provisioner",
				PollInterval:  config.RuntimeStore.PollInterval,
				LeaseDuration: config.RuntimeStore.LeaseDuration,
				RenewInterval: config.RuntimeStore.RenewInterval,
			},
		},
	)
	if err != nil {
		if closeStore != nil {
			_ = closeStore()
		}
		return nil, err
	}
	windows, checker, windowsErr := initializeWindows(config, windowsStore)
	if windowsErr != nil {
		if closeStore != nil {
			_ = closeStore()
		}
		return nil, windowsErr
	}
	runWorkers := service.Run
	if config.ImagePreparation.Auth.Enabled {
		if preparationStore == nil || imagePolicies == nil {
			if closeStore != nil {
				_ = closeStore()
			}
			return nil, errors.New("image preparation requires PostgreSQL and an approved image policy catalog")
		}
		transport, parseErr := imageprep.NewFileTransport(config.ImagePreparation.NodesPath, k3s.KubernetesImageRunner(registry))
		if parseErr != nil {
			_ = closeStore()
			return nil, parseErr
		}
		preparation = imageprep.NewService(preparationStore, k3s.ImageInventory{Registry: registry}, imagePolicies, transport, config.ImagePreparation.Worker)
		runWorkers = func(ctx context.Context) error {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 2)
			go func() { done <- service.Run(ctx) }()
			go func() { done <- preparation.Run(ctx) }()
			first := <-done
			cancel()
			return errors.Join(first, <-done)
		}
	}
	if windows != nil {
		priorRun := runWorkers
		runWorkers = func(ctx context.Context) error { return runCombinedWorkers(ctx, priorRun, windows.Run) }
	}
	handler := httpapi.NewHandlerWithWindows(service, service, config.ServiceAuth, imagePolicies, readiness, vmPolicy, windowsUseCase(windows), checkerUseCase(checker))
	handler = httpapi.WithImagePreparations(handler, preparation, config.ImagePreparation.Auth)
	app := &application{
		handler:   handler,
		runWorker: runWorkers,
		close:     closeStore,
	}
	if broker != nil {
		app.syncTargets = func(ctx context.Context) { broker.Run(ctx, reportBrokerSync) }
	}
	return app, nil
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
	// HTTP requests must finish before cancellation reaches the worker and store.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
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
	if config.APIOnly {
		logger.Info("deployment API bridge: workers disabled; schema migrations disabled")
	} else {
		go func() { workerErrors <- runWorkers(runCtx, app) }()
	}
	logger.Info("starting secure provisioner", "address", config.Address)

	var runErr error
	workerStopped := config.APIOnly
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

	httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer httpShutdownCancel()
	shutdownErr := shutdownInOrder(
		func() error {
			if err := server.Shutdown(httpShutdownCtx); err != nil {
				return fmt.Errorf("graceful shutdown: %w", err)
			}
			return nil
		},
		cancel,
		func() error {
			if workerStopped {
				return nil
			}
			workerShutdownCtx, workerShutdownCancel := context.WithTimeout(context.Background(), config.WorkerShutdownTimeout)
			defer workerShutdownCancel()
			select {
			case err := <-workerErrors:
				if err != nil {
					return fmt.Errorf("runtime worker shutdown: %w", err)
				}
				return nil
			case <-workerShutdownCtx.Done():
				return errors.New("runtime worker shutdown timed out")
			}
		},
		app.close,
	)
	runErr = errors.Join(runErr, shutdownErr)
	return runErr
}

func shutdownInOrder(stopHTTP func() error, cancelWorker func(), waitWorker func() error, closeStore func() error) error {
	var result error
	if stopHTTP != nil {
		result = errors.Join(result, stopHTTP())
	}
	if cancelWorker != nil {
		cancelWorker()
	}
	if waitWorker != nil {
		result = errors.Join(result, waitWorker())
	}
	if closeStore != nil {
		if err := closeStore(); err != nil {
			result = errors.Join(result, fmt.Errorf("close runtime store: %w", err))
		}
	}
	return result
}
