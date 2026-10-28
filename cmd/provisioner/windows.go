package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

func validateWindowsSettings(path, storeMode string) error {
	if path == "" {
		return nil
	}
	if storeMode != "postgres" || !filepath.IsAbs(path) {
		return errors.New("Windows runtime requires postgres mode and an absolute PROVISIONER_WINDOWS_CONFIG path")
	}
	return nil
}

// Avoid converting a nil *Service to a non-nil interface: disabled installations
// must not register Windows submission routes.
func windowsUseCase(service *windowsruntime.Service) httpapi.WindowsUseCase {
	if service == nil {
		return nil
	}
	return service
}

func checkerUseCase(checker *windowsruntime.Checker) httpapi.CheckerUseCase {
	if checker == nil {
		return nil
	}
	return checker
}

func initializeWindows(config appConfig, store *windowsruntime.PostgresStore) (*windowsruntime.Service, *windowsruntime.Checker, error) {
	if config.WindowsConfigPath == "" {
		return nil, nil, nil
	}
	if err := validateWindowsSettings(config.WindowsConfigPath, config.RuntimeStore.Mode); err != nil {
		return nil, nil, err
	}
	cfg, err := windowsruntime.LoadConfig(config.WindowsConfigPath)
	if err != nil {
		return nil, nil, err
	}
	if store == nil {
		return nil, nil, errors.New("Windows durable store unavailable")
	}
	checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	checkSchema := store.Check
	if config.APIOnly {
		checkSchema = store.CheckBridge
	}
	if err = checkSchema(checkCtx); err != nil {
		return nil, nil, errors.New("Windows execution schema unavailable")
	}
	token, err := cfg.ReadBrokerToken()
	if err != nil {
		return nil, nil, err
	}
	broker, err := windowsruntime.NewBroker(cfg.BrokerURL, token, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	var transport windowsruntime.Transport = bridgeWindowsTransport{}
	if !config.APIOnly {
		if cfg.HTTPSExecutor != nil {
			transport, err = windowsruntime.NewHTTPSExecutorTransport(*cfg.HTTPSExecutor)
			if err != nil {
				return nil, nil, err
			}
			if transport.(*windowsruntime.HTTPSExecutorTransport).UsesToken(token) {
				return nil, nil, errors.New("Windows executor token must differ from Broker token")
			}
		} else {
			rdp, transportErr := windowsruntime.NewFreeRDPTransport(cfg.RDP)
			if transportErr != nil {
				return nil, nil, transportErr
			}
			if transportErr = rdp.Validate(checkCtx); transportErr != nil {
				return nil, nil, transportErr
			}
			transport = rdp
		}
	}
	serviceConfig, err := cfg.ServiceConfig()
	if err != nil {
		return nil, nil, err
	}
	service, err := windowsruntime.NewService(serviceConfig, store, broker, transport)
	if err != nil {
		return nil, nil, err
	}
	if cfg.HTTPSExecutor != nil {
		if cfg.HTTPSExecutor.UsesBrokerMTLS() {
			service.SetPoolAnyTargets()
		} else {
			service.SetPoolTargets(cfg.HTTPSExecutor.Targets)
		}
	}
	if cfg.Checker == nil {
		return service, nil, nil
	}
	if err := validateCheckerBackendSettings(*cfg.Checker, config.ServiceAuth); err != nil {
		return nil, nil, err
	}
	if cfg.Checker.BackendURL != "" {
		service.SetCheckerServiceTokens(map[string]string{"default": config.ServiceAuth.CheckerToken})
	} else {
		service.SetCheckerServiceTokens(config.ServiceAuth.CheckerBackendTokens)
	}
	targets := make(map[string]bool)
	if cfg.HTTPSExecutor != nil {
		for id := range cfg.HTTPSExecutor.Targets {
			targets[id] = true
		}
	} else {
		for id := range cfg.RDP.Credentials {
			targets[id] = true
		}
	}
	checker, err := windowsruntime.NewChecker(service, windowsruntime.CheckerConfig{BackendURL: cfg.Checker.BackendURL, Backends: cfg.Checker.Backends, Targets: targets, CheckerCommitSHA: cfg.Checker.CheckerCommitSHA, VMTemplateSHA256: cfg.Checker.VMTemplateSHA256, DriverSHA256: cfg.Checker.DriverSHA256, ConfigVersion: cfg.Checker.ConfigVersion}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	return service, checker, nil
}

func validateCheckerBackendSettings(checker windowsruntime.CheckerRuntimeConfig, auth httpapi.ServiceAuthConfig) error {
	if checker.BackendURL != "" {
		if len(checker.Backends) != 0 || auth.CheckerToken == "" || len(auth.CheckerBackendTokens) != 0 {
			return errors.New("legacy Windows checker origin requires only the legacy checker service token")
		}
		return nil
	}
	if auth.CheckerToken != "" || len(checker.Backends) != 2 || len(auth.CheckerBackendTokens) != 2 {
		return errors.New("Windows checker requires internal and external backend origins and service tokens")
	}
	for _, id := range []string{"internal", "external"} {
		if checker.Backends[id] == "" || auth.CheckerBackendTokens[id] == "" {
			return errors.New("Windows checker backend origin or service token missing")
		}
	}
	return nil
}

type bridgeWindowsTransport struct{}

func (bridgeWindowsTransport) Execute(context.Context, windowsruntime.Connection, windowsruntime.Job) windowsruntime.Outcome {
	return windowsruntime.Outcome{Result: "unreachable", ErrorCode: "API_BRIDGE_HAS_NO_WORKER"}
}

func runCombinedWorkers(ctx context.Context, first, second func(context.Context) error) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- first(child) }()
	go func() { done <- second(child) }()
	firstErr := <-done
	cancel()
	return errors.Join(firstErr, <-done)
}
