package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/dashboard"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

const defaultAddress = "127.0.0.1:18081"

func main() {
	handler, service, err := newDemoHandler()
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("RUNTIME_DASHBOARD_ADDR")
	if address == "" {
		address = defaultAddress
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	workerErrors := make(chan error, 1)
	serverErrors := make(chan error, 1)
	go func() { workerErrors <- service.Run(ctx) }()
	go func() { serverErrors <- server.ListenAndServe() }()

	log.Printf("runtime dashboard: http://%s (demo instance: %s)", address, runtimeops.DemoInstanceID)
	select {
	case <-ctx.Done():
	case err := <-workerErrors:
		if err != nil {
			log.Printf("runtime worker stopped: %v", err)
		}
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("runtime dashboard stopped: %v", err)
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("runtime dashboard shutdown: %v", err)
	}
}

func newDemoHandler() (http.Handler, *runtimeops.Service, error) {
	service, err := runtimeops.NewDemoService()
	if err != nil {
		return nil, nil, err
	}
	api := httpapi.NewHandlerWithRuntime(service, service)
	return dashboard.Handler(api), service, nil
}
