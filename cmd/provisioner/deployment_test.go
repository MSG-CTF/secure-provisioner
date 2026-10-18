package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeploymentModesRejectUnknownOrCombinedArguments(t *testing.T) {
	for _, args := range [][]string{{"--workers=false"}, {"--deployment-api-only", "--deployment-handoff-lock"}, {"--deployment-api-only=true"}} {
		if _, err := deploymentMode(args); err == nil {
			t.Fatalf("accepted unsupported startup arguments: %v", args)
		}
	}
	for _, option := range []string{"--deployment-api-only", "--deployment-handoff-lock", "--deployment-capabilities"} {
		if _, err := deploymentMode([]string{option}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeploymentAPIBridgeNeverStartsWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var called atomic.Bool
	app := &application{handler: http.NewServeMux(), runWorker: func(context.Context) error { called.Store(true); return nil }}
	err := runApplication(ctx, appConfig{APIOnly: true, Address: "127.0.0.1:0"}, app, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if called.Load() {
		t.Fatal("API-only bridge executed a worker")
	}
}

func TestDeploymentBridgeRejectsVolatileStoreBeforeInitialization(t *testing.T) {
	if _, err := newApplication(appConfig{APIOnly: true, RuntimeStore: runtimeStoreConfig{Mode: "memory"}}, nil); err == nil {
		t.Fatal("API bridge accepted a private volatile operation queue")
	}
}
