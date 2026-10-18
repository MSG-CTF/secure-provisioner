package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
)

// Modes are deliberately fixed: deployment callers cannot choose a listener,
// database query, or executable. Capabilities need no environment or credentials.
func deploymentMode(args []string) (string, error) {
	if len(args) == 0 {
		return "normal", nil
	}
	if len(args) == 1 {
		switch args[0] {
		case "--deployment-capabilities":
			return "capabilities", nil
		case "--deployment-api-only":
			return "api-only", nil
		case "--deployment-handoff-lock":
			return "handoff", nil
		}
	}
	return "", errors.New("unsupported deployment mode")
}

func runHandoff(getenv func(string) string, input io.Reader, output io.Writer) error {
	config, err := loadRuntimeStoreConfig(getenv)
	if err != nil || config.Mode != "postgres" {
		return errors.New("deployment handoff requires PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	database, err := runtimepg.OpenExisting(ctx, config.DatabaseURL)
	if err != nil {
		return errors.New("deployment handoff database is unavailable")
	}
	defer database.Close()
	release, err := database.AcquireDeploymentHandoff(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := io.WriteString(output, "HANDOFF_READY\n"); err != nil {
		return err
	}
	done := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 32)).ReadString('\n')
		done <- err == nil && line == "release\n"
	}()
	select {
	case valid := <-done:
		if !valid {
			return errors.New("deployment handoff pipe closed")
		}
		return release()
	case <-time.After(2500 * time.Millisecond):
		return errors.New("deployment handoff stop deadline exceeded")
	}
}
