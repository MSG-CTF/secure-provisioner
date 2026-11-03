package main

import (
	"errors"
	"io"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
)

// Construct clients using the same strict registry parser as service startup.
// This does not contact Kubernetes, open a database, listen or start workers.
func validateRegistryCommand(args []string, output io.Writer) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("one registry path is required")
	}
	if _, err := k3s.LoadRegistry(args[0], k3s.KubeconfigClientFactory{}); err != nil {
		return errors.New("registry validation failed")
	}
	_, err := io.WriteString(output, "{\"registry_valid\":true}\n")
	return err
}
