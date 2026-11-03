package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryValidationUsesRuntimeRulesWithoutServiceEnvironment(t *testing.T) {
	directory := t.TempDir()
	kubeconfig := filepath.Join(directory, "kubeconfig.json")
	config := `{"apiVersion":"v1","kind":"Config","current-context":"default","clusters":[{"name":"default","cluster":{"server":"https://127.0.0.1:6443"}}],"users":[{"name":"default","user":{"token":"test-only"}}],"contexts":[{"name":"default","context":{"cluster":"default","user":"default"}}]}`
	if err := os.WriteFile(kubeconfig, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(directory, "registry.json")
	for _, test := range []struct {
		name, fields string
		valid        bool
	}{
		{"valid disabled target", `"provider":"GCP","exposure_mode":"NODE_PORT","enabled":false`, true},
		{"enabled without isolation policy", `"provider":"GCP","enabled":true`, false},
		{"unknown provider", `"provider":"UNKNOWN","enabled":false`, false},
		{"unknown field", `"provider":"GCP","enabled":false,"typo":true`, false},
		{"invalid exposure", `"provider":"GCP","enabled":false,"exposure_mode":"UNKNOWN"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"clusters":[{"target_id":"node-uid","region":"test","architecture":"amd64","public_gateway":"http://127.0.0.1","kubeconfig_path":"` + filepath.ToSlash(kubeconfig) + `",` + test.fields + `}]}`
			if err := os.WriteFile(registry, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := validateRegistryCommand([]string{registry}, &output)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
			if test.valid && strings.TrimSpace(output.String()) != `{"registry_valid":true}` {
				t.Fatal(output.String())
			}
			if !test.valid && output.Len() != 0 {
				t.Fatal("invalid registry produced a success receipt")
			}
		})
	}
	for _, args := range [][]string{nil, {""}, {registry, "unexpected"}} {
		if err := validateRegistryCommand(args, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid validation arguments accepted")
		}
	}
}
