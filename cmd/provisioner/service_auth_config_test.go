package main

import (
	"os"
	"path/filepath"
	"testing"
)

const validCurrentServiceToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const validPreviousServiceToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func TestLoadServiceAuthConfigAcceptsCurrentAndPreviousTokens(t *testing.T) {
	config, err := loadServiceAuthConfig(environment(map[string]string{
		"PROVISIONER_SERVICE_TOKEN":          validCurrentServiceToken,
		"PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.CurrentToken != validCurrentServiceToken || config.PreviousToken != validPreviousServiceToken {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadServiceAuthConfigReadsOneTrailingLineEndingFromAbsoluteFiles(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		content  string
		values   map[string]string
		wantCurr string
		wantPrev string
	}{
		{
			name:    "current LF",
			key:     "PROVISIONER_SERVICE_TOKEN_FILE",
			content: validCurrentServiceToken + "\n",
			values: map[string]string{
				"PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken,
			},
			wantCurr: validCurrentServiceToken,
			wantPrev: validPreviousServiceToken,
		},
		{
			name:    "previous CRLF",
			key:     "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE",
			content: validPreviousServiceToken + "\r\n",
			values: map[string]string{
				"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken,
			},
			wantCurr: validCurrentServiceToken,
			wantPrev: validPreviousServiceToken,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "service-token")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			test.values[test.key] = path

			config, err := loadServiceAuthConfig(environment(test.values))
			if err != nil {
				t.Fatal(err)
			}
			if config.CurrentToken != test.wantCurr || config.PreviousToken != test.wantPrev {
				t.Fatalf("config = %#v", config)
			}
		})
	}
}

func TestLoadServiceAuthConfigRejectsInvalidSettings(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing-token")
	conflictingFile := filepath.Join(t.TempDir(), "conflicting-token")
	testCases := []struct {
		name   string
		values map[string]string
	}{
		{name: "missing current token", values: map[string]string{}},
		{name: "current direct and file", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN":      validCurrentServiceToken,
			"PROVISIONER_SERVICE_TOKEN_FILE": conflictingFile,
		}},
		{name: "previous direct and file", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN":               validCurrentServiceToken,
			"PROVISIONER_PREVIOUS_SERVICE_TOKEN":      validPreviousServiceToken,
			"PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE": conflictingFile,
		}},
		{name: "relative file path", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN_FILE": "service-token",
		}},
		{name: "file read failure", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN_FILE": missingFile,
		}},
		{name: "42 characters", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		}},
		{name: "129 characters", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		}},
		{name: "space", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
		}},
		{name: "plus", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
		}},
		{name: "slash", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
		}},
		{name: "equals", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		}},
		{name: "two newlines", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n",
		}},
		{name: "same current and previous token", values: map[string]string{
			"PROVISIONER_SERVICE_TOKEN":          validCurrentServiceToken,
			"PROVISIONER_PREVIOUS_SERVICE_TOKEN": validCurrentServiceToken,
		}},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadServiceAuthConfig(environment(test.values))
			if err == nil {
				t.Fatalf("loadServiceAuthConfig() config = %#v, error = nil", config)
			}
			if config.CurrentToken != "" || config.PreviousToken != "" {
				t.Fatalf("loadServiceAuthConfig() returned token on error: %#v", config)
			}
		})
	}
}

func TestLoadServiceAuthConfigRejectsFileWithTwoTrailingLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-token")
	if err := os.WriteFile(path, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := loadServiceAuthConfig(environment(map[string]string{
		"PROVISIONER_SERVICE_TOKEN_FILE": path,
	}))
	if err == nil {
		t.Fatalf("loadServiceAuthConfig() config = %#v, error = nil", config)
	}
	if config.CurrentToken != "" || config.PreviousToken != "" {
		t.Fatalf("loadServiceAuthConfig() returned token on error: %#v", config)
	}
}
