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
		"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.CurrentToken != validCurrentServiceToken || config.PreviousToken != validPreviousServiceToken {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadServiceAuthConfigReadsOneTrailingLineEndingFromAbsoluteFiles(t *testing.T) {
	for _, tc := range []struct {
		name, key, content string
		values             map[string]string
		wantCurr, wantPrev string
	}{
		{"current LF", "PROVISIONER_SERVICE_TOKEN_FILE", validCurrentServiceToken + "\n", map[string]string{"PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken}, validCurrentServiceToken, validPreviousServiceToken},
		{"previous CRLF", "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE", validPreviousServiceToken + "\r\n", map[string]string{"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken}, validCurrentServiceToken, validPreviousServiceToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "service-token")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.values[tc.key] = path
			config, err := loadServiceAuthConfig(environment(tc.values))
			if err != nil {
				t.Fatal(err)
			}
			if config.CurrentToken != tc.wantCurr || config.PreviousToken != tc.wantPrev {
				t.Fatalf("config = %#v", config)
			}
		})
	}
}

func TestLoadServiceAuthConfigRejectsInvalidSettings(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing-token")
	conflictingFile := filepath.Join(t.TempDir(), "conflicting-token")
	for _, tc := range []struct {
		name   string
		values map[string]string
	}{
		{"missing current token", map[string]string{}},
		{"current direct and file", map[string]string{"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_SERVICE_TOKEN_FILE": conflictingFile}},
		{"previous direct and file", map[string]string{"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken, "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE": conflictingFile}},
		{"relative file path", map[string]string{"PROVISIONER_SERVICE_TOKEN_FILE": "service-token"}},
		{"file read failure", map[string]string{"PROVISIONER_SERVICE_TOKEN_FILE": missingFile}},
		{"42 characters", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"129 characters", map[string]string{"PROVISIONER_SERVICE_TOKEN": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}},
		{"space", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "}},
		{"plus", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+"}},
		{"slash", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/"}},
		{"equals", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		{"two newlines", map[string]string{"PROVISIONER_SERVICE_TOKEN": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n"}},
		{"same current and previous token", map[string]string{"PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken, "PROVISIONER_PREVIOUS_SERVICE_TOKEN": validCurrentServiceToken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := loadServiceAuthConfig(environment(tc.values))
			if err == nil {
				t.Fatalf("config = %#v, error = nil", config)
			}
		})
	}
}

func TestLoadServiceAuthConfigRejectsFileWithTwoTrailingLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-token")
	if err := os.WriteFile(path, []byte(validCurrentServiceToken+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if config, err := loadServiceAuthConfig(environment(map[string]string{"PROVISIONER_SERVICE_TOKEN_FILE": path})); err == nil {
		t.Fatalf("config = %#v, error = nil", config)
	}
}
