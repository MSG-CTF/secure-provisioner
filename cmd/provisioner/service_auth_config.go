package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

var serviceTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func loadServiceAuthConfig(getenv func(string) string) (httpapi.ServiceAuthConfig, error) {
	if getenv == nil {
		return httpapi.ServiceAuthConfig{}, errors.New("environment reader is required")
	}
	current, err := readServiceTokenSetting(getenv, "PROVISIONER_SERVICE_TOKEN", "PROVISIONER_SERVICE_TOKEN_FILE", true)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	previous, err := readServiceTokenSetting(getenv, "PROVISIONER_PREVIOUS_SERVICE_TOKEN", "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	if previous != "" && current == previous {
		return httpapi.ServiceAuthConfig{}, errors.New("current and previous service tokens must differ")
	}
	checker, err := readServiceTokenSetting(getenv, "PROVISIONER_CHECKER_SERVICE_TOKEN", "PROVISIONER_CHECKER_SERVICE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	if checker != "" && (checker == current || checker == previous) {
		return httpapi.ServiceAuthConfig{}, errors.New("checker service token must differ from full service tokens")
	}
	internalChecker, err := readServiceTokenSetting(getenv, "PROVISIONER_CHECKER_INTERNAL_SERVICE_TOKEN", "PROVISIONER_CHECKER_INTERNAL_SERVICE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	externalChecker, err := readServiceTokenSetting(getenv, "PROVISIONER_CHECKER_EXTERNAL_SERVICE_TOKEN", "PROVISIONER_CHECKER_EXTERNAL_SERVICE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	if (internalChecker == "") != (externalChecker == "") || checker != "" && internalChecker != "" {
		return httpapi.ServiceAuthConfig{}, errors.New("configure both internal and external checker tokens, or the legacy checker token")
	}
	if internalChecker != "" && (internalChecker == externalChecker || internalChecker == current || internalChecker == previous || externalChecker == current || externalChecker == previous) {
		return httpapi.ServiceAuthConfig{}, errors.New("checker backend service tokens must be distinct from each other and full service tokens")
	}
	recovery, err := readServiceTokenSetting(getenv, "PROVISIONER_WINDOWS_RECOVERY_TOKEN", "PROVISIONER_WINDOWS_RECOVERY_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	if recovery != "" && (recovery == current || recovery == previous || recovery == checker || recovery == internalChecker || recovery == externalChecker) {
		return httpapi.ServiceAuthConfig{}, errors.New("Windows recovery token must differ from service and checker tokens")
	}
	ciSmoke, err := readServiceTokenSetting(getenv, "PROVISIONER_CI_SMOKE_TOKEN", "PROVISIONER_CI_SMOKE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	ciTeamID := getenv("PROVISIONER_CI_SMOKE_TEAM_ID")
	ciTargetID := getenv("PROVISIONER_CI_SMOKE_TARGET_ID")
	if ciSmoke != "" {
		if ciSmoke == current || ciSmoke == previous || ciSmoke == checker || ciSmoke == internalChecker || ciSmoke == externalChecker || ciSmoke == recovery {
			return httpapi.ServiceAuthConfig{}, errors.New("CI smoke token must differ from full service tokens")
		}
		if !provisioner.TeamID(ciTeamID).Valid() || ciTargetID == "" || ciTargetID != strings.TrimSpace(ciTargetID) {
			return httpapi.ServiceAuthConfig{}, errors.New("CI smoke token requires a valid team ID and target ID")
		}
	} else if ciTeamID != "" || ciTargetID != "" {
		return httpapi.ServiceAuthConfig{}, errors.New("CI smoke scope requires a token")
	}
	var checkerBackendTokens map[string]string
	if internalChecker != "" {
		checkerBackendTokens = map[string]string{"internal": internalChecker, "external": externalChecker}
	}
	return httpapi.ServiceAuthConfig{CurrentToken: current, PreviousToken: previous, CheckerToken: checker, CheckerBackendTokens: checkerBackendTokens, WindowsRecoveryToken: recovery, CISmokeToken: ciSmoke, CISmokeTeamID: provisioner.TeamID(ciTeamID), CISmokeTargetID: ciTargetID}, nil
}

func readServiceTokenSetting(getenv func(string) string, valueKey, fileKey string, required bool) (string, error) {
	value := getenv(valueKey)
	filePath := getenv(fileKey)
	if value != "" && filePath != "" {
		return "", fmt.Errorf("%s and %s cannot both be set", valueKey, fileKey)
	}
	if value == "" && filePath == "" {
		if required {
			return "", fmt.Errorf("%s or %s is required", valueKey, fileKey)
		}
		return "", nil
	}
	if filePath != "" {
		if !filepath.IsAbs(filePath) {
			return "", fmt.Errorf("%s must be an absolute path", fileKey)
		}
		contents, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileKey, err)
		}
		value = removeOneTrailingLineEnding(string(contents))
	}
	if !serviceTokenPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a 43-128 character Base64URL token", valueKey)
	}
	return value, nil
}

func removeOneTrailingLineEnding(value string) string {
	if strings.HasSuffix(value, "\r\n") {
		return strings.TrimSuffix(value, "\r\n")
	}
	return strings.TrimSuffix(value, "\n")
}
