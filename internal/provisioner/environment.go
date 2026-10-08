package provisioner

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

var environmentName = regexp.MustCompile("^[A-Z_][A-Z0-9_]{0,63}$")
var sensitiveEnvironmentName = regexp.MustCompile("SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL")

func ValidSecretReference(reference string) bool {
	if reference == "" {
		return true
	}
	parsed, err := uuid.Parse(reference)
	return err == nil && parsed != uuid.Nil && parsed.String() == reference
}

func ValidateEnvironment(env map[string]string, secret bool) error {
	if len(env) > 32 {
		return errors.New("environment has more than 32 entries")
	}
	total := 0
	for name, value := range env {
		if !environmentName.MatchString(name) {
			return errors.New("invalid environment name")
		}
		if !secret && (name == "FLAG" || sensitiveEnvironmentName.MatchString(name)) {
			return errors.New("secret values require secret_ref")
		}
		if !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return errors.New("invalid environment value")
		}
		total += len(name) + len(value)
	}
	if total > 16384 {
		return errors.New("environment exceeds 16384 bytes")
	}
	return nil
}
