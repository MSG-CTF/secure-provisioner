package provisioner

import (
	"strings"
	"unicode"
	"unicode/utf16"
)

const MaxHTTPReadinessPathLength = 1024

// ValidHTTPReadinessPath matches the Scheduler's HTTP healthcheck path rule.
// Java/Kotlin String.length counts UTF-16 code units, so use that limit here.
func ValidHTTPReadinessPath(value string) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	length := 0
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
		length += utf16.RuneLen(character)
		if length > MaxHTTPReadinessPathLength {
			return false
		}
	}
	return true
}
