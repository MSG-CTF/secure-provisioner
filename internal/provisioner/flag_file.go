package provisioner

import (
	"path"
	"strings"
)

// ValidFlagFilePath limits the operator-owned FLAG projection to challenge files.
// Callers cannot choose this path through the HTTP container schema.
func ValidFlagFilePath(value string) bool {
	if len(value) > 512 || path.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if value == "/flag" || value == "/flag.txt" {
		return true
	}
	if path.Base(value) != "flag" && path.Base(value) != "flag.txt" {
		return false
	}
	return strings.HasPrefix(value, "/home/") || strings.HasPrefix(value, "/app/") || strings.HasPrefix(value, "/srv/")
}
