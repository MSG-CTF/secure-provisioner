package provisioner

import (
	"net"
	"strconv"
	"strings"
)

// ImageRepository removes a digest or tag and canonicalizes registry aliases.
// Nondefault registry ports are preserved; explicit HTTPS 443 and a trailing
// DNS dot identify the same registry as its unqualified hostname.
// This is a policy lookup key, not a replacement for immutable-image validation.
func ImageRepository(image string) string {
	name, _, _ := strings.Cut(image, "@")
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	if registry, remainder, qualified := strings.Cut(name, "/"); qualified {
		if host, port, err := net.SplitHostPort(registry); err == nil {
			host = strings.TrimSuffix(host, ".")
			if number, err := strconv.Atoi(port); err == nil {
				port = strconv.Itoa(number)
			}
			if port == "443" {
				registry = host
				if strings.Contains(host, ":") {
					registry = "[" + host + "]"
				}
			} else {
				registry = net.JoinHostPort(host, port)
			}
		} else {
			registry = strings.TrimSuffix(registry, ".")
		}
		name = registry + "/" + remainder
	}
	return strings.ToLower(name)
}
