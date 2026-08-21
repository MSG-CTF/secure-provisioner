package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

type serviceAuthenticator struct {
	currentDigest  [sha256.Size]byte
	previousDigest [sha256.Size]byte
	hasCurrent     bool
	hasPrevious    bool
}

func newServiceAuthenticator(config ServiceAuthConfig) serviceAuthenticator {
	authenticator := serviceAuthenticator{}
	if config.CurrentToken != "" {
		authenticator.currentDigest = sha256.Sum256([]byte(config.CurrentToken))
		authenticator.hasCurrent = true
	}
	if config.PreviousToken != "" {
		authenticator.previousDigest = sha256.Sum256([]byte(config.PreviousToken))
		authenticator.hasPrevious = true
	}
	return authenticator
}

func (authenticator serviceAuthenticator) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !authenticator.authenticate(request) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="secure-provisioner"`)
			writeAPIError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "service authentication failed")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (authenticator serviceAuthenticator) authenticate(request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	digest := sha256.Sum256([]byte(parts[1]))
	currentMatch := subtle.ConstantTimeCompare(digest[:], authenticator.currentDigest[:])
	previousMatch := subtle.ConstantTimeCompare(digest[:], authenticator.previousDigest[:])
	return authenticator.hasCurrent && (currentMatch == 1 || authenticator.hasPrevious && previousMatch == 1)
}
