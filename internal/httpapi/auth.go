package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

type serviceAuthenticator struct {
	currentDigest  [sha256.Size]byte
	previousDigest [sha256.Size]byte
	checkerDigests map[string][sha256.Size]byte
	ciSmokeDigest  [sha256.Size]byte
	hasCurrent     bool
	hasPrevious    bool
	hasCISmoke     bool
}

type ciSmokeContextKey struct{}
type checkerBackendContextKey struct{}

type serviceRole uint8

const (
	serviceRoleNone serviceRole = iota
	serviceRoleFull
	serviceRoleCISmoke
	serviceRoleChecker
)

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
	authenticator.checkerDigests = make(map[string][sha256.Size]byte)
	if config.CheckerToken != "" && len(config.CheckerBackendTokens) == 0 {
		authenticator.checkerDigests["default"] = sha256.Sum256([]byte(config.CheckerToken))
	}
	for backendID, token := range config.CheckerBackendTokens {
		if token != "" {
			authenticator.checkerDigests[backendID] = sha256.Sum256([]byte(token))
		}
	}
	if config.CISmokeToken != "" && config.CISmokeTeamID.Valid() && config.CISmokeTargetID != "" {
		authenticator.ciSmokeDigest = sha256.Sum256([]byte(config.CISmokeToken))
		authenticator.hasCISmoke = true
	}
	return authenticator
}

func (authenticator serviceAuthenticator) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		role, backendID := authenticator.authenticate(request)
		checkerRoute := request.URL.Path == "/v1/checker-submissions" || strings.HasPrefix(request.URL.Path, "/v1/checker-submissions/")
		if role == serviceRoleNone || checkerRoute && role != serviceRoleChecker || !checkerRoute && role == serviceRoleChecker {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="secure-provisioner"`)
			writeAPIError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "service authentication failed")
			return
		}
		if role == serviceRoleCISmoke {
			request = request.WithContext(context.WithValue(request.Context(), ciSmokeContextKey{}, true))
		}
		if role == serviceRoleChecker {
			request = request.WithContext(context.WithValue(request.Context(), checkerBackendContextKey{}, backendID))
		}
		next.ServeHTTP(writer, request)
	})
}

func (authenticator serviceAuthenticator) authenticate(request *http.Request) (serviceRole, string) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return serviceRoleNone, ""
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return serviceRoleNone, ""
	}
	digest := sha256.Sum256([]byte(parts[1]))
	currentMatch := subtle.ConstantTimeCompare(digest[:], authenticator.currentDigest[:])
	previousMatch := subtle.ConstantTimeCompare(digest[:], authenticator.previousDigest[:])
	ciSmokeMatch := subtle.ConstantTimeCompare(digest[:], authenticator.ciSmokeDigest[:])
	if !authenticator.hasCurrent {
		return serviceRoleNone, ""
	}
	if currentMatch == 1 || authenticator.hasPrevious && previousMatch == 1 {
		return serviceRoleFull, ""
	}
	for backendID, checkerDigest := range authenticator.checkerDigests {
		if subtle.ConstantTimeCompare(digest[:], checkerDigest[:]) == 1 {
			return serviceRoleChecker, backendID
		}
	}
	if authenticator.hasCISmoke && ciSmokeMatch == 1 {
		return serviceRoleCISmoke, ""
	}
	return serviceRoleNone, ""
}

func checkerBackendID(request *http.Request) string {
	id, _ := request.Context().Value(checkerBackendContextKey{}).(string)
	return id
}

func isCISmokeRequest(request *http.Request) bool {
	return request.Context().Value(ciSmokeContextKey{}) == true
}
