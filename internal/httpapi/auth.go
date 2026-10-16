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
	ciSmokeDigest  [sha256.Size]byte
	hasCurrent     bool
	hasPrevious    bool
	hasCISmoke     bool
}

type ciSmokeContextKey struct{}

type serviceRole uint8

const (
	serviceRoleNone serviceRole = iota
	serviceRoleFull
	serviceRoleCISmoke
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
	if config.CISmokeToken != "" && config.CISmokeTeamID.Valid() && config.CISmokeTargetID != "" {
		authenticator.ciSmokeDigest = sha256.Sum256([]byte(config.CISmokeToken))
		authenticator.hasCISmoke = true
	}
	return authenticator
}

func (authenticator serviceAuthenticator) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		role := authenticator.authenticate(request)
		if role == serviceRoleNone {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="secure-provisioner"`)
			writeAPIError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "service authentication failed")
			return
		}
		if role == serviceRoleCISmoke {
			request = request.WithContext(context.WithValue(request.Context(), ciSmokeContextKey{}, true))
		}
		next.ServeHTTP(writer, request)
	})
}

func (authenticator serviceAuthenticator) authenticate(request *http.Request) serviceRole {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return serviceRoleNone
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return serviceRoleNone
	}
	digest := sha256.Sum256([]byte(parts[1]))
	currentMatch := subtle.ConstantTimeCompare(digest[:], authenticator.currentDigest[:])
	previousMatch := subtle.ConstantTimeCompare(digest[:], authenticator.previousDigest[:])
	ciSmokeMatch := subtle.ConstantTimeCompare(digest[:], authenticator.ciSmokeDigest[:])
	if !authenticator.hasCurrent {
		return serviceRoleNone
	}
	if currentMatch == 1 || authenticator.hasPrevious && previousMatch == 1 {
		return serviceRoleFull
	}
	if authenticator.hasCISmoke && ciSmokeMatch == 1 {
		return serviceRoleCISmoke
	}
	return serviceRoleNone
}

func isCISmokeRequest(request *http.Request) bool {
	return request.Context().Value(ciSmokeContextKey{}) == true
}
