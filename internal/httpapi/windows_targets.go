package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type windowsTargetSource interface {
	ListTargets(context.Context, int, string) (windowsruntime.VMPage, error)
	TargetConnection(context.Context, string) (windowsruntime.Connection, error)
}

func (api *API) windowsTargetsAccess(w http.ResponseWriter, r *http.Request) (windowsTargetSource, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(r) {
		writeAPIError(w, 403, "FORBIDDEN", "CI smoke token cannot inspect Windows targets")
		return nil, false
	}
	source, ok := api.windows.(windowsTargetSource)
	if !ok {
		writeAPIError(w, 503, "WINDOWS_TARGETS_UNAVAILABLE", "Windows target discovery is unavailable")
		return nil, false
	}
	return source, true
}

func (api *API) handleWindowsTargets(w http.ResponseWriter, r *http.Request) {
	source, ok := api.windowsTargetsAccess(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	limit := 200
	if values, exists := query["limit"]; exists {
		if len(values) != 1 {
			writeAPIError(w, 400, "INVALID_REQUEST", "one limit value is required")
			return
		}
		var err error
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 200 {
			writeAPIError(w, 400, "INVALID_REQUEST", "limit must be between 1 and 200")
			return
		}
	}
	after := query.Get("after")
	if len(query["after"]) > 1 || len(after) > 512 || strings.IndexFunc(after, unicode.IsControl) >= 0 {
		writeAPIError(w, 400, "INVALID_REQUEST", "invalid pagination cursor")
		return
	}
	page, err := source.ListTargets(r.Context(), limit, after)
	if err != nil {
		writeWindowsTargetError(w, err)
		return
	}
	writeJSON(w, 200, page)
}

func (api *API) windowsConnection(w http.ResponseWriter, r *http.Request) (windowsruntime.Connection, bool) {
	source, ok := api.windowsTargetsAccess(w, r)
	if !ok {
		return windowsruntime.Connection{}, false
	}
	id := r.PathValue("resource_target_id")
	if !windowsruntime.ValidID(id) {
		writeAPIError(w, 400, "INVALID_REQUEST", "valid Windows VM UUID is required")
		return windowsruntime.Connection{}, false
	}
	connection, err := source.TargetConnection(r.Context(), id)
	if err != nil {
		writeWindowsTargetError(w, err)
		return windowsruntime.Connection{}, false
	}
	return connection, true
}

func (api *API) handleWindowsConnection(w http.ResponseWriter, r *http.Request) {
	connection, ok := api.windowsConnection(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, connection)
}

func (api *API) handleWindowsRDP(w http.ResponseWriter, r *http.Request) {
	connection, ok := api.windowsConnection(w, r)
	if !ok {
		return
	}
	profile, err := windowsruntime.BuildRDPProfile(connection, true)
	if err != nil {
		writeAPIError(w, 502, "WINDOWS_RDP_PROFILE_INVALID", "broker returned an invalid RDP profile")
		return
	}
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="windows-%s.rdp"`, connection.TargetID))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	_, _ = w.Write(profile)
}

func writeWindowsTargetError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var upstream *windowsruntime.APIError
	if errors.As(err, &upstream) {
		switch upstream.Status {
		case 404, 409, 503:
			status = upstream.Status
		}
		if upstream.Code == "BROKER_INVALID_REQUEST" {
			status = 400
		}
	}
	if errors.Is(err, windowsruntime.ErrTargetDiscoveryUnavailable) {
		status = 503
	}
	writeAPIError(w, status, "WINDOWS_TARGETS_UNAVAILABLE", "broker Windows targets could not be read")
}
