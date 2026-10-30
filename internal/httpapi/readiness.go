package httpapi

import (
	"context"
	"net/http"
	"time"
)

// ReadinessConfig checks the persistent control plane without changing workloads.
// The deployment bridge intentionally has no worker and remains API-ready.
type ReadinessConfig struct {
	StoreMode     string
	APIOnly       bool
	CheckDatabase func(context.Context) error
}

type readinessResponse struct {
	Status    string    `json:"status"`
	StoreMode string    `json:"store_mode"`
	Database  string    `json:"database"`
	Mode      string    `json:"mode"`
	CheckedAt time.Time `json:"checked_at"`
}

func (config ReadinessConfig) handle(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(request) {
		writeAPIError(writer, http.StatusForbidden, "FORBIDDEN", "CI smoke token cannot inspect control-plane readiness")
		return
	}
	response := readinessResponse{Status: "down", StoreMode: "memory", Database: "not_configured", Mode: "primary"}
	if config.APIOnly {
		response.Mode = "deployment_bridge"
	}
	if config.StoreMode == "postgres" {
		response.StoreMode = "postgres"
		response.Database = "down"
		if config.CheckDatabase != nil {
			ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
			defer cancel()
			if err := config.CheckDatabase(ctx); err == nil && ctx.Err() == nil {
				response.Status, response.Database = "ok", "ok"
			}
		}
	}
	response.CheckedAt = time.Now().UTC()
	code := http.StatusServiceUnavailable
	if response.Status == "ok" {
		code = http.StatusOK
	}
	// Never include a DSN, database error, queue contents or workload identity.
	writeJSON(writer, code, response)
}
