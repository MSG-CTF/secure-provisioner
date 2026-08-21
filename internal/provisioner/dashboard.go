package provisioner

import (
	_ "embed"
	"net/http"
)

//go:embed web/dashboard.html
var dashboardHTML []byte

func (api *API) handleDashboard(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(dashboardHTML)
}
