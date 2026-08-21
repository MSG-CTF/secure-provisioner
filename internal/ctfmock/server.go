package ctfmock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const mockChallengeFlag = "MSG{reflected_xss_runtime_demo}"

var mockChallengeTemplate = template.Must(template.New("mock-xss").Parse(`<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Reflected Search</title>
  <style>
    body { max-width: 720px; margin: 56px auto; padding: 0 20px; font: 16px/1.5 system-ui,sans-serif; color: #17202a; }
    input { width: min(100%,520px); padding: 10px; border: 1px solid #9aa5b1; }
    button { padding: 10px 16px; background: #087e8b; color: white; border: 0; cursor: pointer; }
    code { background: #eef2f5; padding: 2px 5px; }
    .meta { color: #52616b; font-size: 14px; }
  </style>
</head>
<body>
  <h1>Reflected Search</h1>
  <form method="get">
    <input name="q" autocomplete="off" placeholder="Search term">
    <button type="submit">Search</button>
  </form>
  <p class="meta">Instance <code>{{.InstanceID}}</code></p>
</body>
</html>`))

type Scenario struct {
	SchedulerUnavailable      bool `json:"scheduler_unavailable"`
	CatalogUnavailable        bool `json:"catalog_unavailable"`
	EndpointUnhealthy         bool `json:"endpoint_unhealthy"`
	BrokerCallbackUnavailable bool `json:"broker_callback_unavailable"`
	SLAUnavailable            bool `json:"sla_unavailable"`
	ReleaseUnavailable        bool `json:"release_unavailable"`
}

type RecordedEvent struct {
	Target     string         `json:"target"`
	Payload    map[string]any `json:"payload"`
	ReceivedAt time.Time      `json:"received_at"`
}

type Server struct {
	mu             sync.RWMutex
	provisionerURL string
	httpClient     *http.Client
	scenario       Scenario
	events         []RecordedEvent
}

func NewHandler(provisionerURL string) http.Handler {
	server := &Server{
		provisionerURL: strings.TrimRight(provisionerURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", server.handleHealth)
	mux.HandleFunc("GET /health/ready", server.handleHealth)
	mux.HandleFunc("GET /mock/v1/scenario", server.handleGetScenario)
	mux.HandleFunc("PUT /mock/v1/scenario", server.handleSetScenario)
	mux.HandleFunc("GET /mock/v1/events", server.handleGetEvents)
	mux.HandleFunc("GET /mock/v1/scheduler/reservations/{reservationId}", server.handleReservation)
	mux.HandleFunc("POST /mock/v1/scheduler/releases", server.handleRelease)
	mux.HandleFunc("GET /mock/v1/catalog/challenges/{challengeId}", server.handleChallenge)
	mux.HandleFunc("GET /mock/v1/challenges/{instanceId}", server.handleChallengeEndpoint)
	mux.HandleFunc("POST /mock/v1/broker/events", server.handleBrokerEvent)
	mux.HandleFunc("POST /mock/v1/sla/events", server.handleSLAEvent)
	mux.HandleFunc("POST /mock/v1/broker/instances", server.proxyCreate)
	mux.HandleFunc("GET /mock/v1/broker/instances/{instanceId}", server.proxyGetInstance)
	mux.HandleFunc("DELETE /mock/v1/broker/instances/{instanceId}", server.proxyDelete)
	mux.HandleFunc("GET /mock/v1/broker/operations/{operationId}", server.proxyGetOperation)
	mux.HandleFunc("GET /mock/v1/broker/debug/resources/{instanceId}", server.proxyGetResources)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
		mux.ServeHTTP(writer, request)
	})
}

func (server *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) handleGetScenario(writer http.ResponseWriter, _ *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()
	writeJSON(writer, http.StatusOK, server.scenario)
}

func (server *Server) handleSetScenario(writer http.ResponseWriter, request *http.Request) {
	var scenario Scenario
	if err := decodeJSON(request, &scenario); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_SCENARIO", err.Error())
		return
	}

	server.mu.Lock()
	server.scenario = scenario
	server.mu.Unlock()
	writeJSON(writer, http.StatusOK, scenario)
}

func (server *Server) handleGetEvents(writer http.ResponseWriter, _ *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()

	events := append([]RecordedEvent(nil), server.events...)
	writeJSON(writer, http.StatusOK, map[string]any{"events": events})
}

func (server *Server) handleReservation(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().SchedulerUnavailable {
		writeError(writer, http.StatusServiceUnavailable, "SCHEDULER_UNAVAILABLE", "fake scheduler is unavailable")
		return
	}

	reservationID := request.PathValue("reservationId")
	writeJSON(writer, http.StatusOK, map[string]any{
		"reservation_id":        reservationID,
		"cluster_id":            "k3s-local",
		"valid":                 reservationID != "invalid",
		"cpu_millicores":        500,
		"memory_mib":            256,
		"ephemeral_storage_mib": 256,
	})
}

func (server *Server) handleRelease(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().ReleaseUnavailable {
		writeError(writer, http.StatusServiceUnavailable, "RELEASE_UNAVAILABLE", "fake reservation release is unavailable")
		return
	}

	var payload map[string]any
	if err := decodeJSON(request, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_RELEASE", err.Error())
		return
	}
	server.record("scheduler-release", payload)
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) handleChallenge(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().CatalogUnavailable {
		writeError(writer, http.StatusServiceUnavailable, "CATALOG_UNAVAILABLE", "fake challenge catalog is unavailable")
		return
	}

	challengeID := request.PathValue("challengeId")
	xssImage := os.Getenv("CTF_MOCK_XSS_IMAGE")
	if xssImage == "" {
		xssImage = "msg-ctf/reflected-xss@sha256:" + strings.Repeat("d", 64)
	}
	challenges := map[string]map[string]any{
		"xss-101": {
			"challenge_id":     "xss-101",
			"image":            xssImage,
			"container_port":   8080,
			"command":          []string{"/xss-challenge"},
			"security_profile": "restricted-web",
			"resource_profile": "small",
			"network_profile":  "http-ingress-no-egress",
			"runtime_class":    "runc",
		},
		"pwn-101": {
			"challenge_id":     "pwn-101",
			"image":            "ghcr.io/msg-ctf/sample-pwn@sha256:" + strings.Repeat("a", 64),
			"container_port":   31337,
			"security_profile": "pwn-sandbox",
			"resource_profile": "small",
			"network_profile":  "tcp-ingress-dns-egress",
			"runtime_class":    "runc",
		},
		"web-101": {
			"challenge_id":     "web-101",
			"image":            "ghcr.io/msg-ctf/sample-web@sha256:" + strings.Repeat("b", 64),
			"container_port":   8080,
			"security_profile": "standard-web",
			"resource_profile": "small",
			"network_profile":  "http-ingress-dns-egress",
			"runtime_class":    "runc",
		},
		"kernel-101": {
			"challenge_id":     "kernel-101",
			"image":            "ghcr.io/msg-ctf/sample-kernel@sha256:" + strings.Repeat("c", 64),
			"container_port":   9000,
			"security_profile": "strong-isolation",
			"resource_profile": "large",
			"network_profile":  "tcp-ingress-dns-egress",
			"runtime_class":    "kata-qemu",
		},
	}

	challenge, exists := challenges[challengeID]
	if !exists {
		writeError(writer, http.StatusNotFound, "CHALLENGE_NOT_FOUND", "challenge was not found")
		return
	}
	writeJSON(writer, http.StatusOK, challenge)
}

func (server *Server) handleChallengeEndpoint(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().EndpointUnhealthy {
		writeError(writer, http.StatusServiceUnavailable, "CHALLENGE_UNHEALTHY", "fake challenge endpoint is unhealthy")
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	query, searched := request.URL.Query()["q"]
	if !searched {
		_ = mockChallengeTemplate.Execute(writer, map[string]string{"InstanceID": request.PathValue("instanceId")})
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     "flag",
		Value:    mockChallengeFlag,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
	value := ""
	if len(query) > 0 {
		value = query[0]
	}

	// This unescaped reflection intentionally mirrors the XSS challenge fixture.
	_, _ = fmt.Fprintf(writer, `<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Search result</title></head>
<body><h1>Search result</h1><div id="result">You searched for: %s</div><p><a href="%s">Back</a></p></body>
</html>`, value, template.URL(request.URL.Path))
}

func (server *Server) handleBrokerEvent(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().BrokerCallbackUnavailable {
		writeError(writer, http.StatusServiceUnavailable, "BROKER_CALLBACK_UNAVAILABLE", "fake Broker callback is unavailable")
		return
	}
	server.recordEventRequest(writer, request, "broker")
}

func (server *Server) handleSLAEvent(writer http.ResponseWriter, request *http.Request) {
	if server.currentScenario().SLAUnavailable {
		writeError(writer, http.StatusServiceUnavailable, "SLA_UNAVAILABLE", "fake SLA receiver is unavailable")
		return
	}
	server.recordEventRequest(writer, request, "sla")
}

func (server *Server) recordEventRequest(writer http.ResponseWriter, request *http.Request, target string) {
	var payload map[string]any
	if err := decodeJSON(request, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_EVENT", err.Error())
		return
	}
	server.record(target, payload)
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) proxyCreate(writer http.ResponseWriter, request *http.Request) {
	server.proxy(writer, request, http.MethodPost, "/internal/v1/instances")
}

func (server *Server) proxyGetInstance(writer http.ResponseWriter, request *http.Request) {
	path := "/internal/v1/instances/" + url.PathEscape(request.PathValue("instanceId"))
	server.proxy(writer, request, http.MethodGet, path)
}

func (server *Server) proxyDelete(writer http.ResponseWriter, request *http.Request) {
	path := "/internal/v1/instances/" + url.PathEscape(request.PathValue("instanceId"))
	server.proxy(writer, request, http.MethodDelete, path)
}

func (server *Server) proxyGetOperation(writer http.ResponseWriter, request *http.Request) {
	path := "/internal/v1/operations/" + url.PathEscape(request.PathValue("operationId"))
	server.proxy(writer, request, http.MethodGet, path)
}

func (server *Server) proxyGetResources(writer http.ResponseWriter, request *http.Request) {
	path := "/internal/v1/debug/resources/" + url.PathEscape(request.PathValue("instanceId"))
	server.proxy(writer, request, http.MethodGet, path)
}

func (server *Server) proxy(writer http.ResponseWriter, incoming *http.Request, method string, path string) {
	if server.provisionerURL == "" {
		writeError(writer, http.StatusServiceUnavailable, "PROVISIONER_NOT_CONFIGURED", "fake Broker has no Provisioner URL")
		return
	}

	body, err := io.ReadAll(io.LimitReader(incoming.Body, 64<<10))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "could not read request")
		return
	}

	request, err := http.NewRequestWithContext(incoming.Context(), method, server.provisionerURL+path, bytes.NewReader(body))
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "PROXY_ERROR", "could not build Provisioner request")
		return
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := server.httpClient.Do(request)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "PROVISIONER_UNAVAILABLE", "Provisioner is unavailable")
		return
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		writeError(writer, http.StatusBadGateway, "PROXY_ERROR", "could not read Provisioner response")
		return
	}

	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(responseBody)
}

func (server *Server) currentScenario() Scenario {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.scenario
}

func (server *Server) record(target string, payload map[string]any) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.events = append(server.events, RecordedEvent{
		Target:     target,
		Payload:    payload,
		ReceivedAt: time.Now().UTC(),
	})
}

func decodeJSON(request *http.Request, destination any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeError(writer http.ResponseWriter, status int, code string, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
