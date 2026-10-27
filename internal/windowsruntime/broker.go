package windowsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const maxBrokerResponse = 256 * 1024
const maxBrokerListResponse = 8 << 20

// APIError deliberately contains no response body, URL, or wrapped transport
// error: those can include credentials and remote diagnostic text.
type APIError struct {
	Status int
	Code   string
}

func (err *APIError) Error() string {
	return fmt.Sprintf("windows broker request failed (status %d, code %s)", err.Status, safeBrokerCode(err.Code))
}

func safeBrokerCode(code string) string {
	switch code {
	case "WINDOWS_VM_NOT_READY", "WINDOWS_VM_NOT_FOUND", "WINDOWS_EXECUTION_NOT_FOUND",
		"WINDOWS_CONNECTION_DISABLED", "WINDOWS_VM_UNAVAILABLE", "WINDOWS_VM_ADDRESS_UNAVAILABLE",
		"WINDOWS_EXECUTION_CONFLICT", "WINDOWS_EXECUTION_FINISHED", "DATABASE_ERROR",
		"WINDOWS_CONNECTION_NOT_CONFIGURED", "RUNTIME_AUTH_NOT_CONFIGURED",
		"BROKER_CONFIG_INVALID", "BROKER_INVALID_REQUEST", "BROKER_INVALID_RESPONSE",
		"BROKER_TRANSPORT_ERROR", "BROKER_HTTP_ERROR":
		return code
	default:
		return "BROKER_HTTP_ERROR"
	}
}

// ValidID accepts only the canonical lower-case, hyphenated UUID spelling.
func ValidID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && len(id) == 36 && parsed.String() == id
}

type HTTPBroker struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewBroker(baseURL, token string, client *http.Client) (*HTTPBroker, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, &APIError{Code: "BROKER_CONFIG_INVALID"}
	}
	loopback := strings.EqualFold(parsed.Hostname(), "localhost")
	if addr, parseErr := netip.ParseAddr(parsed.Hostname()); parseErr == nil {
		loopback = addr.IsLoopback()
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return nil, &APIError{Code: "BROKER_CONFIG_INVALID"}
	}
	if token == "" || strings.IndexFunc(token, unicode.IsSpace) >= 0 || strings.IndexFunc(token, unicode.IsControl) >= 0 {
		return nil, &APIError{Code: "BROKER_CONFIG_INVALID"}
	}
	copyClient := http.Client{Timeout: 30 * time.Second}
	if client != nil {
		copyClient = *client
		if copyClient.Timeout <= 0 {
			copyClient.Timeout = 30 * time.Second
		}
	}
	// Always stop at the first response, including same-origin redirects. A
	// caller's redirect policy must never forward this broker's bearer token.
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPBroker{baseURL: strings.TrimRight(parsed.String(), "/"), token: token, client: &copyClient}, nil
}

func (broker *HTTPBroker) Connection(ctx context.Context, targetID string) (Connection, error) {
	if !ValidID(targetID) {
		return Connection{}, &APIError{Code: "BROKER_INVALID_REQUEST"}
	}
	body, err := broker.request(ctx, http.MethodGet, targetID, "connection", nil)
	if err != nil {
		return Connection{}, err
	}
	var connection Connection
	if decodeBrokerJSON(body, &connection, false) != nil || !validBrokerConnection(connection, targetID) {
		return Connection{}, &APIError{Status: http.StatusOK, Code: "BROKER_INVALID_RESPONSE"}
	}
	return connection, nil
}

func validBrokerCursor(cursor string) bool {
	return len(cursor) <= 512 && strings.IndexFunc(cursor, unicode.IsControl) < 0
}

// List discovers available targets without reserving or connecting to any VM.
func (broker *HTTPBroker) List(ctx context.Context, limit int, after string) (VMPage, error) {
	if limit < 1 || limit > 200 || !validBrokerCursor(after) {
		return VMPage{}, &APIError{Code: "BROKER_INVALID_REQUEST"}
	}
	query := url.Values{"limit": {fmt.Sprint(limit)}}
	if after != "" {
		query.Set("after", after)
	}
	data, err := broker.requestPath(ctx, http.MethodGet, "/v1/runtime/windows-vms?"+query.Encode(), nil, maxBrokerListResponse)
	if err != nil {
		return VMPage{}, err
	}
	var page VMPage
	if decodeBrokerJSON(data, &page, false) != nil || page.Items == nil || len(page.Items) > limit {
		return VMPage{}, &APIError{Status: 200, Code: "BROKER_INVALID_RESPONSE"}
	}
	seen := make(map[string]bool, len(page.Items))
	for _, item := range page.Items {
		if !validBrokerConnection(item, item.TargetID) || seen[item.TargetID] {
			return VMPage{}, &APIError{Status: 200, Code: "BROKER_INVALID_RESPONSE"}
		}
		seen[item.TargetID] = true
	}
	if page.NextCursor != nil && (*page.NextCursor == "" || !validBrokerCursor(*page.NextCursor) || *page.NextCursor == after) {
		return VMPage{}, &APIError{Status: 200, Code: "BROKER_INVALID_RESPONSE"}
	}
	return page, nil
}

func validBrokerConnection(connection Connection, targetID string) bool {
	addr, err := netip.ParseAddr(connection.Host)
	if connection.TargetID != targetID || !ValidID(connection.TargetID) || connection.Protocol != "rdp" || err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || connection.Port < 1 || connection.Port > 65535 || len(connection.ExecutorCertificatePEM) > 1<<20 {
		return false
	}
	if connection.Username == "" || len(connection.Username) > 256 {
		return false
	}
	for _, char := range connection.Username {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !strings.ContainsRune("_.@\\$-", char) {
			return false
		}
	}
	return connection.Username[0] != '-' && connection.Username[0] != '\\'
}

type brokerEvent struct {
	ExecutionID string `json:"execution_id"`
	Event       string `json:"event"`
	Result      string `json:"result,omitempty"`
	ExitCode    *int64 `json:"exit_code"`
}

func (broker *HTTPBroker) Event(ctx context.Context, targetID string, body []byte) (EventAck, error) {
	var event brokerEvent
	if !ValidID(targetID) || len(body) == 0 || len(body) > 4096 || decodeBrokerJSON(body, &event, true) != nil || !validBrokerEvent(event) {
		return EventAck{}, &APIError{Code: "BROKER_INVALID_REQUEST"}
	}
	response, err := broker.request(ctx, http.MethodPost, targetID, "execution-events", body)
	if err != nil {
		return EventAck{}, err
	}
	var ack EventAck
	if decodeBrokerJSON(response, &ack, false) != nil || ack.TargetID != targetID || ack.ExecutionID != event.ExecutionID {
		return EventAck{}, &APIError{Status: http.StatusOK, Code: "BROKER_INVALID_RESPONSE"}
	}
	executionState := "RUNNING"
	if event.Event == "finished" {
		executionState = "FINISHED"
	}
	// VMState reports the VM's current state. A replay of this finished event
	// can arrive after the VM has been reset or assigned to another execution.
	if ack.ExecutionState != executionState || ack.VMState == "" || event.Event == "started" && ack.VMState != "RUNNING" {
		return EventAck{}, &APIError{Status: http.StatusOK, Code: "BROKER_INVALID_RESPONSE"}
	}
	return ack, nil
}

func validBrokerEvent(event brokerEvent) bool {
	if !ValidID(event.ExecutionID) {
		return false
	}
	if event.Event == "started" {
		return event.Result == "" && event.ExitCode == nil
	}
	if event.Event != "finished" {
		return false
	}
	switch event.Result {
	case "succeeded":
		if event.ExitCode == nil || *event.ExitCode != 0 {
			return false
		}
	case "failed", "timeout", "unreachable":
	default:
		return false
	}
	return event.ExitCode == nil || (*event.ExitCode >= -2147483648 && *event.ExitCode <= 4294967295)
}

func decodeBrokerJSON(body []byte, destination any, rejectUnknown bool) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if rejectUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected JSON suffix")
	}
	return nil
}

func (broker *HTTPBroker) request(ctx context.Context, method, targetID, operation string, body []byte) ([]byte, error) {
	return broker.requestPath(ctx, method, "/v1/runtime/windows-vms/"+targetID+"/"+operation, body, maxBrokerResponse)
}

func (broker *HTTPBroker) requestPath(ctx context.Context, method, path string, body []byte, responseLimit int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, broker.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, &APIError{Code: "BROKER_INVALID_REQUEST"}
	}
	request.Header.Set("Authorization", "Bearer "+broker.token)
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := broker.client.Do(request)
	if err != nil {
		return nil, &APIError{Code: "BROKER_TRANSPORT_ERROR"}
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, int64(responseLimit)+1))
	if err != nil || len(responseBody) > responseLimit {
		return nil, &APIError{Status: response.StatusCode, Code: "BROKER_INVALID_RESPONSE"}
	}
	if response.StatusCode != http.StatusOK {
		code := "BROKER_HTTP_ERROR"
		var remoteError struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if decodeBrokerJSON(responseBody, &remoteError, false) == nil {
			code = safeBrokerCode(remoteError.Error.Code)
		}
		return nil, &APIError{Status: response.StatusCode, Code: code}
	}
	return responseBody, nil
}
