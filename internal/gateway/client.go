// Package gateway integrates the external MSG CTF route API. It never accepts
// participant-supplied destinations or secrets in workload requests.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Destination struct {
	TargetIP        string          `json:"target_ip"`
	TargetPort      int             `json:"target_port"`
	Protocol        string          `json:"protocol"`
	PublicTransport PublicTransport `json:"public_transport,omitempty"`
	OwnerTeamID     string          `json:"owner_team_id,omitempty"`
}
type Route struct {
	InstanceID          string          `json:"instance_id"`
	Hostname            string          `json:"hostname"`
	Port                int             `json:"port"`
	TLS                 bool            `json:"tls"`
	Protocol            string          `json:"protocol"`
	URL                 *string         `json:"url"`
	CreatedAt           time.Time       `json:"created_at"`
	PublicTransport     PublicTransport `json:"public_transport,omitempty"`
	OwnerTeamID         string          `json:"owner_team_id,omitempty"`
	OwnerAccessEnforced bool            `json:"owner_access_enforced,omitempty"`
}
type APIError struct {
	Code      string
	Status    int
	Permanent bool
}

func (e *APIError) Error() string { return e.Code }

type Client struct {
	base  string
	token string
	http  *http.Client
	gate  chan struct{}
}

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$`)
var validHostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.gate\.msgctf\.kr$`)

func NewClient(base, tokenFile string, timeout time.Duration, transport http.RoundTripper, limits ...int) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.Fragment != "" || timeout < 75*time.Second || !filepath.IsAbs(tokenFile) {
		return nil, errors.New("invalid Gateway HTTPS, token file or timeout configuration")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("Gateway token file unavailable")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return nil, errors.New("invalid Gateway token file")
	}
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	limit := 1
	if len(limits) > 0 {
		limit = limits[0]
	}
	if limit < 1 {
		return nil, errors.New("Gateway concurrency must be positive")
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, gate: make(chan struct{}, limit), http: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// PublicIP is intentionally stricter than a global-unicast check: documentation,
// carrier NAT, benchmark and other reserved ranges must not become upstreams.
func PublicIP(raw string) (string, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return "", errors.New("Gateway upstream must be a public IP literal")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "", errors.New("Gateway upstream is not public")
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "2002::/16", "64:ff9b:1::/48", "100::/64"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return "", errors.New("Gateway upstream is reserved")
		}
	}
	return ip.String(), nil
}
func (c *Client) Put(ctx context.Context, id string, d Destination) (Route, error) {
	var result Route
	// A missing/null TLS field must not silently select plaintext transport.
	var response struct {
		Route
		TLS *bool `json:"tls"`
	}
	ip, err := PublicIP(d.TargetIP)
	if err != nil || d.TargetPort < 1 || d.TargetPort > 65535 || (d.Protocol != "http" && d.Protocol != "tcp") || !d.validDraft() {
		return result, &APIError{Code: "GATEWAY_INVALID_DESTINATION", Permanent: true}
	}
	d.TargetIP = ip
	responseFailure := &APIError{Code: "GATEWAY_INVALID_RESPONSE"}
	if d.PublicTransport != TransportLegacy {
		responseFailure.Code = "GATEWAY_CONTRACT_UNCONFIRMED"
	}
	if err = c.call(ctx, http.MethodPut, id, d, &response); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Code == "GATEWAY_INVALID_RESPONSE" || (d.PublicTransport != TransportLegacy && apiErr.Status >= 200 && apiErr.Status < 300)) {
			return result, responseFailure
		}
		return result, err
	}
	result = response.Route
	if response.TLS == nil || result.InstanceID != id || !validHostname.MatchString(result.Hostname) || result.Port < 1 || result.Port > 65535 || result.Protocol != d.Protocol || result.CreatedAt.IsZero() {
		return Route{}, responseFailure
	}
	result.TLS = *response.TLS
	if d.PublicTransport != TransportLegacy && (result.PublicTransport != d.PublicTransport || result.OwnerTeamID != d.OwnerTeamID || !result.OwnerAccessEnforced || result.TLS != (d.PublicTransport == TransportTLS)) {
		return Route{}, responseFailure
	}
	if d.Protocol == "http" {
		if result.Port != 443 || !result.TLS || result.URL == nil || *result.URL != "https://"+result.Hostname {
			return Route{}, responseFailure
		}
	} else if result.URL != nil {
		return Route{}, responseFailure
	}
	return result, nil
}
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, id, nil, nil)
}
func (c *Client) call(ctx context.Context, method, id string, body any, result any) error {
	return c.callRoute(ctx, method, id, "", body, result)
}

func (c *Client) callRoute(ctx context.Context, method, id, suffix string, body any, result any) error {
	if !validID.MatchString(id) {
		return &APIError{Code: "GATEWAY_INVALID_INSTANCE_ID", Permanent: true}
	}
	// Runtime workers already bound the number of waiters. Share the request
	// deadline with this queue so a busy peer does not send every other worker
	// into exponential operation retries during a simultaneous reset.
	ctx, cancel := context.WithTimeout(ctx, c.http.Timeout)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return &APIError{Code: "GATEWAY_LOCAL_BUSY"}
	}
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return &APIError{Code: "GATEWAY_INVALID_REQUEST", Permanent: true}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/routes/"+url.PathEscape(id)+suffix, bytes.NewReader(payload))
	if err != nil {
		return &APIError{Code: "GATEWAY_REQUEST_FAILED"}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return &APIError{Code: "GATEWAY_UNAVAILABLE"}
	}
	defer response.Body.Close()
	if method == http.MethodDelete && response.StatusCode == 204 {
		return nil
	}
	if (method == http.MethodPut && (response.StatusCode == 200 || response.StatusCode == 201)) || (method == http.MethodGet && response.StatusCode == 200) {
		raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(raw) > 16384 || json.Unmarshal(raw, result) != nil {
			return &APIError{Code: "GATEWAY_INVALID_RESPONSE"}
		}
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	var failure struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &failure)
	code := "GATEWAY_HTTP_ERROR"
	switch failure.Error.Code {
	case "GATEWAY_BUSY", "INSTANCE_CONFLICT", "TARGET_IN_USE", "INSTANCE_DELETED", "NGINX_APPLY_FAILED", "INVALID_RUNTIME_TOKEN", "RUNTIME_AUTH_NOT_CONFIGURED", "GATEWAY_NOT_CONFIGURED", "CONTROLLER_UNAVAILABLE", "REGISTRY_INVALID", "NGINX_RECOVERY_REQUIRED", "VALIDATION_ERROR", "INVALID_TARGET", "INVALID_REQUEST", "INVALID_JSON", "INVALID_INSTANCE_ID",
		"PORT_POOL_EXHAUSTED", "PORT_ALLOCATION_CONFLICT", "OWNER_CONFLICT", "OWNER_ACCESS_NOT_CONFIGURED", "TRANSPORT_NOT_SUPPORTED", "ROUTE_CLEANUP_PENDING":
		code = failure.Error.Code
		if !strings.HasPrefix(code, "GATEWAY_") {
			code = "GATEWAY_" + code
		}
	}
	permanent := response.StatusCode == 400 || response.StatusCode == 409 || response.StatusCode == 422
	if destination, ok := body.(Destination); ok && destination.PublicTransport != TransportLegacy && response.StatusCode == http.StatusConflict && (failure.Error.Code == "PORT_ALLOCATION_CONFLICT" || failure.Error.Code == "ROUTE_CLEANUP_PENDING") {
		// Draft allocator contention and an unfinished route cleanup are not
		// evidence that a different instance owns the backend NodePort.
		permanent = false
	}
	return &APIError{Code: code, Status: response.StatusCode, Permanent: permanent}
}
