package k3s

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type SecretResolver interface {
	Resolve(context.Context, string, string, string) (map[string]string, error)
}

type BackendSecretResolver struct {
	endpoint string
	token    string
	client   *http.Client
}

var secretServiceToken = regexp.MustCompile("^[A-Za-z0-9_-]{32,256}$")

func NewBackendSecretResolver(origin, token string) (*BackendSecretResolver, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.ContainsAny(origin, "\\ \t\r\n") || !secretServiceToken.MatchString(token) {
		return nil, errors.New("invalid Backend secret resolver configuration")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" &&
		(parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
		return nil, errors.New("Backend secret resolver requires HTTPS or literal loopback HTTP")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &BackendSecretResolver{
		endpoint: strings.TrimRight(origin, "/") + "/internal/v1/runtime-secrets/resolve",
		token:    token,
		client: &http.Client{
			Transport: transport, Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (resolver *BackendSecretResolver) Resolve(ctx context.Context, reference, container, image string) (map[string]string, error) {
	if resolver == nil || !provisioner.ValidSecretReference(reference) || reference == "" {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
	}
	encoded, _ := json.Marshal(map[string]string{"secret_ref": reference, "container": container, "image": image})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
	}
	request.Header.Set("Authorization", "Bearer "+resolver.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := resolver.client.Do(request)
	if err != nil {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", true, nil)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", response.StatusCode >= 500 || response.StatusCode == 429, nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if err != nil || len(body) > 128<<10 {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
	}
	var envelope struct {
		Code string `json:"code"`
		Data struct {
			Env map[string]json.RawMessage `json:"env"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Code != "SUCCESS" || len(envelope.Data.Env) == 0 {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
	}
	values := make(map[string]string, len(envelope.Data.Env))
	for name, raw := range envelope.Data.Env {
		var value string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
			return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		values[name] = value
	}
	if provisioner.ValidateEnvironment(values, true) != nil {
		return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
	}
	return values, nil
}
