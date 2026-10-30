package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadinessRequiresFullServiceAuthenticationBeforeDatabaseRead(t *testing.T) {
	for _, token := range []string{"", "wrong", testCISmokeToken, testCurrentServiceToken, testPreviousServiceToken} {
		t.Run(token, func(t *testing.T) {
			config := ciSmokeAuthConfig(t)
			config.PreviousToken = testPreviousServiceToken
			calls := 0
			handler := NewHandlerWithRuntimeReadiness(nil, nil, config, nil, ReadinessConfig{
				StoreMode: "postgres", CheckDatabase: func(context.Context) error { calls++; return nil },
			})
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/healthz", nil)
			if token != "" {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := http.StatusOK
			if token == "" || token == "wrong" {
				want = http.StatusUnauthorized
			} else if token == testCISmokeToken {
				want = http.StatusForbidden
			}
			if response.Code != want || (calls == 1) != (want == http.StatusOK) {
				t.Fatalf("code=%d, calls=%d, want code=%d", response.Code, calls, want)
			}
		})
	}
}

func TestReadinessReportsOnlyLiveDurableStoreAndSafeMetadata(t *testing.T) {
	for _, test := range []struct {
		name, store, database string
		bridge                bool
		check                 func(context.Context) error
		code                  int
	}{
		{"primary", "postgres", "ok", false, func(context.Context) error { return nil }, 200},
		{"bridge", "postgres", "ok", true, func(context.Context) error { return nil }, 200},
		{"unavailable", "postgres", "down", false, func(context.Context) error { return errors.New("private-dsn-and-password") }, 503},
		{"missing-check", "postgres", "down", false, nil, 503},
		{"ephemeral-store", "memory", "not_configured", false, nil, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandlerWithRuntimeReadiness(nil, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, nil,
				ReadinessConfig{StoreMode: test.store, APIOnly: test.bridge, CheckDatabase: test.check})
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/healthz", nil)
			request.Header.Set("Authorization", "Bearer "+testCurrentServiceToken)
			response := httptest.NewRecorder()
			before := time.Now().UTC()
			handler.ServeHTTP(response, request)
			var body readinessResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			_ = json.Unmarshal(response.Body.Bytes(), &fields)
			if response.Code != test.code || body.Database != test.database || body.StoreMode != test.store ||
				(body.Status == "ok") != (test.code == 200) || (body.Mode == "deployment_bridge") != test.bridge ||
				body.CheckedAt.Before(before) || body.CheckedAt.After(time.Now().UTC()) || len(fields) != 5 ||
				response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("code=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestReadinessDatabaseCheckHasDeadlineAndHonorsRequestCancellation(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/healthz", nil)
	request.Header.Set("Authorization", "Bearer "+testCurrentServiceToken)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	request = request.WithContext(ctx)
	handler := NewHandlerWithRuntimeReadiness(nil, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, nil,
		ReadinessConfig{StoreMode: "postgres", CheckDatabase: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 2*time.Second || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("database check lacks a bounded canceled context")
			}
			return nil // An ignored cancellation must still never produce a ready response.
		}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled check returned %d", response.Code)
	}
}
