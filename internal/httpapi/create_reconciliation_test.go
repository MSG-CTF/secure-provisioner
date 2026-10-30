package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type reconciliationRuntime struct {
	recordingRuntimeUseCase
	store   *operations.MemoryStore
	command provisioner.CreateWorkloadCommand
	calls   int
}

func (runtime *reconciliationRuntime) ReconcileCreate(command provisioner.CreateWorkloadCommand) (operations.Operation, bool, error) {
	runtime.command = command
	runtime.calls++
	return runtime.store.ReconcileCreate(command, 4)
}

func TestReconcileCreateReturnsTerminalFenceAndOriginalInputFingerprint(t *testing.T) {
	runtime := &reconciliationRuntime{store: operations.NewMemoryStore(nil)}
	handler := newTestHandlerWithRuntime(&recordingCreateUseCase{}, runtime)
	path := "/internal/v1/instances/" + runtimeInstanceID + "/reconcile_create"
	var originalID string
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(validCreateRequestJSON()))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var body OperationResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Status != "FAILED" || body.LastErrorCode != "CREATE_NOT_ACCEPTED" || !body.CleanupCompleted {
			t.Fatalf("unconfirmed reconciliation result: %#v", body)
		}
		if originalID != "" && originalID != body.OperationID {
			t.Fatalf("replay changed operation: %s, %s", originalID, body.OperationID)
		}
		originalID = body.OperationID
	}
	if runtime.createCalls != 0 || len(runtime.command.RequestFingerprint) != 64 {
		t.Fatalf("create calls=%d fingerprint=%q", runtime.createCalls, runtime.command.RequestFingerprint)
	}
}

func TestReconcileCreateRejectsAuthenticationScopeAndMalformedIdentity(t *testing.T) {
	for _, test := range []struct {
		name, body, instance, token string
		status                      int
	}{
		{name: "no authentication", body: validCreateRequestJSON(), instance: runtimeInstanceID, status: http.StatusUnauthorized},
		{name: "CI scope mismatch", body: validCreateRequestJSON(), instance: runtimeInstanceID, token: strings.Repeat("C", 43), status: http.StatusForbidden},
		{name: "path mismatch", body: validCreateRequestJSON(), instance: "11111111-1111-4111-8111-111111111111", token: testCurrentServiceToken, status: http.StatusConflict},
		{name: "camelCase request field", body: strings.Replace(validCreateRequestJSON(), `"request_id"`, `"requestId"`, 1), instance: runtimeInstanceID, token: testCurrentServiceToken, status: http.StatusBadRequest},
		{name: "invalid UUID", body: strings.Replace(validCreateRequestJSON(), runtimeInstanceID, "invalid", 1), instance: "invalid", token: testCurrentServiceToken, status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &reconciliationRuntime{store: operations.NewMemoryStore(nil)}
			handler := NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken,
				CISmokeToken: strings.Repeat("C", 43), CISmokeTeamID: "00000000-0000-4000-8000-000000000019", CISmokeTargetID: "ci-target"})
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances/"+test.instance+"/reconcile_create", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || runtime.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, runtime.calls, response.Body.String())
			}
		})
	}
}

func TestReconcileCreateRejectsChangedPayloadWithoutChangingFence(t *testing.T) {
	runtime := &reconciliationRuntime{store: operations.NewMemoryStore(nil)}
	handler := newTestHandlerWithRuntime(&recordingCreateUseCase{}, runtime)
	path := "/internal/v1/instances/" + runtimeInstanceID + "/reconcile_create"
	for index, body := range []string{validCreateRequestJSON(), strings.Replace(validCreateRequestJSON(), `"target_id":"aws-dev"`, `"target_id":"other-target"`, 1)} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := http.StatusAccepted
		if index == 1 {
			want = http.StatusConflict
		}
		if response.Code != want {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}
