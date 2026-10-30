package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

const recoveryTarget = "00000000-0000-4000-8000-000000000001"
const recoveryExecution = "00000000-0000-4000-8000-000000000004"
const recoveryEvent = "00000000-0000-4000-8000-000000000005"
const recoveryToken = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"

type recoveryUseCaseStub struct {
	windowsUseCaseStub
	calls   int
	receipt windowsruntime.RecoveryReceipt
	err     error
}

func (s *recoveryUseCaseStub) ConfirmRecovery(_ context.Context, targetID, executionID, eventID string) (windowsruntime.RecoveryReceipt, error) {
	s.calls++
	if targetID != recoveryTarget || executionID != recoveryExecution || eventID != recoveryEvent {
		return windowsruntime.RecoveryReceipt{}, windowsruntime.ErrConflict
	}
	return s.receipt, s.err
}

func TestWindowsRecoveryEndpointRequiresDedicatedTokenAndValidReceipt(t *testing.T) {
	use := &recoveryUseCaseStub{receipt: windowsruntime.RecoveryReceipt{
		TargetID: recoveryTarget, ExecutionID: recoveryExecution, EventID: recoveryEvent,
		VMState: "READY", CleanupDelivery: "PENDING",
	}}
	h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, ServiceAuthConfig{
		CurrentToken: testCurrentServiceToken, WindowsRecoveryToken: recoveryToken,
	}, nil, ReadinessConfig{}, nil, use)
	path := "/internal/v1/windows-vms/" + recoveryTarget + "/recovery-events"
	body := `{"execution_id":"` + recoveryExecution + `","event_id":"` + recoveryEvent + `","vm_state":"READY"}`
	request := func(token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		return response
	}
	for _, token := range []string{"", testCurrentServiceToken, strings.Repeat("K", 43)} {
		if got := request(token, body); got.Code != 401 {
			t.Fatalf("token %q: status=%d body=%s", token, got.Code, got.Body)
		}
	}
	for _, invalid := range []string{
		`{"execution_id":"bad","event_id":"` + recoveryEvent + `","vm_state":"READY"}`,
		`{"execution_id":"` + recoveryExecution + `","event_id":"` + recoveryEvent + `","vm_state":"RESET_REQUIRED"}`,
		`{"execution_id":"` + recoveryExecution + `","event_id":"` + recoveryEvent + `","vm_state":"READY","extra":1}`,
	} {
		if got := request(recoveryToken, invalid); got.Code != 400 {
			t.Fatalf("invalid body: status=%d body=%s", got.Code, got.Body)
		}
	}
	if use.calls != 0 {
		t.Fatalf("invalid requests reached store: %d", use.calls)
	}
	got := request(recoveryToken, body)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"cleanup_delivery":"PENDING"`) || use.calls != 1 {
		t.Fatalf("recovery receipt: status=%d body=%s calls=%d", got.Code, got.Body, use.calls)
	}
	other := httptest.NewRequest(http.MethodGet, "/internal/v1/windows-executions/"+recoveryExecution, nil)
	other.Header.Set("Authorization", "Bearer "+recoveryToken)
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, other)
	if denied.Code != 401 {
		t.Fatalf("recovery token accessed another API: %d %s", denied.Code, denied.Body)
	}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{windowsruntime.ErrNotFound, 404, "WINDOWS_EXECUTION_NOT_FOUND"},
		{windowsruntime.ErrConflict, 409, "WINDOWS_RECOVERY_CONFLICT"},
		{windowsruntime.ErrRecoveryNotReady, 409, "WINDOWS_EXECUTION_NOT_FINISHED"},
		{windowsruntime.ErrRecoveryUnavailable, 503, "WINDOWS_RECOVERY_UNAVAILABLE"},
	} {
		use.err = tc.err
		got := request(recoveryToken, body)
		if got.Code != tc.status || !strings.Contains(got.Body.String(), tc.code) {
			t.Fatalf("error %v: status=%d body=%s", tc.err, got.Code, got.Body)
		}
	}
}
