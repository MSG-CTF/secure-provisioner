package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type checkerUseCaseStub struct {
	calls      int
	backendIDs []string
}

func (s *checkerUseCaseStub) SubmitForBackend(_ context.Context, backendID string, request windowsruntime.CheckerRequest, token string) (windowsruntime.Record, bool, error) {
	s.calls++
	s.backendIDs = append(s.backendIDs, backendID)
	return windowsruntime.Record{ID: "00000000-0000-4000-8000-000000000004", RequestID: request.SubmissionID, Checker: &windowsruntime.CheckerJob{BackendID: backendID, AssignmentID: request.AssignmentID, Request: &request}}, true, nil
}
func (s *checkerUseCaseStub) GetForBackend(_ context.Context, backendID, submissionID string) (windowsruntime.Record, error) {
	s.calls++
	s.backendIDs = append(s.backendIDs, backendID)
	return windowsruntime.Record{ID: "00000000-0000-4000-8000-000000000004", RequestID: submissionID, Checker: &windowsruntime.CheckerJob{BackendID: backendID, AssignmentID: "00000000-0000-4000-8000-000000000003", Request: &windowsruntime.CheckerRequest{SubmissionID: submissionID}}}, nil
}

func TestCheckerHTTPBindsBackendIdentityToServiceToken(t *testing.T) {
	checker := &checkerUseCaseStub{}
	internalToken, externalToken := strings.Repeat("I", 43), strings.Repeat("E", 43)
	h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken, CheckerBackendTokens: map[string]string{"internal": internalToken, "external": externalToken}}, nil, ReadinessConfig{}, nil, &windowsUseCaseStub{}, checker)
	request := windowsruntime.CheckerRequest{RequestVersion: 1, SubmissionID: "00000000-0000-4000-8000-000000000002", AssignmentID: "00000000-0000-4000-8000-000000000003"}
	body, _ := json.Marshal(request)
	for _, tc := range []struct{ id, token string }{{"internal", internalToken}, {"external", externalToken}} {
		req := httptest.NewRequest(http.MethodPost, "/v1/checker-submissions", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", request.SubmissionID)
		req.Header.Set("X-Submission-Token", "backend-job-token-secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 202 || checker.backendIDs[len(checker.backendIDs)-1] != tc.id {
			t.Fatalf("%s post: %d %s ids=%v", tc.id, w.Code, w.Body, checker.backendIDs)
		}
		req = httptest.NewRequest(http.MethodGet, "/v1/checker-submissions/"+request.SubmissionID, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("X-Submission-Token", "backend-job-token-secret")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 || checker.backendIDs[len(checker.backendIDs)-1] != tc.id {
			t.Fatalf("%s get: %d %s ids=%v", tc.id, w.Code, w.Body, checker.backendIDs)
		}
	}
}

func TestCheckerHTTPUsesBackendEnvelopeAndRejectsMissingJobToken(t *testing.T) {
	checker := &checkerUseCaseStub{}
	checkerToken := strings.Repeat("K", 43)
	h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken, CheckerToken: checkerToken}, nil, ReadinessConfig{}, nil, &windowsUseCaseStub{}, checker)
	body, _ := json.Marshal(windowsruntime.CheckerRequest{RequestVersion: 1, SubmissionID: "00000000-0000-4000-8000-000000000002", AssignmentID: "00000000-0000-4000-8000-000000000003"})
	call := func(token, serviceToken string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/checker-submissions", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		req.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000002")
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Submission-Token", token)
		}
		writer := httptest.NewRecorder()
		h.ServeHTTP(writer, req)
		return writer
	}
	if w := call("", checkerToken); w.Code != 400 || checker.calls != 0 {
		t.Fatalf("missing token: %d %s", w.Code, w.Body.String())
	}
	if w := call("backend-job-token-secret", testCurrentServiceToken); w.Code != 401 || checker.calls != 0 {
		t.Fatalf("full service token accepted on checker route: %d %s", w.Code, w.Body.String())
	}
	w := call("backend-job-token-secret", checkerToken)
	if w.Code != 202 || checker.calls != 1 || !strings.Contains(w.Body.String(), `"checker_job_id":"00000000-0000-4000-8000-000000000004"`) || !strings.Contains(w.Body.String(), `"code":"SUCCESS"`) {
		t.Fatalf("checker response: %d %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/checker-submissions/00000000-0000-4000-8000-000000000002", nil)
	req.Header.Set("Authorization", "Bearer "+checkerToken)
	req.Header.Set("X-Submission-Token", "backend-job-token-secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || checker.calls != 2 || !strings.Contains(w.Body.String(), `"checker_job_id":"00000000-0000-4000-8000-000000000004"`) {
		t.Fatalf("checker get: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/v1/windows-vms", nil)
	req.Header.Set("Authorization", "Bearer "+checkerToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("checker token escaped its route scope: %d %s", w.Code, w.Body.String())
	}
}
