package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type windowsUseCaseStub struct {
	calls   int
	payload []byte
	err     error
}

func (s *windowsUseCaseStub) MaxPayload() int { return 100000 }
func (s *windowsUseCaseStub) Submit(_ context.Context, request, target string, payload []byte) (windowsruntime.Record, bool, error) {
	s.calls++
	s.payload = bytes.Clone(payload)
	return windowsruntime.Record{ID: "00000000-0000-4000-8000-000000000003", TargetID: target, Phase: "QUEUED", Payload: payload, StartedBody: []byte("secret")}, true, s.err
}
func (s *windowsUseCaseStub) Get(context.Context, string) (windowsruntime.Record, error) {
	s.calls++
	if s.err != nil {
		return windowsruntime.Record{}, s.err
	}
	return windowsruntime.Record{ID: "00000000-0000-4000-8000-000000000003", Phase: "FINISHED", Payload: []byte("secret-payload"), StartedBody: []byte("secret-event"), Fingerprint: "private-fingerprint", Outcome: &windowsruntime.Outcome{Result: "succeeded"}}, nil
}

func TestWindowsHTTPUploadAndPrivateResult(t *testing.T) {
	use := &windowsUseCaseStub{}
	h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, nil, ReadinessConfig{}, nil, use)
	payload := append([]byte("MZ"), bytes.Repeat([]byte{'x'}, 70000)...)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/windows-vms/00000000-0000-4000-8000-000000000001/executions", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testCurrentServiceToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Request-ID", "00000000-0000-4000-8000-000000000002")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 202 || !bytes.Equal(use.payload, payload) || w.Header().Get("Location") != "/internal/v1/windows-executions/00000000-0000-4000-8000-000000000003" {
		t.Fatalf("upload code=%d body=%s bytes=%d", w.Code, w.Body.String(), len(use.payload))
	}
	req = httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	req.Header.Set("Authorization", "Bearer "+testCurrentServiceToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "fingerprint") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsafe response=%d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["phase"] != "FINISHED" {
		t.Fatal(body)
	}
}
func TestWindowsHTTPRejectsCIAndOversizeBeforeSubmission(t *testing.T) {
	ci := strings.Repeat("C", 43)
	auth := ServiceAuthConfig{CurrentToken: testCurrentServiceToken, CISmokeToken: ci, CISmokeTeamID: "00000000-0000-4000-8000-000000000018", CISmokeTargetID: "aws-dev"}
	for _, tc := range []struct {
		name, token, target, requestID, media string
		size, want                            int
	}{
		{"no auth", "", "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "application/octet-stream", 3, 401},
		{"CI", ci, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "application/octet-stream", 3, 403},
		{"target", testCurrentServiceToken, "invalid", "00000000-0000-4000-8000-000000000002", "application/octet-stream", 3, 400},
		{"key", testCurrentServiceToken, "00000000-0000-4000-8000-000000000001", "missing", "application/octet-stream", 3, 400},
		{"type", testCurrentServiceToken, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "application/json", 3, 415},
		{"oversize", testCurrentServiceToken, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "application/octet-stream", 100001, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			use := &windowsUseCaseStub{}
			h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, auth, nil, ReadinessConfig{}, nil, use)
			req := httptest.NewRequest(http.MethodPost, "/internal/v1/windows-vms/"+tc.target+"/executions", bytes.NewReader(bytes.Repeat([]byte{'x'}, tc.size)))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			req.Header.Set("Content-Type", tc.media)
			req.Header.Set("X-Request-ID", tc.requestID)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want || use.calls != 0 {
				t.Fatalf("code=%d calls=%d body=%s", w.Code, use.calls, w.Body.String())
			}
		})
	}
	use := &windowsUseCaseStub{err: windowsruntime.ErrNotFound}
	h := NewHandlerWithWindows(&recordingCreateUseCase{}, nil, auth, nil, ReadinessConfig{}, nil, use)
	for _, token := range []string{ci, testCurrentServiceToken} {
		req := httptest.NewRequest("GET", "/internal/v1/windows-executions/00000000-0000-4000-8000-000000000003", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := 404
		if token == ci {
			want = 403
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
