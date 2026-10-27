package httpapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

const discoveryTarget = "00000000-0000-4000-8000-000000000001"

type windowsDiscoveryStub struct {
	windowsUseCaseStub
	lists, connections int
	limit              int
	after              string
	targetErr          error
}

func (s *windowsDiscoveryStub) ListTargets(_ context.Context, limit int, after string) (windowsruntime.VMPage, error) {
	s.lists++
	s.limit = limit
	s.after = after
	return windowsruntime.VMPage{Items: []windowsruntime.Connection{discoveryConnection()}}, s.targetErr
}
func (s *windowsDiscoveryStub) TargetConnection(context.Context, string) (windowsruntime.Connection, error) {
	s.connections++
	return discoveryConnection(), s.targetErr
}
func discoveryConnection() windowsruntime.Connection {
	return windowsruntime.Connection{TargetID: discoveryTarget, Name: "broker-windows", Protocol: "rdp", Host: "192.0.2.33", Port: 3390, Username: "msgexec", RDPFile: "full address:s:192.0.2.33:3390\r\nusername:s:msgexec\r\nprompt for credentials:i:1\r\nenablecredsspsupport:i:1\r\nredirectclipboard:i:0\r\nredirectprinters:i:0\r\ndrivestoredirect:s:\r\n"}
}
func discoveryHandler(use *windowsDiscoveryStub) http.Handler {
	return NewHandlerWithWindows(&recordingCreateUseCase{}, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken, CISmokeToken: strings.Repeat("C", 43), CISmokeTeamID: "00000000-0000-4000-8000-000000000018", CISmokeTargetID: "aws-dev"}, nil, ReadinessConfig{}, nil, use)
}
func discoveryCall(h http.Handler, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestWindowsTargetDiscoveryUsesBrokerWithoutSubmission(t *testing.T) {
	use := &windowsDiscoveryStub{}
	h := discoveryHandler(use)
	w := discoveryCall(h, "/internal/v1/windows-vms?limit=2&after=cursor%2B1", testCurrentServiceToken)
	if w.Code != 200 || use.lists != 1 || use.limit != 2 || use.after != "cursor+1" || !strings.Contains(w.Body.String(), discoveryTarget) {
		t.Fatalf("list=%d %s %+v", w.Code, w.Body.String(), use)
	}
	w = discoveryCall(h, "/internal/v1/windows-vms/"+discoveryTarget+"/connection", testCurrentServiceToken)
	if w.Code != 200 || use.connections != 1 || !strings.Contains(w.Body.String(), "rdp_file") {
		t.Fatalf("connection=%d %s", w.Code, w.Body.String())
	}
	w = discoveryCall(h, "/internal/v1/windows-vms/"+discoveryTarget+"/connection.rdp", testCurrentServiceToken)
	raw := w.Body.Bytes()
	if w.Code != 200 || len(raw) < 2 || !bytes.Equal(raw[:2], []byte{0xff, 0xfe}) || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/x-rdp") || !strings.Contains(w.Header().Get("Content-Disposition"), discoveryTarget+".rdp") {
		t.Fatalf("rdp status=%d headers=%v", w.Code, w.Header())
	}
	units := make([]uint16, (len(raw)-2)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2+2*i:])
	}
	text := string(utf16.Decode(units))
	for _, wanted := range []string{"full address:s:192.0.2.33:3390", "username:s:msgexec", "authentication level:i:1", "redirectclipboard:i:0", "prompt for credentials:i:1"} {
		if !strings.Contains(text, wanted) {
			t.Fatal("missing RDP property", wanted)
		}
	}
	if use.calls != 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("discovery reserved or cached a VM")
	}
}
func TestWindowsTargetDiscoveryRejectsUnauthorizedAndInvalidQueries(t *testing.T) {
	for _, path := range []string{"/internal/v1/windows-vms", "/internal/v1/windows-vms/" + discoveryTarget + "/connection", "/internal/v1/windows-vms/" + discoveryTarget + "/connection.rdp"} {
		for _, token := range []string{"", strings.Repeat("C", 43)} {
			use := &windowsDiscoveryStub{}
			w := discoveryCall(discoveryHandler(use), path, token)
			want := 401
			if token != "" {
				want = 403
			}
			if w.Code != want || use.lists+use.connections != 0 {
				t.Fatalf("unauthorized %s => %d calls=%d", path, w.Code, use.lists+use.connections)
			}
		}
	}
	for _, query := range []string{"limit=0", "limit=201", "limit=wrong", "limit=1&limit=2", "after=bad%0Avalue", "after=" + strings.Repeat("x", 513)} {
		use := &windowsDiscoveryStub{}
		w := discoveryCall(discoveryHandler(use), "/internal/v1/windows-vms?"+query, testCurrentServiceToken)
		if w.Code != 400 || use.lists != 0 {
			t.Fatalf("query %s => %d", query, w.Code)
		}
	}
}
func TestWindowsTargetDiscoveryPropagatesAvailabilityNotBrokerAuth(t *testing.T) {
	for _, tc := range []struct{ upstream, want int }{{409, 409}, {404, 404}, {401, 502}, {503, 503}} {
		use := &windowsDiscoveryStub{targetErr: &windowsruntime.APIError{Status: tc.upstream, Code: "WINDOWS_VM_NOT_READY"}}
		w := discoveryCall(discoveryHandler(use), "/internal/v1/windows-vms/"+discoveryTarget+"/connection", testCurrentServiceToken)
		if w.Code != tc.want {
			t.Fatalf("upstream %d => %d", tc.upstream, w.Code)
		}
	}
}
