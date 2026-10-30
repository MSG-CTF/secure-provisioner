package windowsruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCheckerScopesSameSubmissionIDToBackend(t *testing.T) {
	service, _, _ := serviceFixture(t, &serviceBroker{}, Outcome{Result: "failed"})
	payload := []byte("MZ test")
	called := map[string]int{}
	client := &http.Client{Transport: checkerRoundTrip(func(request *http.Request) (*http.Response, error) {
		backendID := strings.TrimSuffix(request.URL.Hostname(), ".example")
		if backendID != "internal" && backendID != "external" || request.URL.Path != "/internal/v1/checker-submissions/"+testRequest+"/payload" && request.URL.Path != "/internal/v1/checker-submissions/"+testRequest+"/events" || request.Header.Get("Authorization") != "Bearer "+backendID+"-job-token-secret" {
			t.Errorf("misrouted Backend call: %s %s", request.Method, request.URL)
		}
		called[backendID]++
		response := &http.Response{StatusCode: 200, Header: make(http.Header)}
		if request.Method == http.MethodGet {
			response.Header.Set("Content-Type", "application/octet-stream")
			response.Body = io.NopCloser(strings.NewReader(string(payload)))
		} else {
			response.Body = io.NopCloser(strings.NewReader(`{"code":"SUCCESS","data":{"submission_id":"` + testRequest + `","event_id":"00000000-0000-4000-8000-000000000010","accepted":true}}`))
		}
		return response, nil
	})}
	checker, err := NewChecker(service, CheckerConfig{
		Backends: map[string]string{"internal": "https://internal.example", "external": "https://external.example"},
		Targets:  map[string]bool{testTarget: true}, CheckerCommitSHA: strings.Repeat("a", 40),
		VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1",
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	request := CheckerRequest{
		RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003",
		TeamID: "00000000-0000-4000-8000-000000000005", ChallengeID: "00000000-0000-4000-8000-000000000006",
		ReleaseID: "00000000-0000-4000-8000-000000000007", VMID: testTarget, ReadinessCheckID: "ready",
		PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536,
		CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64),
		DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1",
	}
	internal, created, err := checker.SubmitForBackend(context.Background(), "internal", request, "internal-job-token-secret")
	if err != nil || !created {
		t.Fatalf("internal submit: created=%v err=%v", created, err)
	}
	if _, err := checker.GetForBackend(context.Background(), "external", testRequest); err != ErrNotFound {
		t.Fatalf("external backend read internal job: %v", err)
	}
	external, created, err := checker.SubmitForBackend(context.Background(), "external", request, "external-job-token-secret")
	if err != nil || !created {
		t.Fatalf("external submit: created=%v err=%v", created, err)
	}
	if internal.ID == external.ID || internal.RequestID == external.RequestID || internal.Checker.BackendURL != "https://internal.example" || external.Checker.BackendURL != "https://external.example" {
		t.Fatalf("backend jobs collided or misrouted: internal=%+v external=%+v", internal, external)
	}
	for _, tc := range []struct {
		backend string
		want    string
	}{{"internal", internal.ID}, {"external", external.ID}} {
		got, err := checker.GetForBackend(context.Background(), tc.backend, testRequest)
		if err != nil || got.ID != tc.want {
			t.Fatalf("%s lookup: %+v %v", tc.backend, got, err)
		}
		fetched, err := service.fetchCheckerPayload(context.Background(), got)
		if err != nil || string(fetched) != string(payload) {
			t.Fatalf("%s payload: %s %v", tc.backend, fetched, err)
		}
		got.Checker.ResultPending = true
		got.Checker.ResultEventID = "00000000-0000-4000-8000-000000000010"
		got.Checker.ResultBody = []byte(`{}`)
		if err := service.postCheckerResult(context.Background(), got); err != nil {
			t.Fatalf("%s callback: %v", tc.backend, err)
		}
		if called[tc.backend] != 2 {
			t.Fatalf("%s calls = %d", tc.backend, called[tc.backend])
		}
	}
	if _, err := checker.GetForBackend(context.Background(), "unconfigured", testRequest); err != ErrNotFound {
		t.Fatalf("unconfigured backend read: %v", err)
	}
	if _, _, err := checker.SubmitForBackend(context.Background(), "unconfigured", request, "another-job-token-secret"); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestCheckerRejectsOriginWithEmptyQueryOrFragment(t *testing.T) {
	service, _, _ := serviceFixture(t, &serviceBroker{}, Outcome{Result: "failed"})
	for _, origin := range []string{"https://internal.example?", "https://internal.example#"} {
		_, err := NewChecker(service, CheckerConfig{
			Backends: map[string]string{"internal": origin}, Targets: map[string]bool{testTarget: true},
			CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64),
			DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1",
		}, &http.Client{})
		if err == nil {
			t.Fatalf("accepted malformed Backend origin %q", origin)
		}
	}
}
