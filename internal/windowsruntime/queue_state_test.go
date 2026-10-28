package windowsruntime

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCheckerQueueProjectionFollowsAssignmentAndPersistsReceiptOrder(t *testing.T) {
	ctx := context.Background()
	service, store, _ := serviceFixture(t, &serviceBroker{}, Outcome{Result: "failed"})
	service.SetPoolTargets(map[string]ExecutorCredential{testTarget: {}})
	checker, err := NewChecker(service, CheckerConfig{Backends: map[string]string{"internal": "https://backend.example"}, Targets: map[string]bool{testTarget: true}, CheckerCommitSHA: strings.Repeat("a", 40), ConfigVersion: "test-v1"}, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := CheckerRequest{RequestVersion: 1, SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", TeamID: "00000000-0000-4000-8000-000000000005", ChallengeID: "00000000-0000-4000-8000-000000000006", PayloadSHA256: strings.Repeat("b", 64), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), ConfigVersion: "test-v1"}
	first, created, err := checker.SubmitForBackend(ctx, "internal", request, "backend-job-token-secret")
	if err != nil || !created || first.QueueState != "QUEUED" || first.QueuePosition == nil || *first.QueuePosition != 1 {
		t.Fatalf("first queue receipt: %+v %v", first, err)
	}
	replay, created, err := checker.SubmitForBackend(ctx, "internal", request, "backend-job-token-secret")
	if err != nil || created || replay.ID != first.ID || replay.QueuePosition == nil || *replay.QueuePosition != 1 {
		t.Fatalf("receipt replay: %+v %v", replay, err)
	}
	request.SubmissionID = "00000000-0000-4000-8000-000000000007"
	request.AssignmentID = "00000000-0000-4000-8000-000000000008"
	request.TeamID = "00000000-0000-4000-8000-000000000009"
	second, _, err := checker.SubmitForBackend(ctx, "internal", request, "backend-job-token-secret")
	if err != nil || second.QueuePosition == nil || *second.QueuePosition != 2 {
		t.Fatalf("second queue receipt: %+v %v", second, err)
	}
	r, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil || r == nil || r.ID != first.ID {
		t.Fatalf("claim: %+v %v", r, err)
	}
	r.Phase = "QUEUED"
	if err := store.Save(ctx, *r, "worker"); err != nil {
		t.Fatal(err)
	}
	if bound, err := store.BindTarget(ctx, r.ID, "worker", testTarget); err != nil || !bound {
		t.Fatalf("bind: %v %v", bound, err)
	}
	assigned, err := checker.GetForBackend(ctx, "internal", first.Checker.Request.SubmissionID)
	if err != nil || assigned.QueueState != "PREPARING" || assigned.QueuePosition != nil {
		t.Fatalf("assigned projection: %+v %v", assigned, err)
	}
	waiting, err := checker.GetForBackend(ctx, "internal", second.Checker.Request.SubmissionID)
	if err != nil || waiting.QueueState != "QUEUED" || waiting.QueuePosition == nil || *waiting.QueuePosition != 1 {
		t.Fatalf("remaining queue: %+v %v", waiting, err)
	}
}
