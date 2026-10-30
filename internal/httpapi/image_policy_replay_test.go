package httpapi

// Accepted requests retain their identity when the operator reloads image policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

type reviewUnusedRuntimeAdapters struct{}

func (reviewUnusedRuntimeAdapters) CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	panic("review enqueue test must not create a real workload")
}

func (reviewUnusedRuntimeAdapters) Get(context.Context, runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	panic("review enqueue test must not query a real cluster")
}

func (reviewUnusedRuntimeAdapters) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	panic("review enqueue test must not delete a real workload")
}

func reviewRuntimeService(t *testing.T, store operations.Store) *runtimeops.Service {
	t.Helper()
	adapter := reviewUnusedRuntimeAdapters{}
	service, err := runtimeops.NewService(adapter, adapter, adapter, runtimebinding.NewMemoryStore(), store, isolation.NewStaticResolver(), runtimeops.Config{
		MaxAttempts: 3,
		Worker:      operations.WorkerConfig{Concurrency: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func reviewPolicyHandler(t *testing.T, store operations.Store, policyJSON string) http.Handler {
	t.Helper()
	catalog, err := ParseImagePolicies([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	service := reviewRuntimeService(t, store)
	return withTestServiceAuthentication(NewHandlerWithRuntimePolicies(service, service, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, catalog))
}

func reviewGradeRequestBody(t *testing.T) string {
	t.Helper()
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{
		Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true,
		RunAsUser: 10001, WritablePaths: []WritablePath{{Path: "/tmp", SizeMiB: 64}},
	}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func reviewPostBody(handler http.Handler, body string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	return response
}

func TestImagePolicyReplaySamePolicyReplayReturnsExistingOperation(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "review-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	first := reviewPostBody(reviewPolicyHandler(t, store, testImagePolicies), body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := reviewPostBody(reviewPolicyHandler(t, store, testImagePolicies), body)
	if second.Code != http.StatusAccepted || !strings.Contains(second.Body.String(), `"created":false`) {
		t.Fatalf("same policy replay status=%d body=%s", second.Code, second.Body.String())
	}
}

func TestImagePolicyReplayChangedCallerRequestStillConflicts(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "review-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	handler := reviewPolicyHandler(t, store, testImagePolicies)
	if first := reviewPostBody(handler, body); first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var changed CreateWorkloadRequest
	if err := json.Unmarshal([]byte(body), &changed); err != nil {
		t.Fatal(err)
	}
	changed.Workload.ResourceLimits.MemoryMiB++
	encoded, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if response := reviewPostBody(handler, string(encoded)); response.Code != http.StatusConflict {
		t.Fatalf("changed caller body status=%d body=%s, want 409", response.Code, response.Body.String())
	}
}

func TestImagePolicyReplayAcceptedRequestReplaysAfterCatalogPathUpdate(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "review-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	first := reviewPostBody(reviewPolicyHandler(t, store, testImagePolicies), body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	updated := strings.Replace(testImagePolicies, `"path": "/app/instance", "size_mib": 32`, `"path": "/app/instance", "size_mib": 48`, 1)
	if updated == testImagePolicies {
		t.Fatal("test did not change the catalog")
	}
	replay := reviewPostBody(reviewPolicyHandler(t, store, updated), body)
	if replay.Code != http.StatusAccepted || !strings.Contains(replay.Body.String(), `"created":false`) {
		t.Fatalf("same accepted body after operator catalog reload: status=%d body=%s, want 202 and existing operation", replay.Code, replay.Body.String())
	}
}

func TestImagePolicyReplayAcceptedRequestReplaysAfterCatalogBlock(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "review-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	first := reviewPostBody(reviewPolicyHandler(t, store, testImagePolicies), body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	blocked := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "blocked", "blocked_reason": "paused for review",`, 1)
	replay := reviewPostBody(reviewPolicyHandler(t, store, blocked), body)
	if replay.Code != http.StatusAccepted || !strings.Contains(replay.Body.String(), `"created":false`) {
		t.Fatalf("same accepted body after operator catalog block: status=%d body=%s, want 202 and existing operation", replay.Code, replay.Body.String())
	}
}

func TestImagePolicyReplayBlockedCatalogRejectsNewRequest(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "new-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	blocked := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "blocked", "blocked_reason": "paused for review",`, 1)
	response := reviewPostBody(reviewPolicyHandler(t, store, blocked), body)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("new blocked request status=%d", response.Code)
	}
}

func TestImagePolicyReplayRejectsChangesToOverriddenInput(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "changed-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	handler := reviewPolicyHandler(t, store, testImagePolicies)
	if response := reviewPostBody(handler, body); response.Code != http.StatusAccepted {
		t.Fatal(response.Body.String())
	}
	var changed CreateWorkloadRequest
	if err := json.Unmarshal([]byte(body), &changed); err != nil {
		t.Fatal(err)
	}
	changed.Workload.Containers[0].WritablePaths[0].SizeMiB++
	encoded, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if response := reviewPostBody(handler, string(encoded)); response.Code != http.StatusConflict {
		t.Fatalf("changed overridden input status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestImagePolicyReplayConcurrentReplicasRetainFirstApprovedPolicy(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "concurrent-policy-operation", nil })
	body := reviewGradeRequestBody(t)
	updated := strings.Replace(testImagePolicies, `"path": "/app/instance", "size_mib": 32`, `"path": "/app/instance", "size_mib": 48`, 1)
	handlers := []http.Handler{reviewPolicyHandler(t, store, testImagePolicies), reviewPolicyHandler(t, store, updated)}
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 20)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func(i int) { defer group.Done(); <-start; responses <- reviewPostBody(handlers[i%2], body) }(i)
	}
	close(start)
	group.Wait()
	close(responses)
	created := 0
	for response := range responses {
		if response.Code != http.StatusAccepted {
			t.Fatal(response.Body.String())
		}
		if strings.Contains(response.Body.String(), `"created":true`) {
			created++
		}
		if !strings.Contains(response.Body.String(), `"operation_id":"concurrent-policy-operation"`) {
			t.Fatal(response.Body.String())
		}
	}
	if created != 1 {
		t.Fatalf("created %d operations", created)
	}
}
