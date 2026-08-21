package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const interactionToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestMVPInteractionCreateStatusAndTTLDelete(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	database, err := runtimepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := sqlDB.Exec(`TRUNCATE runtime_operations, runtime_bindings`); err != nil {
		t.Fatal(err)
	}
	createResult := provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-k3s-001/instance-11111111", NamespaceUID: "namespace-uid",
		ServiceURL: "http://203.0.113.10:30080",
		Endpoints:  []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://203.0.113.10:30080"}},
	}
	service, err := runtimeops.NewService(
		&interactionCreate{result: createResult}, &interactionStatus{}, &interactionDelete{},
		database.Bindings(), database.Operations(), isolation.NewStaticResolver(), runtimeops.Config{
			MaxAttempts: 4, CleanupTimeout: time.Second, DeleteCoordinator: database.DeleteCoordinator(),
			Worker: operations.WorkerConfig{Concurrency: 2, WorkerID: "interaction", PollInterval: time.Millisecond, LeaseDuration: time.Second, RenewInterval: 100 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("worker shutdown: %v", err)
		}
	}()
	handler := httpapi.NewHandlerWithRuntime(service, service, httpapi.ServiceAuthConfig{CurrentToken: interactionToken})
	createBody := readFixture(t, "create-web-digest.json")
	if response := performRequest(handler, http.MethodPost, "/internal/v1/instances", createBody, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}
	created := performRequest(handler, http.MethodPost, "/internal/v1/instances", createBody, interactionToken)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	createOperationID := jsonString(t, created.Body.Bytes(), "operation_id")
	waitForHTTPStatus(t, handler, createOperationID, "SUCCEEDED")
	status := performRequest(handler, http.MethodGet, "/internal/v1/instances/11111111-1111-4111-8111-111111111111/runtime-status", nil, interactionToken)
	if status.Code != http.StatusOK {
		t.Fatalf("runtime status=%d body=%s", status.Code, status.Body.String())
	}
	deleteBody := readFixture(t, "delete-ttl.json")
	deleted := performRequest(handler, http.MethodDelete, "/internal/v1/instances/11111111-1111-4111-8111-111111111111", deleteBody, interactionToken)
	if deleted.Code != http.StatusAccepted {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	deleteOperationID := jsonString(t, deleted.Body.Bytes(), "operation_id")
	waitForHTTPStatus(t, handler, deleteOperationID, "SUCCEEDED")
	terminated := performRequest(handler, http.MethodGet, "/internal/v1/instances/11111111-1111-4111-8111-111111111111/runtime-status", nil, interactionToken)
	if terminated.Code != http.StatusOK || jsonString(t, terminated.Body.Bytes(), "phase") != "TERMINATED" {
		t.Fatalf("terminated=%d body=%s", terminated.Code, terminated.Body.String())
	}
	replayed := performRequest(handler, http.MethodDelete, "/internal/v1/instances/11111111-1111-4111-8111-111111111111", deleteBody, interactionToken)
	if replayed.Code != http.StatusAccepted || jsonString(t, replayed.Body.Bytes(), "operation_id") != deleteOperationID {
		t.Fatalf("replay=%d body=%s", replayed.Code, replayed.Body.String())
	}
}

type interactionCreate struct {
	result provisioner.CreateWorkloadResult
}

func (adapter *interactionCreate) CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	return adapter.result, nil
}

type interactionStatus struct{}

func (*interactionStatus) Get(_ context.Context, binding runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	return k3s.RuntimeStatus{InstanceID: binding.InstanceID, TargetID: binding.TargetID, RuntimeWorkloadID: binding.RuntimeWorkloadID, Phase: "READY", ObservedAt: time.Now().UTC(), Containers: []k3s.ContainerRuntimeStatus{}}, nil
}

type interactionDelete struct{}

func (*interactionDelete) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	return nil
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("../../examples/requests/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func performRequest(handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
func jsonString(t *testing.T, body []byte, key string) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	result, _ := value[key].(string)
	return result
}
func waitForHTTPStatus(t *testing.T, handler http.Handler, operationID, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response := performRequest(handler, http.MethodGet, "/internal/v1/operations/"+operationID, nil, interactionToken)
		body, _ := io.ReadAll(response.Body)
		if response.Code == http.StatusOK && jsonString(t, body, "status") == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("operation %s did not reach %s", operationID, want)
}
