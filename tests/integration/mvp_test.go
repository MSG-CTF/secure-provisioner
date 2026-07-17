package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/ctfmock"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type testEnvironment struct {
	dependencyMock *httptest.Server
	provisioner    *httptest.Server
	brokerMock     *httptest.Server
	cancel         context.CancelFunc
}

func newTestEnvironment(t *testing.T, expirationInterval time.Duration) *testEnvironment {
	t.Helper()

	dependencyMock := httptest.NewServer(ctfmock.NewHandler(""))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := provisioner.NewService(dependencyMock.URL, logger, expirationInterval)
	ctx, cancel := context.WithCancel(context.Background())
	service.Start(ctx, 4)
	provisionerServer := httptest.NewServer(provisioner.NewHandler(service))
	brokerMock := httptest.NewServer(ctfmock.NewHandler(provisionerServer.URL))

	environment := &testEnvironment{
		dependencyMock: dependencyMock,
		provisioner:    provisionerServer,
		brokerMock:     brokerMock,
		cancel:         cancel,
	}
	t.Cleanup(func() {
		cancel()
		brokerMock.Close()
		provisionerServer.Close()
		dependencyMock.Close()
	})

	return environment
}

func TestConcurrentCreateUsesOneTeamChallengeInstance(t *testing.T) {
	environment := newTestEnvironment(t, 20*time.Millisecond)

	const requestCount = 8
	accepted := make(chan provisioner.AcceptedOperation, requestCount)
	errorsChannel := make(chan error, requestCount)
	var waitGroup sync.WaitGroup

	for index := 0; index < requestCount; index++ {
		waitGroup.Add(1)
		go func(requestNumber int) {
			defer waitGroup.Done()
			request := createRequest(
				fmt.Sprintf("req-concurrent-%d", requestNumber),
				fmt.Sprintf("inst-concurrent-%d", requestNumber),
				"team-a",
				"pwn-101",
				time.Now().UTC().Add(time.Hour),
			)

			var response provisioner.AcceptedOperation
			if err := doJSON(http.MethodPost, environment.brokerMock.URL+"/mock/v1/broker/instances", request, http.StatusAccepted, &response); err != nil {
				errorsChannel <- err
				return
			}
			accepted <- response
		}(index)
	}

	waitGroup.Wait()
	close(accepted)
	close(errorsChannel)

	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}

	instanceIDs := make(map[string]bool)
	for response := range accepted {
		instanceIDs[response.InstanceID] = true
	}
	if len(instanceIDs) != 1 {
		t.Fatalf("expected one instance for the same team and challenge, got %v", instanceIDs)
	}

	var instanceID string
	for candidate := range instanceIDs {
		instanceID = candidate
	}
	instance := waitForPhase(t, environment.brokerMock.URL, instanceID, provisioner.PhaseReady, 3*time.Second)
	if instance.Endpoint == "" {
		t.Fatal("expected a verified endpoint for a ready instance")
	}

	var resources provisioner.RuntimeResources
	if err := doJSON(http.MethodGet, environment.brokerMock.URL+"/mock/v1/broker/debug/resources/"+instanceID, nil, http.StatusOK, &resources); err != nil {
		t.Fatal(err)
	}
	assertIsolationBaseline(t, resources)

	webRequest := createRequest("req-web", "inst-web", "team-a", "web-101", time.Now().UTC().Add(time.Hour))
	var webAccepted provisioner.AcceptedOperation
	if err := doJSON(http.MethodPost, environment.brokerMock.URL+"/mock/v1/broker/instances", webRequest, http.StatusAccepted, &webAccepted); err != nil {
		t.Fatal(err)
	}
	if webAccepted.InstanceID == instanceID {
		t.Fatal("different challenges for the same team must have separate instances")
	}
	waitForPhase(t, environment.brokerMock.URL, webAccepted.InstanceID, provisioner.PhaseReady, 3*time.Second)

	deleteURL := environment.brokerMock.URL + "/mock/v1/broker/instances/" + instanceID
	var deleteAccepted provisioner.AcceptedOperation
	if err := doJSON(http.MethodDelete, deleteURL, provisioner.DeleteRequest{RequestID: "req-delete-1"}, http.StatusAccepted, &deleteAccepted); err != nil {
		t.Fatal(err)
	}
	waitForPhase(t, environment.brokerMock.URL, instanceID, provisioner.PhaseTerminated, 3*time.Second)

	var repeatedDelete provisioner.AcceptedOperation
	if err := doJSON(http.MethodDelete, deleteURL, provisioner.DeleteRequest{RequestID: "req-delete-2"}, http.StatusAccepted, &repeatedDelete); err != nil {
		t.Fatal(err)
	}
	if repeatedDelete.Phase != provisioner.PhaseTerminated || !repeatedDelete.Duplicate {
		t.Fatalf("expected idempotent terminated response, got %+v", repeatedDelete)
	}
}

func TestEndpointFailureRollsBackFakeRuntime(t *testing.T) {
	environment := newTestEnvironment(t, 20*time.Millisecond)

	scenario := ctfmock.Scenario{EndpointUnhealthy: true}
	if err := doJSON(http.MethodPut, environment.dependencyMock.URL+"/mock/v1/scenario", scenario, http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}

	request := createRequest("req-failure", "inst-failure", "team-b", "pwn-101", time.Now().UTC().Add(time.Hour))
	var accepted provisioner.AcceptedOperation
	if err := doJSON(http.MethodPost, environment.brokerMock.URL+"/mock/v1/broker/instances", request, http.StatusAccepted, &accepted); err != nil {
		t.Fatal(err)
	}

	failed := waitForPhase(t, environment.brokerMock.URL, accepted.InstanceID, provisioner.PhaseFailed, 3*time.Second)
	if failed.LastError == "" {
		t.Fatal("expected a non-sensitive failure reason")
	}

	response, err := http.Get(environment.brokerMock.URL + "/mock/v1/broker/debug/resources/" + accepted.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected fake runtime rollback, got HTTP %d", response.StatusCode)
	}
}

func TestTTLAutomaticallyTerminatesInstance(t *testing.T) {
	environment := newTestEnvironment(t, 10*time.Millisecond)

	request := createRequest("req-ttl", "inst-ttl", "team-c", "web-101", time.Now().UTC().Add(250*time.Millisecond))
	var accepted provisioner.AcceptedOperation
	if err := doJSON(http.MethodPost, environment.brokerMock.URL+"/mock/v1/broker/instances", request, http.StatusAccepted, &accepted); err != nil {
		t.Fatal(err)
	}

	waitForPhase(t, environment.brokerMock.URL, accepted.InstanceID, provisioner.PhaseReady, 2*time.Second)
	waitForPhase(t, environment.brokerMock.URL, accepted.InstanceID, provisioner.PhaseTerminated, 3*time.Second)
}

func createRequest(requestID string, instanceID string, teamID string, challengeID string, expiresAt time.Time) provisioner.CreateRequest {
	return provisioner.CreateRequest{
		RequestID:     requestID,
		InstanceID:    instanceID,
		TeamID:        teamID,
		ChallengeID:   challengeID,
		ClusterID:     "k3s-local",
		ReservationID: "rsv-local",
		CreatedBy:     "integration-test",
		ExpiresAt:     expiresAt,
	}
}

func waitForPhase(t *testing.T, baseURL string, instanceID string, expected provisioner.Phase, timeout time.Duration) provisioner.InstanceView {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var instance provisioner.InstanceView
		err := doJSON(http.MethodGet, baseURL+"/mock/v1/broker/instances/"+instanceID, nil, http.StatusOK, &instance)
		if err == nil && instance.Phase == expected {
			return instance
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("instance %s did not reach phase %s", instanceID, expected)
	return provisioner.InstanceView{}
}

func assertIsolationBaseline(t *testing.T, resources provisioner.RuntimeResources) {
	t.Helper()

	if !resources.ResourceQuotaApplied || !resources.LimitRangeApplied || !resources.DefaultDenyNetworkPolicy {
		t.Fatalf("expected quota, limits, and default deny policy: %+v", resources)
	}
	if resources.ServiceAccountAutomount || resources.AllowPrivilegeEscalation || resources.Privileged {
		t.Fatalf("expected restricted service account and privileges: %+v", resources)
	}
	if resources.HostNetwork || resources.HostPID || resources.HostIPC || resources.HostPathAllowed {
		t.Fatalf("expected host access to be denied: %+v", resources)
	}
	if !resources.DropAllCapabilities || resources.SeccompProfile != "RuntimeDefault" {
		t.Fatalf("expected capability drop and seccomp: %+v", resources)
	}
}

func doJSON(method string, endpoint string, payload any, expectedStatus int, destination any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("expected HTTP %d from %s, got %d: %s", expectedStatus, endpoint, response.StatusCode, string(responseBody))
	}
	if destination == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, destination); err != nil {
		return fmt.Errorf("decode response from %s: %w", endpoint, err)
	}
	return nil
}
