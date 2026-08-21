package workerload_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/MSG-CTF/secure-provisioner/internal/ctfmock"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestAccepts500ConcurrentRequests(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	db, service, handler := newLoadTestEnvironment(t, dsn)
	defer db.Close()
	defer service.Close()

	const requestCount = 500
	start := make(chan struct{})
	errorsChannel := make(chan error, requestCount)
	var waitGroup sync.WaitGroup
	for index := 1; index <= requestCount; index++ {
		waitGroup.Add(1)
		go func(requestNumber int) {
			defer waitGroup.Done()
			<-start
			payload := map[string]any{
				"request_id": fmt.Sprintf("load-request-%d", requestNumber), "instance_id": fmt.Sprintf("load-instance-%d", requestNumber),
				"team_id": requestNumber, "challenge_id": fmt.Sprintf("load-challenge-%d", requestNumber),
				"cluster_id": "cluster-1", "reservation_id": fmt.Sprintf("load-reservation-%d", requestNumber),
				"created_by": "load-test", "expires_at": time.Now().UTC().Add(time.Hour),
			}
			body, err := json.Marshal(payload)
			if err != nil {
				errorsChannel <- err
				return
			}
			request := httptest.NewRequest("POST", "/internal/v1/instances", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 202 {
				errorsChannel <- fmt.Errorf("request %d returned HTTP %d: %s", requestNumber, response.Code, response.Body.String())
			}
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}

	var operations int
	if err := db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != requestCount {
		t.Fatalf("operation rows = %d, want %d", operations, requestCount)
	}
}

func TestDuplicateRequestCreatesOneOperation(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	db, service, handler := newLoadTestEnvironment(t, dsn)
	defer db.Close()
	defer service.Close()
	payload, err := json.Marshal(map[string]any{
		"request_id": "duplicate-request", "instance_id": "duplicate-instance", "team_id": 101,
		"challenge_id": "duplicate-challenge", "cluster_id": "cluster-1", "reservation_id": "duplicate-reservation",
		"created_by": "load-test", "expires_at": time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	const requestCount = 100
	errorsChannel := make(chan error, requestCount)
	var waitGroup sync.WaitGroup
	for index := 0; index < requestCount; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request := httptest.NewRequest("POST", "/internal/v1/instances", bytes.NewReader(payload))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusAccepted {
				errorsChannel <- fmt.Errorf("duplicate request returned HTTP %d: %s", response.Code, response.Body.String())
			}
		}()
	}
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	var operations int
	if err := db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 1 {
		t.Fatalf("operation rows = %d, want 1", operations)
	}
}

func TestPendingOperationResumesAfterServiceRestart(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	dependencyServer := httptest.NewServer(ctfmock.NewHandler(""))
	defer dependencyServer.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := provisioner.NewPostgresService(context.Background(), dependencyServer.URL, logger, time.Hour, dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("TRUNCATE operations, instances"); err != nil {
		t.Fatal(err)
	}
	request := provisioner.CreateRequest{
		RequestID: "restart-request", InstanceID: "restart-instance", TeamID: 101, ChallengeID: "web-101",
		ClusterID: "k3s-local", ReservationID: "rsv-local", CreatedBy: "load-test", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if _, err := first.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := provisioner.NewPostgresService(context.Background(), dependencyServer.URL, logger, time.Hour, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	second.StartWithOptions(ctx, provisioner.WorkerOptions{
		Concurrency: 2, PollInterval: time.Millisecond, LeaseDuration: time.Second,
		MaximumRetries: 3, RetryBaseDelay: time.Millisecond,
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		instance, err := second.GetInstance(request.InstanceID)
		if err == nil && instance.Phase == provisioner.PhaseReady {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending operation did not resume after service restart")
}

func newLoadTestEnvironment(t *testing.T, dsn string) (*sql.DB, *provisioner.Service, http.Handler) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := provisioner.NewPostgresService(context.Background(), "http://127.0.0.1:1", logger, time.Hour, dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = service.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), "TRUNCATE operations, instances"); err != nil {
		_ = service.Close()
		_ = db.Close()
		t.Fatal(err)
	}
	return db, service, provisioner.NewHandler(service)
}
