package workerload_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
)

const capacityToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" // synthetic, loopback-only
const capacityImage = "ghcr.io/msg-ctf/challenges/worker-load/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestWorkerCapacity150 exercises the real HTTP/service/PostgreSQL/leased-worker
// path. The execution adapter deliberately sleeps; it does NOT run Kubernetes.
// Every output explicitly labels that boundary. Never use an operational DB.
func TestWorkerCapacity150(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_LOAD_DATABASE_URL")
	if dsn == "" {
		t.Skip("opt-in: PROVISIONER_LOAD_DATABASE_URL is not set")
	}
	if err := safeLoadDatabase(dsn, os.Getenv("PROVISIONER_LOAD_ALLOW_TRUNCATE")); err != nil {
		t.Fatal(err)
	}
	workers := capacityIntegers(t, "PROVISIONER_LOAD_WORKERS", "10,20,30,50")
	repeats := capacityIntegers(t, "PROVISIONER_LOAD_REPEATS", "1")[0]
	delay, err := time.ParseDuration(capacityEnv("PROVISIONER_LOAD_EXECUTION", "1s"))
	if err != nil || delay < 0 {
		t.Fatal("invalid controlled execution duration")
	}
	retryEvery := 0
	if value := os.Getenv("PROVISIONER_LOAD_RETRY_EVERY"); value != "" {
		retryEvery, err = strconv.Atoi(value)
		if err != nil || retryEvery < 0 {
			t.Fatal("invalid retry interval")
		}
	}
	output := os.Getenv("PROVISIONER_LOAD_OUTPUT")
	if output == "" {
		t.Fatal("PROVISIONER_LOAD_OUTPUT must name a results directory")
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		t.Fatal(err)
	}
	for _, count := range workers {
		for repeat := 1; repeat <= repeats; repeat++ {
			t.Run(fmt.Sprintf("workers-%d-repeat-%d", count, repeat), func(t *testing.T) {
				result := runCapacityCase(t, dsn, count, delay, retryEvery)
				filename := fmt.Sprintf("workers-%03d-%s-repeat-%d-retry-%d.json", count, delay, repeat, retryEvery)
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, filename), append(data, '\n'), 0644); err != nil {
					t.Fatal(err)
				}
				t.Logf("workers=%d controlled_execution=%s accepted=%d succeeded=%d failed=%d accept_p95=%.1fms completion_p95=%.3fs drain=%.3fs peak=%d attempts=%d polls=%d", count, delay, result.Accepted, result.Succeeded, result.Failed, result.Acceptance.P95, result.Completion.P95/1000, result.DrainMS/1000, result.PeakActive, result.Attempts, result.StatusPolls)
				if result.Accepted != 150 || result.Succeeded != 150 || result.Failed != 0 || result.Bindings != 150 || result.PollFailures != 0 {
					t.Fatalf("incomplete or invalid run; inspect %s", filename)
				}
				if result.PeakActive > count || result.PeakActive <= 0 {
					t.Fatalf("invalid measured concurrency: %d", result.PeakActive)
				}
				expectedAttempts := 150
				if retryEvery > 0 {
					expectedAttempts += 150 / retryEvery
				}
				if result.Attempts != expectedAttempts {
					t.Fatalf("expected %d attempts, got %d", expectedAttempts, result.Attempts)
				}
				for i, sample := range result.Samples {
					expected := 1
					if retryEvery > 0 && (i+1)%retryEvery == 0 {
						expected = 2
					}
					if sample.Attempts != expected {
						t.Fatalf("request %s expected %d attempts, got %d", sample.RequestID, expected, sample.Attempts)
					}
				}
			})
		}
	}
}

type capacitySample struct {
	RequestID              string    `json:"request_id"`
	Submitted              time.Time `json:"submitted_at"`
	AcceptanceMS           float64   `json:"acceptance_ms"`
	QueueMS                float64   `json:"queue_ms"`
	FirstClaimToTerminalMS float64   `json:"first_claim_to_terminal_ms"`
	CompletionMS           float64   `json:"completion_ms"`
	Status                 string    `json:"status"`
	Attempts               int       `json:"attempts"`
	ErrorCode              string    `json:"error_code,omitempty"`
}

type capacityPercentiles struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	Max float64 `json:"max_ms"`
}

type capacityResult struct {
	Scope                  string              `json:"scope"`
	Started                time.Time           `json:"started_at"`
	GoVersion              string              `json:"go_version"`
	OS                     string              `json:"os"`
	CPU                    int                 `json:"logical_cpus"`
	GOMAXPROCS             int                 `json:"gomaxprocs"`
	Postgres               string              `json:"postgres_version"`
	Workers                int                 `json:"workers"`
	ControlledExecution    string              `json:"controlled_execution"`
	RetryEvery             int                 `json:"first_attempt_retry_every"`
	Accepted               int                 `json:"accepted"`
	Succeeded              int                 `json:"succeeded"`
	Failed                 int                 `json:"failed"`
	Bindings               int                 `json:"bindings"`
	Attempts               int                 `json:"attempts"`
	PeakActive             int                 `json:"peak_active_adapter_calls"`
	StatusPolls            int64               `json:"http_operation_polls"`
	PollFailures           int64               `json:"http_poll_failures"`
	Acceptance             capacityPercentiles `json:"acceptance"`
	Queue                  capacityPercentiles `json:"queue"`
	FirstClaimToTerminal   capacityPercentiles `json:"first_claim_to_terminal"`
	Completion             capacityPercentiles `json:"completion"`
	DrainMS                float64             `json:"all_150_logical_terminal_ms"`
	PersistedDrainMS       float64             `json:"all_150_persisted_terminal_observed_ms"`
	LogicalClockInversions int                 `json:"logical_clock_inversions"`
	Samples                []capacitySample    `json:"samples"`
}

func runCapacityCase(t *testing.T, dsn string, concurrency int, delay time.Duration, retryEvery int) capacityResult {
	t.Helper()
	observer, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	observer.SetMaxOpenConns(3)
	var dbName string
	if err := observer.QueryRow("SELECT current_database()").Scan(&dbName); err != nil || dbName != "provisioner_load_150" {
		t.Fatal("refusing to reset unexpected database")
	}
	database, err := runtimepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := observer.Exec("TRUNCATE runtime_operations, runtime_bindings"); err != nil {
		t.Fatal(err)
	}

	adapter := &capacityAdapter{delay: delay, retryEvery: retryEvery, attempts: map[string]int{}}
	service, err := runtimeops.NewService(adapter, capacityStatus{}, capacityDelete{}, database.Bindings(), database.Operations(), isolation.NewStaticResolver(), runtimeops.Config{
		MaxAttempts: 4, DeleteCoordinator: database.DeleteCoordinator(),
		Worker: operations.WorkerConfig{Concurrency: concurrency, WorkerID: "capacity", PollInterval: 200 * time.Millisecond, LeaseDuration: 3 * time.Minute, RenewInterval: time.Minute, Backoff: func(attempt int) time.Duration { return time.Second * time.Duration(1<<(attempt-1)) }},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := httpapi.ParseImagePolicies([]byte(fmt.Sprintf(`{"schema_version":1,"managed_repositories":["ghcr.io/msg-ctf/challenges/worker-load/web"],"images":[{"image":%q,"container":"web","isolation_profile":"WEB","status":"create_enabled","run_as_user":10001,"ports":[8080],"exposed_ports":[8080],"writable_paths":[{"path":"/tmp","size_mib":32}]}]}`, capacityImage)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.NewHandlerWithRuntimePolicies(service, service, httpapi.ServiceAuthConfig{CurrentToken: capacityToken}, policy))
	defer server.Close()
	transport := &http.Transport{MaxIdleConns: 300, MaxIdleConnsPerHost: 300}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	var workerError error
	go func() { defer close(exited); workerError = service.Run(ctx) }()
	defer func() {
		cancel()
		<-exited
		if workerError != nil {
			t.Errorf("worker stopped: %v", workerError)
		}
	}()
	pollCtx, stopPolling := context.WithCancel(context.Background())
	defer stopPolling()
	var polls, pollFailures atomic.Int64
	var clients, pollers sync.WaitGroup
	samples := make([]capacitySample, 150)
	accepted := make([]bool, 150)
	start := make(chan struct{})
	for index := range 150 {
		clients.Add(1)
		go func(i int) {
			defer clients.Done()
			instance := fmt.Sprintf("20000000-0000-4000-8000-%012d", i+1)
			requestID := fmt.Sprintf("capacity-%03d", i)
			body := []byte(fmt.Sprintf(`{"request_id":%q,"instance_id":%q,"team_id":%q,"isolation_profile":"WEB","target":{"runtime_type":"KUBERNETES","target_id":"load-target"},"workload":{"containers":[{"name":"web","image":%q,"ports":[8080],"expose":true,"run_as_user":10001}],"resource_limits":{"cpu_millicores":100,"memory_mib":128,"ephemeral_storage_mib":128}}}`, requestID, instance, instance, capacityImage))
			<-start
			submitted := time.Now()
			samples[i] = capacitySample{RequestID: requestID, Submitted: submitted.UTC()}
			request, err := http.NewRequest(http.MethodPost, server.URL+"/internal/v1/instances", bytes.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+capacityToken)
			response, err := client.Do(request)
			if err != nil {
				t.Errorf("admission error: %v", err)
				return
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			samples[i].AcceptanceMS = milliseconds(time.Since(submitted))
			if err != nil || response.StatusCode != http.StatusAccepted {
				t.Errorf("admission status=%d body=%s err=%v", response.StatusCode, data, err)
				return
			}
			var result struct {
				OperationID string `json:"operation_id"`
			}
			if err := json.Unmarshal(data, &result); err != nil || result.OperationID == "" {
				t.Errorf("invalid acceptance response")
				return
			}
			accepted[i] = true
			pollers.Add(1)
			go func() {
				defer pollers.Done()
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-pollCtx.Done():
						return
					case <-ticker.C:
						poll, _ := http.NewRequestWithContext(pollCtx, http.MethodGet, server.URL+"/internal/v1/operations/"+result.OperationID, nil)
						poll.Header.Set("Authorization", "Bearer "+capacityToken)
						answer, err := client.Do(poll)
						if err != nil {
							if pollCtx.Err() == nil {
								pollFailures.Add(1)
							}
							continue
						}
						polls.Add(1)
						var state struct {
							Status string `json:"status"`
						}
						decodeErr := json.NewDecoder(answer.Body).Decode(&state)
						answer.Body.Close()
						if answer.StatusCode != 200 || (decodeErr != nil && pollCtx.Err() == nil) {
							pollFailures.Add(1)
						}
						if state.Status == "SUCCEEDED" || state.Status == "FAILED" {
							return
						}
					}
				}
			}()
		}(index)
	}
	started := time.Now()
	close(start)
	clients.Wait()
	defer func() { stopPolling(); pollers.Wait() }()
	for _, ok := range accepted {
		if !ok {
			t.Fatal("not all 150 requests accepted")
		}
	}
	deadline := time.Now().Add(2*time.Duration((150+concurrency-1)/concurrency)*(delay+time.Second) + 30*time.Second)
	for {
		var complete int
		if err := observer.QueryRow("SELECT count(*) FROM runtime_operations WHERE status IN ('SUCCEEDED','FAILED')").Scan(&complete); err != nil {
			t.Fatal(err)
		}
		if complete == 150 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("completion deadline exceeded: %d/150 terminal", complete)
		}
		select {
		case <-exited:
			t.Fatalf("worker exited before drain: %v", workerError)
		case <-time.After(100 * time.Millisecond):
		}
	}
	persistedDrain := time.Since(started)
	stopPolling()
	pollers.Wait()
	result := capacityResult{Scope: "real HTTP + approved policy + PostgreSQL + leased worker; CONTROLLED EXECUTION ADAPTER, NO KUBERNETES", Started: started.UTC(), GoVersion: runtime.Version(), OS: runtime.GOOS + "/" + runtime.GOARCH, CPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Workers: concurrency, ControlledExecution: delay.String(), RetryEvery: retryEvery, Accepted: 150, PeakActive: int(adapter.peak.Load()), StatusPolls: polls.Load(), PollFailures: pollFailures.Load()}
	result.PersistedDrainMS = milliseconds(persistedDrain)
	if err := observer.QueryRow("SELECT version()").Scan(&result.Postgres); err != nil {
		t.Fatal(err)
	}
	if err := observer.QueryRow("SELECT count(*) FROM runtime_bindings WHERE state='CREATED'").Scan(&result.Bindings); err != nil {
		t.Fatal(err)
	}
	rows, err := observer.Query("SELECT request_id,status,attempt,last_error_code,created_at,started_at,finished_at FROM runtime_operations ORDER BY request_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var acceptTimes, queueTimes, claimToTerminalTimes, completionTimes []float64
	byRequest := make(map[string]*capacitySample, len(samples))
	for i := range samples {
		byRequest[samples[i].RequestID] = &samples[i]
	}
	for rows.Next() {
		var id, state, code string
		var attempts int
		var created, began, finished time.Time
		if err := rows.Scan(&id, &state, &attempts, &code, &created, &began, &finished); err != nil {
			t.Fatal(err)
		}
		sample, ok := byRequest[id]
		if !ok {
			t.Fatal("unexpected operation in isolated run")
		}
		sample.Status, sample.Attempts, sample.ErrorCode = state, attempts, code
		sample.QueueMS = milliseconds(began.Sub(created))
		sample.FirstClaimToTerminalMS = milliseconds(finished.Sub(began))
		sample.CompletionMS = milliseconds(finished.Sub(sample.Submitted))
		if sample.QueueMS < 0 || sample.FirstClaimToTerminalMS < 0 || sample.CompletionMS < 0 {
			result.LogicalClockInversions++
		}
		acceptTimes = append(acceptTimes, sample.AcceptanceMS)
		queueTimes = append(queueTimes, sample.QueueMS)
		claimToTerminalTimes = append(claimToTerminalTimes, sample.FirstClaimToTerminalMS)
		completionTimes = append(completionTimes, sample.CompletionMS)
		result.Attempts += attempts
		if state == "SUCCEEDED" {
			result.Succeeded++
		} else {
			result.Failed++
		}
		result.DrainMS = math.Max(result.DrainMS, milliseconds(finished.Sub(started)))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	result.Acceptance, result.Queue, result.FirstClaimToTerminal, result.Completion = percentiles(acceptTimes), percentiles(queueTimes), percentiles(claimToTerminalTimes), percentiles(completionTimes)
	result.Samples = samples
	return result
}

type capacityAdapter struct {
	delay      time.Duration
	retryEvery int
	active     atomic.Int64
	peak       atomic.Int64
	mu         sync.Mutex
	attempts   map[string]int
}

func (a *capacityAdapter) CreateWorkload(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	active := a.active.Add(1)
	defer a.active.Add(-1)
	for peak := a.peak.Load(); active > peak && !a.peak.CompareAndSwap(peak, active); peak = a.peak.Load() {
	}
	a.mu.Lock()
	a.attempts[command.InstanceID]++
	attempt := a.attempts[command.InstanceID]
	a.mu.Unlock()
	timer := time.NewTimer(a.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return provisioner.CreateWorkloadResult{}, ctx.Err()
	case <-timer.C:
	}
	index, _ := strconv.Atoi(command.InstanceID[len(command.InstanceID)-12:])
	if a.retryEvery > 0 && index%a.retryEvery == 0 && attempt == 1 {
		return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("CONTROLLED_TRANSIENT", true, nil)
	}
	return provisioner.CreateWorkloadResult{RuntimeWorkloadID: "load-target/ctf-" + command.InstanceID, NamespaceUID: "ns-" + command.InstanceID, ServiceURL: "http://127.0.0.1:30080", Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://127.0.0.1:30080"}}}, nil
}

type capacityStatus struct{}

func (capacityStatus) Get(_ context.Context, b runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	return k3s.RuntimeStatus{InstanceID: b.InstanceID, TargetID: b.TargetID, Phase: "READY", ObservedAt: time.Now().UTC()}, nil
}

type capacityDelete struct{}

func (capacityDelete) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	return nil
}

func safeLoadDatabase(dsn, allow string) error {
	u, err := url.Parse(dsn)
	if err != nil || allow != "1" || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Path != "/provisioner_load_150" || u.RawQuery != "sslmode=disable" {
		return fmt.Errorf("refusing load/reset: require explicit opt-in and loopback provisioner_load_150 database")
	}
	return nil
}

func TestCapacityDatabaseSafetyGuard(t *testing.T) {
	valid := "postgres://workerload@127.0.0.1:55439/provisioner_load_150?sslmode=disable"
	if err := safeLoadDatabase(valid, "1"); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{strings.Replace(valid, "127.0.0.1", "production.example", 1), strings.Replace(valid, "provisioner_load_150", "provisioner", 1), "", valid + "&search_path=public"} {
		if safeLoadDatabase(dsn, "1") == nil {
			t.Fatal("unsafe database accepted")
		}
	}
	if safeLoadDatabase(valid, "") == nil {
		t.Fatal("missing reset opt-in accepted")
	}
}

func TestCapacityPercentileNearestRank(t *testing.T) {
	result := percentiles([]float64{40, 10, 30, 20})
	if result.P50 != 20 || result.P95 != 40 || result.Max != 40 {
		t.Fatalf("wrong nearest-rank percentiles: %+v", result)
	}
}

func percentiles(values []float64) capacityPercentiles {
	if len(values) == 0 {
		return capacityPercentiles{}
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	return capacityPercentiles{P50: copyValues[int(math.Ceil(float64(len(values))*0.5))-1], P95: copyValues[int(math.Ceil(float64(len(values))*0.95))-1], Max: copyValues[len(copyValues)-1]}
}
func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func capacityEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func capacityIntegers(t *testing.T, key, fallback string) []int {
	t.Helper()
	var result []int
	for _, raw := range strings.Split(capacityEnv(key, fallback), ",") {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 150 {
			t.Fatalf("invalid bounded setting %s", key)
		}
		result = append(result, value)
	}
	return result
}
