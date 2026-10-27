package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const preparationImage = "ghcr.io/msg-ctf/challenges/web-grade-tampering/web@sha256:9ffbf4761b09e0d182e444bb8793343cdc9633b72692aa516b777cf9c750956d"

type preparationInventory struct{}

func (preparationInventory) Known(target string) bool { return target == "target-a" }
func (preparationInventory) Enabled(target, arch string) bool {
	return target == "target-a" && arch == "AMD64"
}
func (preparationInventory) Nodes(context.Context, string, string) ([]imageprep.Node, error) {
	return []imageprep.Node{{TargetID: "target-a", UID: "node-uid-a", Name: "node-a", BootID: "boot-a", MachineID: "machine-a", Architecture: "AMD64"}, {TargetID: "target-a", UID: "node-uid-b", Name: "node-b", BootID: "boot-b", MachineID: "machine-b", Architecture: "AMD64"}}, nil
}

type preparationRunner struct{ failNode string }

func (r *preparationRunner) Run(_ context.Context, n imageprep.Node, image string, pull bool) (imageprep.Evidence, error) {
	if n.UID == r.failNode {
		return imageprep.Evidence{}, imageprep.Failure{Code: "REGISTRY_UNAUTHORIZED"}
	}
	return imageprep.Evidence{NodeUID: n.UID, BootID: n.BootID, MachineID: n.MachineID, OS: "linux", Architecture: n.Architecture, Image: image, ResolvedDigest: "sha256:9ffbf4761b09e0d182e444bb8793343cdc9633b72692aa516b777cf9c750956d", Complete: true}, nil
}
func TestImagePreparationHTTPPostgresWireAndPartialRetry(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := runtimepg.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec("TRUNCATE image_preparation_operations,image_preparation_observations,image_preparation_node_locks"); err != nil {
		t.Fatal(err)
	}
	policy, err := httpapi.LoadImagePolicies("../../config/web-image-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	runner := &preparationRunner{}
	svc := imageprep.NewService(db.ImagePreparations(), preparationInventory{}, policy, runner, imageprep.Config{TTL: time.Minute, ObserveInterval: 30 * time.Second, MaxAttempts: 3, Concurrency: 2})
	server := httptest.NewServer(httpapi.WithImagePreparations(http.NotFoundHandler(), svc, httpapi.PreparationAuth{Enabled: true, ManagerToken: "test-manager", ReadinessToken: "test-reader"}))
	defer server.Close()
	call := func(method, path string, body any, status int) []byte {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		request, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(data))
		request.Header.Set("Authorization", "Bearer test-manager")
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(response.Body)
		if response.StatusCode != status {
			t.Fatalf("%s %s status=%d body=%s", method, path, response.StatusCode, b)
		}
		return b
	}
	drain := func() {
		t.Helper()
		for range 20 {
			worked, err := svc.Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !worked {
				return
			}
		}
		t.Fatal("worker did not settle")
	}
	request := imageprep.Request{RequestID: uuid.NewString(), ReleaseID: uuid.NewString(), Architecture: "AMD64", IsolationProfile: "WEB", Containers: []imageprep.Container{{Name: "web", Image: preparationImage, Ports: []int{8080}}}, TargetIDs: []string{"target-a"}}
	accepted := call("POST", "/v1/image-preparations", request, 202)
	var acceptedOp imageprep.Operation
	_ = json.Unmarshal(accepted, &acceptedOp)
	drain()
	detail := call("GET", "/v1/image-preparations/"+acceptedOp.ID, nil, 200)
	var op imageprep.Operation
	_ = json.Unmarshal(detail, &op)
	if op.Status != "SUCCEEDED" || len(op.Nodes) != 2 {
		t.Fatalf("detail=%s", detail)
	}
	if err := svc.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	readiness := call("POST", "/v1/image-readiness/query", imageprep.Query{Architecture: "AMD64", Images: []string{preparationImage}, TargetIDs: request.TargetIDs}, 200)
	var hints imageprep.Readiness
	_ = json.Unmarshal(readiness, &hints)
	if !hints.Targets[0].Ready || hints.Targets[0].ReadyNodeCount != 2 {
		t.Fatalf("readiness=%s", readiness)
	}
	if dir := os.Getenv("PROVISIONER_TEST_WIRE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		requestJSON, _ := json.Marshal(request)
		for name, b := range map[string][]byte{"request.json": requestJSON, "accepted.json": accepted, "detail.json": detail, "readiness.json": readiness} {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	runner.failNode = "node-uid-b"
	request.RequestID = uuid.NewString()
	accepted = call("POST", "/v1/image-preparations", request, 202)
	_ = json.Unmarshal(accepted, &acceptedOp)
	drain()
	detail = call("GET", "/v1/image-preparations/"+acceptedOp.ID, nil, 200)
	_ = json.Unmarshal(detail, &op)
	if op.Status != "PARTIAL" {
		t.Fatalf("partial=%s", detail)
	}
	retry := imageprep.Retry{RequestID: uuid.NewString(), NodeUIDs: []string{"node-uid-b"}}
	child := call("POST", "/v1/image-preparations/"+op.ID+"/retry", retry, 202)
	var childOp imageprep.Operation
	_ = json.Unmarshal(child, &childOp)
	runner.failNode = ""
	drain()
	detail = call("GET", "/v1/image-preparations/"+childOp.ID, nil, 200)
	_ = json.Unmarshal(detail, &childOp)
	if childOp.Status != "SUCCEEDED" || childOp.ParentID != op.ID || len(childOp.Nodes) != 1 {
		t.Fatalf("retry=%s", detail)
	}
	call("POST", "/v1/image-preparations/"+op.ID+"/retry", retry, 202)
	// A new service and store observe the same committed history, not process memory.
	restarted, err := runtimepg.OpenExisting(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	record, err := restarted.ImagePreparations().Get(ctx, childOp.ID)
	if err != nil || record.Operation.Status != "SUCCEEDED" {
		t.Fatal("restart lost history")
	}
}
