package imageprep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFileTransportReloadsTrustedNodeUIDWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	write := func(uid string) {
		t.Helper()
		data := fmt.Sprintf(`{"nodes":[{"target_id":"target-a","node_name":"node-a","node_uid":%q,"mode":"kubernetes","namespace":"image-preparation","agent_image":%q}]}`, uid, testImage)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("uid-a")
	calls := 0
	runner, err := NewFileTransport(path, func(_ context.Context, target AgentTarget, node Node, req AgentRequest) (Evidence, error) {
		calls++
		return Evidence{NodeUID: target.NodeUID, MachineID: node.MachineID, BootID: node.BootID, OS: "linux", Architecture: req.Architecture, Image: req.Image, ResolvedDigest: "sha256:" + testImage[len(testImage)-64:], Complete: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	node := Node{TargetID: "target-a", Name: "node-a", UID: "uid-a", MachineID: "machine-a", BootID: "boot-a", Architecture: "AMD64"}
	if _, err := runner.Run(context.Background(), node, testImage, false); err != nil {
		t.Fatal(err)
	}
	write("uid-b")
	if _, err := runner.Run(context.Background(), node, testImage, false); ErrorCode(err) != "AGENT_UNAVAILABLE" {
		t.Fatalf("old UID remained authorized: %v", err)
	}
	node.UID = "uid-b"
	if _, err := runner.Run(context.Background(), node, testImage, false); err != nil {
		t.Fatalf("replacement UID was not loaded: %v", err)
	}
	if calls != 2 {
		t.Fatalf("agent calls=%d, want 2", calls)
	}
}

func TestFileTransportFailsClosedForInvalidOrUnavailableReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	valid := fmt.Sprintf(`{"nodes":[{"target_id":"target-a","node_name":"node-a","node_uid":"uid-a","mode":"kubernetes","namespace":"image-preparation","agent_image":%q}]}`, testImage)
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	runner, err := NewFileTransport(path, func(context.Context, AgentTarget, Node, AgentRequest) (Evidence, error) {
		calls++
		return Evidence{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{"nodes":[]}`, valid + " garbage", `{"nodes":[{"mode":"kubernetes","command":"/bin/sh"}]}`} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := runner.Run(context.Background(), Node{TargetID: "target-a", Name: "node-a", UID: "uid-a"}, testImage, false)
		if ErrorCode(err) != "AGENT_UNAVAILABLE" {
			t.Fatalf("invalid reload accepted: %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), Node{}, testImage, false); ErrorCode(err) != "AGENT_UNAVAILABLE" {
		t.Fatalf("unavailable reload accepted: %v", err)
	}
	if calls != 0 {
		t.Fatalf("invalid file invoked agent %d times", calls)
	}
	if _, err := NewFileTransport(path, nil); err == nil {
		t.Fatal("missing startup configuration accepted")
	}
}

func TestTransportRefusesChangedEnrolledMachineWithUnchangedNodeUID(t *testing.T) {
	data := fmt.Sprintf(`{"nodes":[{"target_id":"target-a","node_name":"node-a","node_uid":"uid-a","machine_id":"machine-a","mode":"kubernetes","namespace":"image-preparation","agent_image":%q}]}`, testImage)
	runner, err := ParseAgentTargets([]byte(data))
	if err != nil {
		t.Fatalf("machine identity pin was rejected: %v", err)
	}
	calls := 0
	runner.Kubernetes = func(_ context.Context, _ AgentTarget, node Node, req AgentRequest) (Evidence, error) {
		calls++
		return Evidence{NodeUID: node.UID, MachineID: node.MachineID, BootID: node.BootID, OS: "linux", Architecture: req.Architecture, Image: req.Image, ResolvedDigest: "sha256:" + testImage[len(testImage)-64:], Complete: true}, nil
	}
	node := Node{TargetID: "target-a", Name: "node-a", UID: "uid-a", MachineID: "machine-replaced", BootID: "boot-a", Architecture: "AMD64"}
	if _, err := runner.Run(context.Background(), node, testImage, false); err == nil {
		t.Fatal("replacement machine reused the enrolled Kubernetes UID")
	}
	if calls != 0 {
		t.Fatal("agent executed on an unenrolled machine")
	}
	node.MachineID = "machine-a"
	if _, err := runner.Run(context.Background(), node, testImage, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("approved agent calls=%d", calls)
	}
}
