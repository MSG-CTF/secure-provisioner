package imageprep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

type fixtureCommands struct {
	blobs   map[string][]byte
	image   string
	config  string
	cached  bool
	pulls   int
	corrupt bool
}

func (f *fixtureCommands) Run(_ context.Context, output io.Writer, args ...string) error {
	if args[0] == "crictl" {
		switch args[len(args)-2] {
		case "inspecti":
			if !f.cached {
				return Failure{Code: "CONTENT_INCOMPLETE"}
			}
			fmt.Fprintf(output, `{"status":{"id":%q,"repoDigests":[%q]}}`, f.config, f.image)
			return nil
		case "pull":
			f.pulls++
			f.cached = true
			return nil
		}
	}
	digest := args[len(args)-1]
	b, ok := f.blobs[digest]
	if !ok {
		return Failure{Code: "CONTENT_INCOMPLETE"}
	}
	if f.corrupt {
		b = []byte("corrupt")
	}
	_, err := output.Write(b)
	return err
}
func (f *fixtureCommands) add(v any) string {
	var b []byte
	if raw, ok := v.([]byte); ok {
		b = raw
	} else {
		b, _ = json.Marshal(v)
	}
	sum := sha256.Sum256(b)
	d := fmt.Sprintf("sha256:%x", sum)
	f.blobs[d] = b
	return d
}
func agentFixture() (*Agent, *fixtureCommands, string) {
	f := &fixtureCommands{blobs: map[string][]byte{}}
	layer := f.add([]byte("layer content"))
	config := f.add(map[string]any{"os": "linux", "architecture": "amd64"})
	f.config = config
	manifest := f.add(map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": config, "size": len(f.blobs[config])}, "layers": []any{map[string]any{"digest": layer, "size": len(f.blobs[layer])}}})
	index := f.add(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"digest": manifest, "size": len(f.blobs[manifest]), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}})
	f.image = "ghcr.io/msg-ctf/challenges/example/web@" + index
	return &Agent{Commands: f, Identity: func() (AgentIdentity, error) {
		return AgentIdentity{NodeUID: "uid", MachineID: "machine", BootID: "boot", OS: "linux", Architecture: "AMD64"}, nil
	}}, f, manifest
}
func TestAgentPullThenFullIndexContentAndCacheHit(t *testing.T) {
	a, f, manifest := agentFixture()
	e, err := a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64", Pull: true})
	if err != nil || !e.Complete || e.ResolvedDigest != manifest || f.pulls != 1 {
		t.Fatalf("prepare=%+v %v pulls=%d", e, err, f.pulls)
	}
	_, err = a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64", Pull: true})
	if err != nil || f.pulls != 1 {
		t.Fatalf("cache hit pulled: %v %d", err, f.pulls)
	}
	f.corrupt = true
	if _, err = a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64"}); err == nil {
		t.Fatal("corrupt content declared ready")
	}
}
func TestAgentMissingLayerWrongExactReferenceAndUnsupportedPlatform(t *testing.T) {
	a, f, _ := agentFixture()
	f.cached = true
	for digest, b := range f.blobs {
		if bytes.Equal(b, []byte("layer content")) {
			delete(f.blobs, digest)
		}
	}
	if _, err := a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64"}); err == nil {
		t.Fatal("missing layer accepted")
	}
	if _, err := a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "ARM64", Pull: true}); ErrorCode(err) != "PLATFORM_MISMATCH" {
		t.Fatalf("platform=%v", err)
	}
	if f.pulls != 0 {
		t.Fatal("platform mismatch pulled")
	}
	if _, err := a.Prepare(context.Background(), AgentRequest{Image: strings.Replace(f.image, "/web@", "/other@", 1), Architecture: "AMD64"}); err == nil {
		t.Fatal("wrong repository accepted")
	}
}

func TestAgentKnownManifestPlatformFailureNeverPulls(t *testing.T) {
	a, f, _ := agentFixture()
	f.cached = true
	config := f.add(map[string]any{"os": "linux", "architecture": "arm64"})
	f.config = config
	manifest := f.add(map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": config, "size": len(f.blobs[config])}, "layers": []any{}})
	f.image = "ghcr.io/msg-ctf/challenges/example/web@" + manifest
	_, err := a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64", Pull: true})
	if ErrorCode(err) != "PLATFORM_MISMATCH" || f.pulls != 0 {
		t.Fatalf("permanent platform mismatch pulled: %v calls=%d", err, f.pulls)
	}
}

func TestAgentRejectsCRIRecordForDifferentConfig(t *testing.T) {
	a, f, _ := agentFixture()
	f.cached = true
	f.config = "sha256:" + strings.Repeat("f", 64)
	if _, err := a.Prepare(context.Background(), AgentRequest{Image: f.image, Architecture: "AMD64"}); err == nil {
		t.Fatal("CRI record bound to different config accepted")
	}
}
