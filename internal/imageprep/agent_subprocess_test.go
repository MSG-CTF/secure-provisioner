package imageprep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if dir := os.Getenv("IMAGEPREP_HELPER_DIR"); dir != "" {
		runAgentFixtureProcess(dir)
		return
	}
	os.Exit(m.Run())
}
func runAgentFixtureProcess(dir string) {
	args := os.Args[1:]
	if len(args) < 2 {
		os.Exit(2)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "failure")); err == nil {
		fmt.Fprint(os.Stderr, string(b))
		os.Exit(1)
	}
	last := args[len(args)-1]
	if args[0] == "crictl" {
		switch args[len(args)-2] {
		case "inspecti":
			if _, err := os.Stat(filepath.Join(dir, "cached")); err != nil {
				os.Exit(1)
			}
			image, _ := os.ReadFile(filepath.Join(dir, "image"))
			config, _ := os.ReadFile(filepath.Join(dir, "config"))
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": map[string]any{"id": string(config), "repoDigests": []string{string(image)}}})
			os.Exit(0)
		case "pull":
			_ = os.WriteFile(filepath.Join(dir, "cached"), []byte("yes"), 0600)
			f, _ := os.OpenFile(filepath.Join(dir, "pulls"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if f != nil {
				_, _ = f.WriteString("pull\n")
				f.Close()
			}
			os.Exit(0)
		}
	}
	if args[0] == "ctr" {
		b, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(last, "sha256:")))
		if err != nil {
			fmt.Fprint(os.Stderr, "not found")
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(b)
		os.Exit(0)
	}
	os.Exit(2)
}
func TestAgentActualSubprocessExactCacheAndSanitizedErrors(t *testing.T) {
	a, fixture, _ := agentFixture()
	dir := t.TempDir()
	for digest, b := range fixture.blobs {
		if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "image"), []byte(fixture.image), 0600)
	_ = os.WriteFile(filepath.Join(dir, "config"), []byte(fixture.config), 0600)
	t.Setenv("IMAGEPREP_HELPER_DIR", dir)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.Commands = ExecCommands{Binary: executable}
	request := AgentRequest{Image: fixture.image, Architecture: "AMD64", Pull: true}
	if _, err := a.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	pulls, _ := os.ReadFile(filepath.Join(dir, "pulls"))
	if string(pulls) != "pull\n" {
		t.Fatalf("cache hit repeated pull: %s", pulls)
	}
	for digest, b := range fixture.blobs {
		if string(b) == "layer content" {
			_ = os.Remove(filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")))
		}
	}
	request.Pull = false
	if _, err := a.Prepare(context.Background(), request); err == nil {
		t.Fatal("missing subprocess content accepted")
	}
	pulls, _ = os.ReadFile(filepath.Join(dir, "pulls"))
	if string(pulls) != "pull\n" {
		t.Fatal("inspect-only repulled")
	}
	_ = os.WriteFile(filepath.Join(dir, "failure"), []byte("unauthorized: TOPSECRET-registry-token"), 0600)
	request.Pull = true
	_, err = a.Prepare(context.Background(), request)
	if ErrorCode(err) != "REGISTRY_UNAUTHORIZED" || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("unsanitized failure %v", err)
	}
}
