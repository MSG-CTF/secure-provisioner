//go:build linux

package imageprep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func trustedFileFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes.json")
	data := fmt.Sprintf(`{"nodes":[{"target_id":"target-a","node_name":"node-a","node_uid":"uid-a","mode":"kubernetes","namespace":"image-preparation","agent_image":%q}]}`, testImage)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileTransportRejectsSymlinksAndNonregularFiles(t *testing.T) {
	path := trustedFileFixture(t)
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(link, nil); err == nil {
		t.Fatal("symlink configuration accepted")
	}
	directoryLink := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(filepath.Dir(path), directoryLink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(filepath.Join(directoryLink, "nodes.json"), nil); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if _, err := NewFileTransport(filepath.Dir(path), nil); err == nil {
		t.Fatal("directory configuration accepted")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(fifo, nil); err == nil {
		t.Fatal("FIFO configuration accepted")
	}
}

func TestFileTransportRejectsWritableConfigAndDirectoryOnReload(t *testing.T) {
	for _, permission := range []os.FileMode{0620, 0602, 0660, 0666} {
		t.Run(fmt.Sprintf("mode-%o", permission), func(t *testing.T) {
			path := trustedFileFixture(t)
			calls := 0
			runner, err := NewFileTransport(path, func(context.Context, AgentTarget, Node, AgentRequest) (Evidence, error) {
				calls++
				return Evidence{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, permission); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileTransport(path, nil); err == nil {
				t.Fatal("writable configuration accepted at startup")
			}
			_, err = runner.Run(context.Background(), Node{TargetID: "target-a", Name: "node-a", UID: "uid-a"}, testImage, false)
			if err == nil || calls != 0 {
				t.Fatal("unsafe reload invoked the agent")
			}
		})
	}
	path := trustedFileFixture(t)
	if err := os.Chmod(filepath.Dir(path), 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(path, nil); err == nil {
		t.Fatal("writable ancestor directory accepted")
	}
}

func TestFileTransportRejectsUntrustedOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual foreign-owner fixture requires root; run Linux verification as root")
	}
	path := trustedFileFixture(t)
	runner, err := NewFileTransport(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(path, nil); err == nil {
		t.Fatal("foreign-owned configuration accepted")
	}
	if _, err := runner.Run(context.Background(), Node{}, testImage, false); err == nil {
		t.Fatal("foreign-owned reload accepted")
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Dir(path), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTransport(path, nil); err == nil {
		t.Fatal("foreign-owned ancestor directory accepted")
	}
}
