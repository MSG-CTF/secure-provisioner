//go:build linux

package k3s

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedFlagReaderChecksDescriptorOwnerAndParentPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, "flag-trust-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "flags.json")
	if err := os.WriteFile(path, []byte(testFlagJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	contents, err := readTrustedFlagFileWithOwner(path, owner)
	if err != nil || string(contents) != testFlagJSON {
		t.Fatalf("trusted file read failed: %v", err)
	}
	if owner != 0 {
		if _, err := readTrustedFlagFile(path); err == nil {
			t.Fatal("production reader accepted a non-root-owned file")
		}
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedFlagFileWithOwner(path, owner); err == nil {
		t.Fatal("group-writable parent directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedFlagFileWithOwner(path, owner); err == nil {
		t.Fatal("world-readable FLAG file was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(directory, "file-link.json")
	if err := os.Symlink(path, fileLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedFlagFileWithOwner(fileLink, owner); err == nil {
		t.Fatal("symlink FLAG file was accepted")
	}
	parentLink := directory + "-link"
	if err := os.Symlink(directory, parentLink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(parentLink) })
	if _, err := readTrustedFlagFileWithOwner(filepath.Join(parentLink, "flags.json"), owner); err == nil {
		t.Fatal("symlink parent directory was accepted")
	}
}
