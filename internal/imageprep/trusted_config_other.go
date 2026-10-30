//go:build !linux

package imageprep

import (
	"errors"
	"io"
	"os"
)

// Non-Linux builds retain ACL-managed development compatibility. Linux is the
// production host and additionally enforces descriptor-based UID/mode checks.
func readTrustedAgentConfig(path string) ([]byte, error) {
	invalid := errors.New("untrusted image agent configuration")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, invalid
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, invalid
	}
	return data, nil
}
