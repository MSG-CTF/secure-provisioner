//go:build linux

package k3s

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func readTrustedFlagFile(filename string) ([]byte, error) {
	return readTrustedFlagFileWithOwner(filename, 0)
}

// readTrustedFlagFileWithOwner uses a parameter only so Linux tests can
// exercise a positive read without requiring root. Production always uses UID 0.
func readTrustedFlagFileWithOwner(filename string, ownerUID uint32) ([]byte, error) {
	if !filepath.IsAbs(filename) {
		return nil, errors.New("FLAG file requires an absolute trusted path")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(filename), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil, errors.New("FLAG file requires an absolute trusted path")
	}
	directoryFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("FLAG file path cannot be opened")
	}
	defer func() { _ = unix.Close(directoryFD) }()
	if !trustedFlagDirectory(directoryFD, ownerUID) {
		return nil, errors.New("FLAG file parent directory is not operator-owned")
	}
	for _, part := range parts[:len(parts)-1] {
		nextFD, err := unix.Openat(directoryFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errors.New("FLAG file parent directory cannot be opened")
		}
		_ = unix.Close(directoryFD)
		directoryFD = nextFD
		if !trustedFlagDirectory(directoryFD, ownerUID) {
			return nil, errors.New("FLAG file parent directory is not operator-owned")
		}
	}
	fileFD, err := unix.Openat(directoryFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("FLAG file cannot be opened")
	}
	file := os.NewFile(uintptr(fileFD), "operator FLAG file")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fileFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != ownerUID || stat.Mode&0o027 != 0 || stat.Size > 1<<20 {
		return nil, errors.New("FLAG file must be an operator-owned private regular file under 1 MiB")
	}
	contents, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(contents) > 1<<20 {
		return nil, errors.New("FLAG file cannot be read safely")
	}
	return contents, nil
}

func trustedFlagDirectory(fd int, ownerUID uint32) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		(stat.Uid == 0 || stat.Uid == ownerUID) && stat.Mode&0o022 == 0
}
