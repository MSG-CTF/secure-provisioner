//go:build linux

package imageprep

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Only root and the effective Runtime service account may own trust material.
// Walk with openat and O_NOFOLLOW so no path component can redirect this read.
func readTrustedAgentConfig(path string) ([]byte, error) {
	invalid := errors.New("untrusted image agent configuration")
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, invalid
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), "/"), "/")
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return nil, invalid
	}
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = unix.Close(directory) }()
	for _, component := range parts[:len(parts)-1] {
		var parent unix.Stat_t
		if unix.Fstat(directory, &parent) != nil || !trustedConfigDirectory(parent) {
			return nil, invalid
		}
		next, openErr := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, invalid
		}
		_ = unix.Close(directory)
		directory = next
	}
	var parent unix.Stat_t
	if unix.Fstat(directory, &parent) != nil || !trustedConfigDirectory(parent) {
		return nil, invalid
	}
	fd, err := unix.Openat(directory, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	file := os.NewFile(uintptr(fd), "trusted-image-agent-config")
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !trustedConfigFile(before) {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, invalid
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !trustedConfigFile(after) ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid ||
		before.Mode != after.Mode || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, invalid
	}
	return data, nil
}

func trustedConfigOwner(uid uint32) bool { return uid == 0 || uid == uint32(os.Geteuid()) }

func trustedConfigFile(info unix.Stat_t) bool {
	return info.Mode&unix.S_IFMT == unix.S_IFREG && trustedConfigOwner(info.Uid) && info.Mode&0022 == 0 && info.Size <= 1<<20
}

func trustedConfigDirectory(info unix.Stat_t) bool {
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || !trustedConfigOwner(info.Uid) {
		return false
	}
	// A root-owned sticky directory (such as /tmp) cannot redirect another
	// owner's protected child. Other writable ancestors are never trusted.
	return info.Mode&0022 == 0 || (info.Uid == 0 && info.Mode&unix.S_ISVTX != 0)
}
