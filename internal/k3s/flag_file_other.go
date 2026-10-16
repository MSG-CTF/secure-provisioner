//go:build !linux

package k3s

import (
	"errors"
	"os"
	"runtime"
)

func readTrustedFlagFile(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, errors.New("FLAG file cannot be inspected")
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o027 != 0) {
		return nil, errors.New("FLAG file must be a private regular file under 1 MiB")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("FLAG file cannot be read")
	}
	return contents, nil
}
