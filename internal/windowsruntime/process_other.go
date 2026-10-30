//go:build !linux

package windowsruntime

import (
	"context"
	"errors"
)

// FreeRDP sessions are deliberately unsupported on non-Linux hosts. Keeping the
// rest of the Runtime buildable on Windows supports guest-runner development.
var errTransportLinux = errors.New("Windows RDP transport requires a Linux host")

func transportMkdirAll(string) error          { return errTransportLinux }
func transportMkdirExclusive(string) error    { return errTransportLinux }
func transportWriteFile(string, []byte) error { return errTransportLinux }
func transportProbeVersion(context.Context, string, []string) ([]byte, error) {
	return nil, errTransportLinux
}

type transportOwnedProcess struct{ done chan struct{} }

func transportStartProcess(string, string, string, []string, []string, []byte) (*transportOwnedProcess, error) {
	return nil, errTransportLinux
}
func (*transportOwnedProcess) stop() error                          { return errTransportLinux }
func (*transportOwnedProcess) wait()                                {}
func transportRecoverProcess(context.Context, string, string) error { return errTransportLinux }
func transportReadFile(string, int, bool) ([]byte, error)           { return nil, errTransportLinux }
