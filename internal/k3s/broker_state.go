package k3s

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type brokerStateEntry struct {
	Config         ClusterConfig    `json:"config"`
	Credential     brokerCredential `json:"credential"`
	DesiredEnabled bool             `json:"desired_enabled"`
}

type brokerState struct {
	Version int                         `json:"version"`
	Targets map[string]brokerStateEntry `json:"targets"`
}

func privateBrokerDirectory(path string, create bool) error {
	if !filepath.IsAbs(path) {
		return brokerError("BROKER_STATE_DIRECTORY_MUST_BE_ABSOLUTE")
	}
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return brokerError("BROKER_STATE_UNAVAILABLE")
		}
	}
	info, err := os.Lstat(path)
	if !create && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return brokerError("BROKER_STATE_DIRECTORY_NOT_PRIVATE")
	}
	return nil
}

func loadBrokerState(directory string) (map[string]brokerStateEntry, error) {
	path := filepath.Join(directory, "targets.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]brokerStateEntry{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128*1024*1024 {
		return nil, brokerError("BROKER_STATE_NOT_PRIVATE_OR_INVALID")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, brokerError("BROKER_STATE_UNAVAILABLE")
	}
	var state brokerState
	if err := brokerJSON(raw, &state, true); err != nil || state.Version != 1 || state.Targets == nil {
		return nil, brokerError("BROKER_STATE_INVALID")
	}
	return state.Targets, nil
}

func saveBrokerState(directory string, entries map[string]brokerStateEntry) error {
	raw, err := json.Marshal(brokerState{Version: 1, Targets: entries})
	if err != nil || len(raw) > 128*1024*1024 {
		return brokerError("BROKER_STATE_INVALID")
	}
	file, err := os.CreateTemp(directory, ".targets-")
	if err != nil {
		return brokerError("BROKER_STATE_UNAVAILABLE")
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), filepath.Join(directory, "targets.json"))
	}
	if err != nil {
		return brokerError("BROKER_STATE_COMMIT_FAILED")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return brokerError("BROKER_STATE_COMMIT_FAILED")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return brokerError("BROKER_STATE_COMMIT_FAILED")
	}
	return nil
}
