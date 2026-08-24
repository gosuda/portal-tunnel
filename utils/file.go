package utils

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func EnsureParentDir(path string) error {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func FileExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	path = strings.TrimSpace(path)
	dir := filepath.Dir(path)
	dir = cmp.Or(dir, ".")
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func ReadJSONFile(path string, out any) error {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func ReadJSONFileIfExists(path string, out any) (bool, error) {
	err := ReadJSONFile(path, out)
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func WriteJSONFile(path string, payload any, mode os.FileMode) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := EnsureParentDir(path); err != nil {
		return err
	}
	return WriteFileAtomic(path, data, mode)
}
