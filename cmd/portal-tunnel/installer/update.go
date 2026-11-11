package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const updateCheckInterval = 24 * time.Hour

var updateCheckClient = utils.NewHTTPClient(
	utils.WithHTTPTimeout(10*time.Second),
	utils.WithHTTPCheckRedirect(func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}),
)

var updateDownloadClient = utils.NewHTTPClient(utils.WithHTTPTimeout(120 * time.Second))

func StartUpdateCheck(currentVersion string) {
	binURL, _, ok := assetURLs("")
	if !ok {
		return
	}

	go func() {
		for {
			checkForAvailableUpdate(currentVersion, binURL)
			time.Sleep(updateCheckInterval)
		}
	}()
}

func checkForAvailableUpdate(currentVersion, binURL string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, binURL, nil)
	if err != nil {
		return
	}
	resp, err := updateCheckClient.Do(req)
	if err != nil {
		return
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()

	parsed, err := url.Parse(location)
	if err != nil {
		return
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) < 5 {
		return
	}

	version := segments[4]
	current := strings.TrimSpace(currentVersion)
	if current != "" && !strings.HasPrefix(current, "v") {
		current = "v" + current
	}
	latestValid := strings.HasPrefix(version, "v") && semver.IsValid(version)
	if !latestValid || !semver.IsValid(current) || semver.Compare(version, current) <= 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nA new version is available: %s. Run 'portal update' to upgrade.\n", version)
}

func resolveExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}
	return execPath, nil
}

func fetchUpdateBinary(binURL string) (string, error) {
	tmpFile, err := os.CreateTemp("", "portal-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	resp, err := acquireFetchUpdateBinaryResponse(binURL, tmpFile, tmpPath)
	if err != nil {
		return "", err
	}
	if err := persistFetchUpdateBinaryResponse(resp, tmpFile, tmpPath); err != nil {
		return "", err
	}
	return tmpPath, nil
}

func acquireFetchUpdateBinaryResponse(binURL string, tmpFile *os.File, tmpPath string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, binURL, nil)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to build binary request: %w", err)
	}
	resp, err := updateDownloadClient.Do(req)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to download binary: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to download binary: unexpected status %d", resp.StatusCode)
	}
	return resp, nil
}

func persistFetchUpdateBinaryResponse(resp *http.Response, tmpFile *os.File, tmpPath string) error {
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = resp.Body.Close()
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to download binary: %w", err)
	}
	_ = resp.Body.Close()

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to sync downloaded binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close downloaded binary: %w", err)
	}
	return nil
}

func verifyUpdateChecksum(tmpPath, checksumURL string) error {
	body, err := fetchVerifyUpdateChecksumBody(checksumURL)
	if err != nil {
		return err
	}
	expectedHash, err := parseVerifyUpdateChecksumExpected(body)
	if err != nil {
		return err
	}
	actualHash, err := digestVerifyUpdateChecksumFile(tmpPath)
	if err != nil {
		return err
	}
	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

func fetchVerifyUpdateChecksumBody(checksumURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, checksumURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build checksum request: %w", err)
	}
	resp, err := updateDownloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download checksum: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksum download returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read checksum response: %w", err)
	}
	return body, nil
}

func parseVerifyUpdateChecksumExpected(body []byte) (string, error) {
	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty checksum response")
	}
	expectedHash := strings.ToLower(fields[0])
	if len(expectedHash) != 64 {
		return "", fmt.Errorf("invalid checksum format (expected 64 hex chars, got %d)", len(expectedHash))
	}
	return expectedHash, nil
}

func digestVerifyUpdateChecksumFile(tmpPath string) (string, error) {
	f, err := os.Open(tmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func UpdateCurrentBinary(version string) error {
	binURL, checksumURL, ok := assetURLs(version)
	if !ok {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	execPath, err := resolveExecutablePath()
	if err != nil {
		return err
	}

	tmpPath, err := fetchUpdateBinary(binURL)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	if err := verifyUpdateChecksum(tmpPath, checksumURL); err != nil {
		return err
	}

	if err := replaceBinary(tmpPath, execPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}

func assetURLs(version string) (binURL, checksumURL string, ok bool) {
	slug := runtime.GOOS + "-" + runtime.GOARCH
	filename, ok := AssetFilename(slug)
	if !ok {
		return "", "", false
	}

	baseURL := types.OfficialReleaseBaseURL + "/latest/download"
	version = strings.TrimSpace(version)
	if version != "" {
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		baseURL = types.OfficialReleaseBaseURL + "/download/" + version
	}

	binURL = baseURL + "/" + filename
	return binURL, binURL + ".sha256", true
}

func replaceBinary(srcPath, dstPath string) error {
	if runtime.GOOS == "windows" {
		return replaceBinaryWindows(srcPath, dstPath)
	}
	return replaceBinaryUnix(srcPath, dstPath)
}

func replaceBinaryUnix(srcPath, dstPath string) error {
	done, err := finalizeReplaceBinaryUnixFastPath(srcPath, dstPath)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	return fallbackReplaceBinaryUnix(srcPath, dstPath)
}

func finalizeReplaceBinaryUnixFastPath(srcPath, dstPath string) (bool, error) {
	if err := os.Chmod(srcPath, 0755); err != nil {
		return false, fmt.Errorf("failed to set permissions: %w", err)
	}
	if err := os.Rename(srcPath, dstPath); err == nil {
		return true, nil
	}
	return false, nil
}

func fallbackReplaceBinaryUnix(srcPath, dstPath string) error {
	src, tmp, tmpPath, err := openReplaceBinaryUnixPair(srcPath, dstPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := copyReplaceBinaryUnixPayload(src, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return fmt.Errorf("failed to replace destination: %w", err)
	}
	tmpPath = ""
	return nil
}

func openReplaceBinaryUnixPair(srcPath, dstPath string) (*os.File, *os.File, string, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return nil, nil, "", err
	}
	dstDir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dstDir, "."+filepath.Base(dstPath)+".update-*")
	if err != nil {
		_ = src.Close()
		return nil, nil, "", fmt.Errorf("failed to create replacement file: %w", err)
	}
	return src, tmp, tmp.Name(), nil
}

func copyReplaceBinaryUnixPayload(src, tmp *os.File) error {
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set replacement permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync replacement binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close replacement binary: %w", err)
	}
	return nil
}

func replaceBinaryWindows(srcPath, dstPath string) error {
	oldPath := dstPath + ".old"

	_ = os.Remove(oldPath)

	if err := os.Rename(dstPath, oldPath); err != nil {
		return fmt.Errorf("failed to rename old binary: %w", err)
	}

	if err := os.Rename(srcPath, dstPath); err != nil {
		_ = os.Rename(oldPath, dstPath)
		return fmt.Errorf("failed to place new binary: %w", err)
	}

	_ = os.Remove(oldPath)
	return nil
}
