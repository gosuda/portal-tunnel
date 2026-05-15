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
			req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, binURL, nil)
			if err == nil {
				resp, err := updateCheckClient.Do(req)
				if err == nil {
					location := resp.Header.Get("Location")
					_ = resp.Body.Close()

					if parsed, err := url.Parse(location); err == nil {
						segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
						if len(segments) >= 5 {
							version := segments[4]
							if strings.HasPrefix(version, "v") && version != currentVersion {
								fmt.Fprintf(os.Stderr, "\nA new version is available: %s. Run 'portal update' to upgrade.\n", version)
							}
						}
					}
				}
			}

			time.Sleep(updateCheckInterval)
		}
	}()
}

func UpdateCurrentBinary(version string) error {
	binURL, checksumURL, ok := assetURLs(version)
	if !ok {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "portal-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, binURL, nil)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to build binary request: %w", err)
	}
	resp, err := updateDownloadClient.Do(req)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to download binary: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = tmpFile.Close()
		return fmt.Errorf("failed to download binary: unexpected status %d", resp.StatusCode)
	}
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = resp.Body.Close()
		_ = tmpFile.Close()
		return fmt.Errorf("failed to download binary: %w", err)
	}
	_ = resp.Body.Close()

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync downloaded binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close downloaded binary: %w", err)
	}

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, checksumURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build checksum request: %w", err)
	}
	resp, err = updateDownloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download checksum: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read checksum response: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return fmt.Errorf("empty checksum response")
	}
	expectedHash := strings.ToLower(fields[0])
	if len(expectedHash) != 64 {
		return fmt.Errorf("invalid checksum format (expected 64 hex chars, got %d)", len(expectedHash))
	}

	f, err := os.Open(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	if err := replaceBinary(tmpFile.Name(), execPath); err != nil {
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
	if err := os.Chmod(srcPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err := os.Rename(srcPath, dstPath); err == nil {
		return nil
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	dstDir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dstDir, "."+filepath.Base(dstPath)+".update-*")
	if err != nil {
		return fmt.Errorf("failed to create replacement file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

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
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return fmt.Errorf("failed to replace destination: %w", err)
	}
	tmpPath = ""
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
