package installer

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// desktopApp is the macOS bundle of Portal Desktop, as ggui.toml names it.
const desktopApp = "Portal Desktop.app"

// linuxDesktopProgram is the program in the Linux install tree.
const linuxDesktopProgram = "usr/bin/portal-desktop"

var errDesktopPackageIncomplete = errors.New("the Portal Desktop package does not hold the program")

// Desktop is where Portal Desktop is installed for the CLI at cliPath, as the
// installers put it: an app bundle in an Applications folder on macOS, and the
// portal-desktop program beside the CLI elsewhere. It reports false for a
// CLI-only installation.
func Desktop(cliPath string) (string, bool) {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, "Applications", desktopApp))
		}
		candidates = append(candidates, filepath.Join(string(filepath.Separator), "Applications", desktopApp))
	case "windows":
		candidates = append(candidates, filepath.Join(filepath.Dir(cliPath), "portal-desktop.exe"))
	default:
		candidates = append(candidates, filepath.Join(filepath.Dir(cliPath), "portal-desktop"))
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

// DesktopInstallCommand is how to install the CLI with Portal Desktop from
// the official release on this platform.
func DesktopInstallCommand() string {
	download := types.OfficialReleaseBaseURL + "/latest/download/"
	if runtime.GOOS == "windows" {
		return "$env:PORTAL_WITH_GUI = '1'; irm " + download + "install.ps1 | iex"
	}
	return "curl -fsSL " + download + "install.sh | sh -s -- --with-gui"
}

// desktopAssetFilename is the release asset of Portal Desktop for this
// platform: the app bundle or the Linux install tree in a tarball, or the
// Windows program.
func desktopAssetFilename() (string, bool) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", false
	}
	slug := runtime.GOOS + "-" + runtime.GOARCH
	switch runtime.GOOS {
	case "darwin", "linux":
		return "portal-desktop-" + slug + ".tar.gz", true
	case "windows":
		return "portal-desktop-" + slug + ".exe", true
	default:
		return "", false
	}
}

// stageDesktop downloads and verifies the release asset of Portal Desktop and
// unpacks it in a new directory beside dst, from where it can be renamed over
// dst. It returns what to rename and the directory, which the caller removes.
func stageDesktop(version, dst string) (string, string, error) {
	filename, ok := desktopAssetFilename()
	if !ok {
		return "", "", fmt.Errorf("no Portal Desktop release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	dir, err := os.MkdirTemp(filepath.Dir(dst), ".portal-desktop-update-")
	if err != nil {
		return "", "", err
	}
	assetURL := releaseAssetURL(version, filename)
	asset, err := fetchUpdateBinary(dir, assetURL)
	if errors.Is(err, errReleaseAssetNotFound) {
		return "", dir, desktopMissingError(version, dst)
	}
	if err != nil {
		return "", dir, err
	}
	if err := verifyUpdateChecksum(asset, assetURL+".sha256"); err != nil {
		return "", dir, err
	}
	var staged string
	switch runtime.GOOS {
	case "windows":
		staged = asset
	case "darwin":
		staged = filepath.Join(dir, desktopApp)
		err = extractTarGz(asset, dir, func(name string) bool { return name == desktopApp || strings.HasPrefix(name, desktopApp+"/") })
	default:
		staged = filepath.Join(dir, filepath.FromSlash(linuxDesktopProgram))
		err = extractTarGz(asset, dir, func(name string) bool { return name == linuxDesktopProgram })
	}
	if err != nil {
		return "", dir, err
	}
	if _, err := os.Stat(staged); err != nil {
		return "", dir, errDesktopPackageIncomplete
	}
	return staged, dir, os.Chmod(staged, 0o755)
}

// desktopMissingError says why an update to a release without Portal Desktop,
// such as one older than it, stops before it changes anything: the CLI and the
// installed desktop move only together.
func desktopMissingError(version, desktop string) error {
	return fmt.Errorf("release %s has no Portal Desktop for %s/%s, and Portal Desktop is installed at %s; "+
		"portal update keeps the CLI and the desktop at one release, so choose a release with Portal Desktop, "+
		"or remove %s to update the CLI alone", version, runtime.GOOS, runtime.GOARCH, desktop, desktop)
}

// swapIn renames src over dst and keeps the old dst beside it, as dst.old,
// until commit removes it; restore puts it back. A desktop that is running
// keeps running from the old copy until it is reopened.
func swapIn(src, dst string) (restore func() error, commit func(), err error) {
	old := dst + ".old"
	// A Windows program left from an update while it ran.
	_ = os.RemoveAll(old)
	if err := os.Rename(dst, old); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(src, dst); err != nil {
		if restoreErr := os.Rename(old, dst); restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
		return nil, nil, err
	}
	restore = func() error {
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		return os.Rename(old, dst)
	}
	commit = func() { _ = os.RemoveAll(old) }
	return restore, commit, nil
}

// extractTarGz writes the directories and regular files of the tarball at src
// whose names keep accepts into dir. It refuses names that would leave dir,
// and links of any kind.
func extractTarGz(src, dir string, keep func(name string) bool) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(path.Clean(header.Name), "/")
		if !keep(name) {
			continue
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("archive entry %q leaves the archive", header.Name)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeArchiveFile(target, archive, header.FileInfo().Mode().Perm()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("archive entry %q is not a file or a directory", header.Name)
		}
	}
}

func writeArchiveFile(target string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
