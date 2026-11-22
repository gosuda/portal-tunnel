package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     string
}

func writeTarGz(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o755, Size: int64(len(e.body))}
		if e.typeflag == tar.TypeSymlink {
			header.Linkname, header.Size = "/etc/passwd", 0
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := archive.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "desktop.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func keepAll(string) bool { return true }

// The update unpacks a downloaded package next to the installed desktop, so
// nothing in the package may write outside the directory it is unpacked in.
func TestExtractTarGzStaysInItsDirectory(t *testing.T) {
	program := tarEntry{name: linuxDesktopProgram, typeflag: tar.TypeReg, body: "program"}
	dir := t.TempDir()
	src := writeTarGz(t, tarEntry{name: "usr/", typeflag: tar.TypeDir}, program, tarEntry{name: "usr/share/icon.png", typeflag: tar.TypeReg, body: "icon"})
	if err := extractTarGz(src, dir, func(name string) bool { return name == linuxDesktopProgram }); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(linuxDesktopProgram))); err != nil || string(data) != "program" {
		t.Fatalf("program = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "usr", "share", "icon.png")); !os.IsNotExist(err) {
		t.Fatalf("an entry that was not asked for was written: %v", err)
	}

	for name, entry := range map[string]tarEntry{
		"parent":   {name: "../escaped", typeflag: tar.TypeReg, body: "x"},
		"absolute": {name: "/tmp/escaped", typeflag: tar.TypeReg, body: "x"},
		"symlink":  {name: "usr/bin/link", typeflag: tar.TypeSymlink},
	} {
		t.Run(name, func(t *testing.T) {
			if err := extractTarGz(writeTarGz(t, entry), t.TempDir(), keepAll); err == nil {
				t.Fatalf("entry %q was accepted", entry.name)
			}
		})
	}
}

// The desktop is swapped in before the CLI; when the CLI then cannot be
// replaced, the old desktop comes back so the pair stays one version.
func TestSwapInRestoresTheOldDesktop(t *testing.T) {
	for _, kind := range []string{"program", "bundle"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			dst, src := filepath.Join(dir, "desktop"), filepath.Join(dir, "staged")
			write := func(path, body string) {
				if kind == "bundle" {
					if err := os.MkdirAll(path, 0o755); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(path, "Info.plist")
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			read := func() string {
				path := dst
				if kind == "bundle" {
					path = filepath.Join(dst, "Info.plist")
				}
				data, _ := os.ReadFile(path)
				return string(data)
			}
			write(dst, "old")
			write(src, "new")
			restore, _, err := swapIn(src, dst)
			if err != nil {
				t.Fatal(err)
			}
			if got := read(); got != "new" {
				t.Fatalf("after the swap the desktop is %q", got)
			}
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			if got := read(); got != "old" {
				t.Fatalf("after the restore the desktop is %q", got)
			}

			write(src, "new")
			_, commit, err := swapIn(src, dst)
			if err != nil {
				t.Fatal(err)
			}
			commit()
			if got := read(); got != "new" {
				t.Fatalf("after the commit the desktop is %q", got)
			}
			if _, err := os.Stat(dst + ".old"); !os.IsNotExist(err) {
				t.Fatalf("the old desktop outlived the commit: %v", err)
			}
		})
	}
}

// portal gui and portal update look for the desktop where the installers put
// it, and treat its absence as a CLI-only installation.
func TestDesktopIsFoundWhereTheInstallersPutIt(t *testing.T) {
	dir := t.TempDir()
	cliPath := filepath.Join(dir, "portal")
	var installed string
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", dir)
		installed = filepath.Join(dir, "Applications", desktopApp)
	case "windows":
		installed = filepath.Join(dir, "portal-desktop.exe")
	default:
		installed = filepath.Join(dir, "portal-desktop")
		if _, ok := Desktop(cliPath); ok {
			t.Fatal("a CLI-only installation was taken for one with the desktop")
		}
	}
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, ok := Desktop(cliPath); !ok || got != installed {
		t.Fatalf("Desktop = %q, %v; want %q", got, ok, installed)
	}
}
