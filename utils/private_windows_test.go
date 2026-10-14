package utils

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateACLRepairsBroadDirectoryAndFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "agent-endpoint.json")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	broad, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, file} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(file); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		dir  bool
	}{
		{path: dir, dir: true},
		{path: file, dir: false},
	} {
		sd, owner, err := privateWindowsDescriptor(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyWindowsPath(tc.path, sd, owner); err != nil {
			t.Fatalf("insecure ACL for %q: %v", tc.path, err)
		}
	}
}

func TestWindowsPrivateFileCreatedWithoutInheritedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := CreatePrivateFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	sd, owner, err := privateWindowsDescriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsPath(path, sd, owner); err != nil {
		t.Fatal(err)
	}
	if err := CreatePrivateFile(path, []byte("replacement")); err == nil {
		t.Fatal("existing identity was overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret" {
		t.Fatalf("private file content changed: %q", data)
	}
}
