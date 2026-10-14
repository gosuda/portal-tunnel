package utils

import (
	"fmt"
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
		_, owner, err := privateWindowsDescriptor(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyWindowsPath(tc.path, owner, tc.dir); err != nil {
			t.Fatalf("insecure ACL for %q: %v", tc.path, err)
		}
	}
}

func TestWindowsPrivateFileCreatedWithoutInheritedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := CreatePrivateFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	_, owner, err := privateWindowsDescriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWindowsPath(path, owner, false); err != nil {
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

func TestWindowsPrivateDirectoryRepairsMissingInheritance(t *testing.T) {
	_, user, err := privateWindowsDescriptor(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []string{"", "OI", "CI"} {
		t.Run("flags="+flags, func(t *testing.T) {
			dir := t.TempDir()
			sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
				"D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)", flags, user.String(), flags, flags))
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			if err := EnsurePrivateDir(dir); err != nil {
				t.Fatal(err)
			}
			actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err = actual.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if acl == nil || acl.AceCount == 0 {
				t.Fatal("directory has no inheritable permissions")
			}
			for i := uint32(0); i < uint32(acl.AceCount); i++ {
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(acl, i, &ace); err != nil {
					t.Fatal(err)
				}
				if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
					t.Fatal("directory permissions are not inherited by both files and directories")
				}
			}
		})
	}
}

func TestWindowsPrivateFilePreservesSafePermissionsAndOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := CreatePrivateFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	_, user, err := privateWindowsDescriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FR;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user.String()))
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatal("safe permissions or ownership changed")
	}
}
