package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateACLRepairsBroadDirectoryAndFile(t *testing.T) {
	dir, file := seedBroadACLDirAndFile(t)
	poisonBroadACLDirAndFile(t, dir, file)
	checkBroadACLRepair(t, dir, file)
}

func seedBroadACLDirAndFile(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "agent-endpoint.json")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

func poisonBroadACLDirAndFile(t *testing.T, dir, file string) {
	t.Helper()
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
}

func checkBroadACLRepair(t *testing.T, dir, file string) {
	t.Helper()
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(file); err != nil {
		t.Fatal(err)
	}
	_, dirOwner, err := privateWindowsDescriptor(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWindowsPath(dir, dirOwner, true); err != nil {
		t.Fatalf("insecure ACL for %q: %v", dir, err)
	}
	_, fileOwner, fileErr := privateWindowsDescriptor(false)
	if fileErr != nil {
		t.Fatal(fileErr)
	}
	if _, err := verifyWindowsPath(file, fileOwner, false); err != nil {
		t.Fatalf("insecure ACL for %q: %v", file, err)
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
			repairDirMissingInheritance(t, user.String(), flags)
		})
	}
}

func repairDirMissingInheritance(t *testing.T, userSID, flags string) {
	t.Helper()
	dir := t.TempDir()
	poisonDirMissingInheritance(t, dir, userSID, flags)
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	checkRepairedDirInheritance(t, dir)
}

func poisonDirMissingInheritance(t *testing.T, dir, userSID, flags string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)", flags, userSID, flags, flags))
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
}

func checkRepairedDirInheritance(t *testing.T, dir string) {
	t.Helper()
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, dacErr := actual.DACL()
	if dacErr != nil {
		t.Fatal(dacErr)
	}
	if acl == nil || acl.AceCount == 0 {
		t.Fatal("directory has no inheritable permissions")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		checkDirInheritanceAce(t, acl, i)
	}
}

func checkDirInheritanceAce(t *testing.T, acl *windows.ACL, index uint32) {
	t.Helper()
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, index, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
		t.Fatal("directory permissions are not inherited by both files and directories")
	}
}

func TestWindowsPrivateFilePreservesSafePermissionsAndOwner(t *testing.T) {
	path, userSID := seedSafeOwnerFile(t)
	poisonSafeOwnerFile(t, path, userSID)
	before := readSafeOwnerFileSecurity(t, path)
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	after := readSafeOwnerFileSecurity(t, path)
	if before != after {
		t.Fatal("safe permissions or ownership changed")
	}
}

func seedSafeOwnerFile(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := CreatePrivateFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	_, user, err := privateWindowsDescriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	return path, user.String()
}

func poisonSafeOwnerFile(t *testing.T, path, userSID string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FR;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", userSID))
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
}

func readSafeOwnerFileSecurity(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.String()
}
