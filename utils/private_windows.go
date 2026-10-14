package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EnsurePrivateDir restricts an agent-owned directory before any secrets are placed in it.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return secureWindowsPath(path, true)
}

// EnsurePrivateFile repairs and verifies the ACL before reading or changing a secret.
func EnsurePrivateFile(path string) error {
	return secureWindowsPath(path, false)
}

// CreatePrivateFile installs the DACL at creation time, not after writing the secret.
func CreatePrivateFile(path string, data []byte) error {
	sd, _, err := privateWindowsDescriptor(false)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("create private file %q: %w", path, err)
	}
	f := os.NewFile(uintptr(handle), path)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	// Windows may add inheritable entries on some volumes. Verify the final result.
	if err := secureWindowsPath(path, false); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func secureWindowsPath(path string, directory bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if directory && filepath.Dir(absPath) == absPath {
		return fmt.Errorf("refusing to change the ACL on volume root %q", absPath)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return err
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("private path %q has unexpected file type", absPath)
	}
	name, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("private path %q is a reparse point", absPath)
	}

	sd, owner, err := privateWindowsDescriptor(directory)
	if err != nil {
		return err
	}
	trustedOwner, verifyErr := verifyWindowsPath(absPath, owner, directory)
	if verifyErr == nil {
		return nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("build private DACL: missing DACL")
	}
	securityInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var replacementOwner *windows.SID
	if trustedOwner == nil {
		securityInfo |= windows.OWNER_SECURITY_INFORMATION
		replacementOwner = owner
	}
	err = windows.SetNamedSecurityInfo(absPath, windows.SE_FILE_OBJECT,
		securityInfo, replacementOwner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("secure private path %q: %w", absPath, err)
	}
	_, err = verifyWindowsPath(absPath, owner, directory)
	return err
}

// privateWindowsDescriptor allows only the running service identity, SYSTEM,
// and Administrators. Directory ACEs are inheritable by its children.
func privateWindowsDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	owner := user.User.Sid
	sid := owner.String()
	if sid == "" {
		return nil, nil, errors.New("current Windows identity has no SID")
	}
	principals := []string{"SY", "BA"}
	if sid != "S-1-5-18" && sid != "S-1-5-32-544" {
		principals = append(principals, sid)
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	var sddl strings.Builder
	sddl.WriteString("D:P")
	for _, principal := range principals {
		fmt.Fprintf(&sddl, "(A;%s;FA;;;%s)", flags, principal)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl.String())
	if err != nil {
		return nil, nil, err
	}
	return sd, owner, nil
}

// verifyWindowsPath returns a trusted owner even when the DACL needs repair.
// Existing owners and narrower permissions are preserved when only trusted
// principals have access and inheritance from the parent is disabled.
// Directories must pass those permissions on to child files and directories.
func verifyWindowsPath(path string, currentUser *windows.SID, directory bool) (*windows.SID, error) {
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read security descriptor of %q: %w", path, err)
	}
	if actual == nil {
		return nil, fmt.Errorf("private path %q has no security descriptor", path)
	}
	allowed := map[string]bool{
		currentUser.String(): true,
		"S-1-5-18":           true, // SYSTEM
		"S-1-5-32-544":       true, // Administrators
	}
	owner, _, err := actual.Owner()
	if err != nil {
		return nil, fmt.Errorf("read owner of %q: %w", path, err)
	}
	if owner == nil || !allowed[owner.String()] {
		return nil, fmt.Errorf("private path %q has an untrusted owner", path)
	}
	control, _, err := actual.Control()
	if err != nil {
		return owner, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return owner, fmt.Errorf("private path %q inherits permissions", path)
	}
	acl, _, err := actual.DACL()
	if err != nil {
		return owner, fmt.Errorf("read DACL of %q: %w", path, err)
	}
	if acl == nil {
		return owner, fmt.Errorf("private path %q has no DACL", path)
	}
	if directory && acl.AceCount == 0 {
		return owner, fmt.Errorf("private directory %q has no inheritable permissions", path)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return owner, fmt.Errorf("inspect private ACL of %q: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return owner, fmt.Errorf("private path %q has unexpected ACE type or inheritance", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !allowed[sid] {
			return owner, fmt.Errorf("private path %q grants access to an untrusted SID", path)
		}
		inheritFlags := byte(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
		if directory && ace.Header.AceFlags&inheritFlags != inheritFlags {
			return owner, fmt.Errorf("private directory %q does not protect child files and directories", path)
		}
	}
	return owner, nil
}
