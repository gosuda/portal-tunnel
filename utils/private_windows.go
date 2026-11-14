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

// EnsurePrivateFile restricts access to a secret, preserving an already private ACL.
func EnsurePrivateFile(path string) error {
	return secureWindowsPath(path, false)
}

// CreatePrivateFile creates a secret file readable only by its owner. It never replaces an existing file.
func CreatePrivateFile(path string, data []byte) error {
	handle, err := openCreatePrivateFileHandle(path)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(handle), path)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func openCreatePrivateFileHandle(path string) (windows.Handle, error) {
	sd, _, err := privateWindowsDescriptor(false)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, fmt.Errorf("create private file %q: %w", path, err)
	}
	return handle, nil
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
	trustedOwner, err := verifyWindowsPath(absPath, owner, directory)
	if err == nil {
		return nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	securityInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var replacementOwner *windows.SID
	if trustedOwner == nil {
		securityInfo |= windows.OWNER_SECURITY_INFORMATION
		replacementOwner = owner
	}
	if err := windows.SetNamedSecurityInfo(absPath, windows.SE_FILE_OBJECT,
		securityInfo, replacementOwner, nil, dacl, nil); err != nil {
		return fmt.Errorf("secure private path %q: %w", absPath, err)
	}
	return nil
}

const (
	localSystemSID           = "S-1-5-18"
	builtinAdministratorsSID = "S-1-5-32-544"
)

func privateWindowsDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	owner := user.User.Sid
	sid := owner.String()
	inheritanceFlags := ""
	if directory {
		inheritanceFlags = "OICI"
	}
	principals := []string{"SY", "BA"}
	if sid != localSystemSID && sid != builtinAdministratorsSID {
		principals = append(principals, sid)
	}
	var sddl strings.Builder
	sddl.WriteString("D:P")
	for _, principal := range principals {
		fmt.Fprintf(&sddl, "(A;%s;FA;;;%s)", inheritanceFlags, principal)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl.String())
	return sd, owner, err
}

func verifyWindowsPath(path string, currentUser *windows.SID, directory bool) (*windows.SID, error) {
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read security descriptor of %q: %w", path, err)
	}
	allowed := map[string]bool{
		currentUser.String():     true,
		localSystemSID:           true,
		builtinAdministratorsSID: true,
	}
	owner, _, err := actual.Owner()
	if err != nil {
		return nil, err
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
	inheritFlags := byte(0)
	if directory {
		inheritFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if inheritFlags != 0 && acl.AceCount == 0 {
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
		if inheritFlags != 0 && ace.Header.AceFlags&inheritFlags != inheritFlags {
			return owner, fmt.Errorf("private directory %q does not protect child files and directories", path)
		}
	}
	return owner, nil
}
