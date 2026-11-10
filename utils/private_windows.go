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

var (
	errBuildPrivateDaclMissingDacl    = errors.New("build private DACL: missing DACL")
	errCurrentWindowsIdentityHasNoSid = errors.New("current Windows identity has no SID")
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

// CreatePrivateFile creates a secret file readable only by its owner. It never replaces an existing file.
func CreatePrivateFile(path string, data []byte) error {
	handle, err := openCreatePrivateFileHandle(path)
	if err != nil {
		return err
	}
	if err := writeCreatePrivateFileData(handle, path, data); err != nil {
		return err
	}
	if err := secureWindowsPath(path, false); err != nil {
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
	var name *uint16
	if parsed, err := windows.UTF16PtrFromString(path); err != nil {
		return 0, err
	} else {
		name = parsed
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

func writeCreatePrivateFileData(handle windows.Handle, path string, data []byte) error {
	f := os.NewFile(uintptr(handle), path)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func secureWindowsPath(path string, directory bool) error {
	resolveSecureWindowsPathTarget := resolvePrivateFileAbs
	if directory {
		resolveSecureWindowsPathTarget = resolvePrivateDirAbs
	}
	absPath, err := resolveSecureWindowsPathTarget(path)
	if err != nil {
		return err
	}
	if err := rejectPrivateReparsePoint(absPath); err != nil {
		return err
	}
	sd, owner, err := privateWindowsDescriptor(directory)
	if err != nil {
		return err
	}
	trustedOwner, verifyErr := verifyWindowsPath(absPath, owner, directory)
	if verifyErr == nil {
		return nil
	}
	if err := applySecureWindowsPathDacl(absPath, sd, owner, trustedOwner); err != nil {
		return err
	}
	_, err = verifyWindowsPath(absPath, owner, directory)
	return err
}

func resolvePrivateDirAbs(path string) (string, error) {
	return resolvePrivateAbsTarget(path, true)
}

func resolvePrivateFileAbs(path string) (string, error) {
	return resolvePrivateAbsTarget(path, false)
}

func resolvePrivateAbsTarget(path string, directory bool) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if directory && filepath.Dir(absPath) == absPath {
		return "", fmt.Errorf("refusing to change the ACL on volume root %q", absPath)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return "", err
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return "", fmt.Errorf("private path %q has unexpected file type", absPath)
	}
	return absPath, nil
}

func rejectPrivateReparsePoint(absPath string) error {
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
	return nil
}

func applySecureWindowsPathDacl(absPath string, sd *windows.SECURITY_DESCRIPTOR, owner, trustedOwner *windows.SID) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	if dacl == nil {
		return errBuildPrivateDaclMissingDacl
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
	if sid == "" {
		return nil, nil, errCurrentWindowsIdentityHasNoSid
	}
	inheritancePrivateWindowsDescriptorFlags := ""
	if directory {
		inheritancePrivateWindowsDescriptorFlags = "OICI"
	}
	sd, err := buildPrivateSecurityDescriptor(sid, inheritancePrivateWindowsDescriptorFlags)
	if err != nil {
		return nil, nil, err
	}
	return sd, owner, nil
}

func buildPrivateSecurityDescriptor(sid string, inheritanceFlags string) (*windows.SECURITY_DESCRIPTOR, error) {
	principals := []string{"SY", "BA"}
	if sid != localSystemSID && sid != builtinAdministratorsSID {
		principals = append(principals, sid)
	}
	var sddl strings.Builder
	sddl.WriteString("D:P")
	for _, principal := range principals {
		fmt.Fprintf(&sddl, "(A;%s;FA;;;%s)", inheritanceFlags, principal)
	}
	return windows.SecurityDescriptorFromString(sddl.String())
}

func verifyWindowsPath(path string, currentUser *windows.SID, directory bool) (*windows.SID, error) {
	actual, err := fetchVerifyWindowsPathDescriptor(path)
	if err != nil {
		return nil, err
	}
	allowed := allowedVerifyWindowsPathSids(currentUser)
	owner, err := checkVerifyWindowsPathOwner(actual, allowed, path)
	if err != nil {
		return nil, err
	}
	if err := checkVerifyWindowsPathProtection(actual, path); err != nil {
		return owner, err
	}
	inheritVerifyWindowsPathFlags := byte(0)
	if directory {
		inheritVerifyWindowsPathFlags = byte(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	}
	if err := checkVerifyWindowsPathAclEntries(actual, allowed, path, inheritVerifyWindowsPathFlags); err != nil {
		return owner, err
	}
	return owner, nil
}

func fetchVerifyWindowsPathDescriptor(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read security descriptor of %q: %w", path, err)
	}
	if actual == nil {
		return nil, fmt.Errorf("private path %q has no security descriptor", path)
	}
	return actual, nil
}

func allowedVerifyWindowsPathSids(currentUser *windows.SID) map[string]bool {
	return map[string]bool{
		currentUser.String():     true,
		localSystemSID:           true,
		builtinAdministratorsSID: true,
	}
}

func checkVerifyWindowsPathOwner(actual *windows.SECURITY_DESCRIPTOR, allowed map[string]bool, path string) (*windows.SID, error) {
	owner, _, err := actual.Owner()
	if err != nil {
		return nil, fmt.Errorf("read owner of %q: %w", path, err)
	}
	if owner == nil || !allowed[owner.String()] {
		return nil, fmt.Errorf("private path %q has an untrusted owner", path)
	}
	return owner, nil
}

func checkVerifyWindowsPathProtection(actual *windows.SECURITY_DESCRIPTOR, path string) error {
	control, _, err := actual.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private path %q inherits permissions", path)
	}
	return nil
}

func fetchVerifyWindowsPathAcl(actual *windows.SECURITY_DESCRIPTOR, path string) (*windows.ACL, error) {
	acl, _, err := actual.DACL()
	if err != nil {
		return nil, fmt.Errorf("read DACL of %q: %w", path, err)
	}
	if acl == nil {
		return nil, fmt.Errorf("private path %q has no DACL", path)
	}
	return acl, nil
}

func checkVerifyWindowsPathAclEntries(actual *windows.SECURITY_DESCRIPTOR, allowed map[string]bool, path string, inheritFlags byte) error {
	acl, err := fetchVerifyWindowsPathAcl(actual, path)
	if err != nil {
		return err
	}
	if inheritFlags != 0 && acl.AceCount == 0 {
		return fmt.Errorf("private directory %q has no inheritable permissions", path)
	}
	return checkVerifyWindowsPathAces(acl, allowed, path, inheritFlags)
}

func checkVerifyWindowsPathAces(acl *windows.ACL, allowed map[string]bool, path string, inheritFlags byte) error {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("inspect private ACL of %q: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("private path %q has unexpected ACE type or inheritance", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !allowed[sid] {
			return fmt.Errorf("private path %q grants access to an untrusted SID", path)
		}
		if inheritFlags != 0 && ace.Header.AceFlags&inheritFlags != inheritFlags {
			return fmt.Errorf("private directory %q does not protect child files and directories", path)
		}
	}
	return nil
}
