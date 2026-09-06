package embedded

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func makeKeyDirectory(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	// Install protection at creation, before inherited grants could permit a
	// competing writer. Existing directories and their children are never
	// rewritten: IDENTITY_PATH may also contain operator-managed certificates.
	serviceSID := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + serviceSID + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + serviceSID + ")")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := createPrivateKeyDirectories(filepath.Clean(dir), &attributes); err != nil {
		return err
	}
	return validateKeyDirectory(dir, user.User.Sid)
}

func createPrivateKeyDirectories(dir string, attributes *windows.SecurityAttributes) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("dnssec key directory %q is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return err
	}
	if err := createPrivateKeyDirectories(parent, attributes); err != nil {
		return err
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(path, attributes); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create private dnssec key directory %q: %w", dir, err)
		}
		// A concurrent creator owns this directory. Do not replace its ACL;
		// the configured key directory is validated by our caller instead.
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("dnssec key directory %q is not a directory", dir)
		}
	}
	return nil
}

func createKeyTempFile(dir string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	serviceSID := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + serviceSID + "D:P(A;;FA;;;SY)(A;;FA;;;" + serviceSID + ")")
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for {
		path := filepath.Join(dir, ".dnssec-key-"+rand.Text())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		// Shared directories may legitimately grant operators inherited read
		// access. Protect the file at CREATE_NEW: hardening an inherited DACL
		// later cannot revoke handles already opened before the first write.
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create private dnssec key file: %w", err)
		}
		return os.NewFile(uintptr(handle), path), nil
	}
}

func publishKeyFile(tmp, path string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Both names are in the same directory. Do not allow replacement or a
	// copy/delete fallback; WRITE_THROUGH waits for the move to reach disk.
	// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func syncKeyPublication(path string) error {
	// FlushFileBuffers commits file-system metadata on Windows. A reader must
	// flush too: it may have observed a concurrent publication before that
	// creator returned. Unlike Unix directory fsync, this requires a writable
	// file handle; opening without CREATE/TRUNCATE never modifies key contents.
	// https://learn.microsoft.com/windows/win32/fileio/file-caching
	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

func restrictKeyPermissions(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	// Existing keys bypass makeKeyDirectory. Validate, but never repair, their
	// shared directory before touching the key or exposing its DNSKEY and DS.
	if err := validateKeyDirectory(filepath.Dir(path), user.User.Sid); err != nil {
		return err
	}
	// POSIX mode bits do not restrict access on Windows. Only the key gets a
	// protected DACL allowing the service account and SYSTEM; no sibling ACLs
	// or inherited operator permissions are changed.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict dnssec key path %q permissions: %w", path, err)
	}
	return nil
}

func trustedKeyDirectorySID(sid, serviceSID *windows.SID) bool {
	return sid.Equals(serviceSID) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func validateKeyDirectory(dir string, serviceSID *windows.SID) error {
	unsafeDirectory := func(reason string) error {
		return fmt.Errorf("unsafe dnssec key directory %q: %s; have an administrator review its owner and ACL, removing untrusted write/delete-child/ACL-control grants before retrying; existing directory and sibling ACLs were not changed", dir, reason)
	}
	descriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect dnssec key directory %q owner and ACL (directory and sibling ACLs were not changed): %w", dir, err)
	}
	if !descriptor.IsValid() {
		return unsafeDirectory("invalid security descriptor")
	}
	// Owners can normally rewrite the DACL without an explicit grant. Do not
	// try to prove OWNER RIGHTS exceptions safe or expand group membership.
	// Administrators, SYSTEM, and the service identity are trusted controls;
	// untrusted ancestor owners remain outside this directory boundary.
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trustedKeyDirectorySID(owner, serviceSID) {
		return unsafeDirectory("owner is not the service identity, SYSTEM, or built-in administrators")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return unsafeDirectory("missing or NULL DACL permits unrestricted control")
	}
	// Accept only straightforward allow/deny ACEs. Read, list, traverse, and
	// synchronization grants are harmless; every other untrusted grant is
	// rejected, including generic write/all, DELETE_CHILD, and ACL control.
	// Denials are not used to cancel grants: interpreting ordering, groups,
	// object ACEs, or conditions would require a general access-check engine.
	const readOnly = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE | windows.GENERIC_READ | windows.GENERIC_EXECUTE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return unsafeDirectory(fmt.Sprintf("cannot inspect ACE %d: %v", i, err))
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // Applies to children, not this directory; keys get their own DACL.
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&^uint8(windows.VALID_INHERIT_FLAGS) != 0 {
			return unsafeDirectory(fmt.Sprintf("unsupported object-applicable ACE %d (type %d)", i, ace.Header.AceType))
		}
		const sidOffset = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < sidOffset+8 {
			return unsafeDirectory(fmt.Sprintf("invalid granting ACE %d", i))
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || uintptr(sid.Len()) > uintptr(ace.Header.AceSize)-sidOffset {
			return unsafeDirectory(fmt.Sprintf("invalid trustee in ACE %d", i))
		}
		if !trustedKeyDirectorySID(sid, serviceSID) && ace.Mask&^windows.ACCESS_MASK(readOnly) != 0 {
			return unsafeDirectory(fmt.Sprintf("ACE %d grants control mask %#x to untrusted principal %s", i, ace.Mask, sid.String()))
		}
	}
	return nil
}
