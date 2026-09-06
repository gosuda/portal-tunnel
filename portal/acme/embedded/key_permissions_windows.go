package embedded

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func makeKeyDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// An inherited directory DELETE_CHILD grant can bypass the key-file DACL.
	// Protect the actual key directory before creating any key files;
	// leave ancestors untouched, since they may hold unrelated application data.
	// Administrators and untrusted ancestor owners remain outside this boundary.
	return restrictKeyACL(dir, "")
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
	// Existing keys bypass makeKeyDirectory. Protect their containing directory
	// too, before reading the key or exposing its DNSKEY and DS.
	return restrictKeyACL(filepath.Dir(path), path)
}

// POSIX mode bits do not restrict access on Windows. Both DACLs exclude parent
// grants and allow only the service account and SYSTEM. Directory ACEs must
// propagate to children so existing inherited certificate files remain usable;
// the protected key-file DACL retains its non-inheritable ACEs.
func restrictKeyACL(dir, key string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	serviceSID := user.User.Sid.String()
	for _, target := range [...]struct {
		path        string
		inheritance string
	}{
		{dir, "OICI"},
		{key, ""},
	} {
		if target.path == "" {
			continue
		}
		descriptor, err := windows.SecurityDescriptorFromString("D:P(A;" + target.inheritance + ";FA;;;SY)(A;" + target.inheritance + ";FA;;;" + serviceSID + ")")
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		if err := windows.SetNamedSecurityInfo(target.path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return fmt.Errorf("restrict dnssec key path %q permissions: %w", target.path, err)
		}
	}
	return nil
}
