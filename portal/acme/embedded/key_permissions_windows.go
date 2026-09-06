package embedded

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func makeKeyDirectory(dir string) error {
	return os.MkdirAll(dir, 0700)
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

// POSIX mode bits do not restrict access on Windows. Disable inherited grants
// and allow only the service account and SYSTEM to access the private key.
func restrictKeyPermissions(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
