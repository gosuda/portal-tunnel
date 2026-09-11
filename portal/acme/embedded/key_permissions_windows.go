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
	return createPrivateKeyDirectories(filepath.Clean(dir), &attributes)
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
		// A concurrent creator owns this directory. Leave its ACL unchanged.
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
