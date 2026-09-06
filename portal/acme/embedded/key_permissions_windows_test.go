package embedded

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func keyPathSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read key path ACL %q: %v", path, err)
	}
	return sd
}

func setKeyTestDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	flags := windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	if protected {
		flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(flags), nil, nil, dacl, nil); err != nil {
		t.Fatalf("set test ACL %q: %v", path, err)
	}
}

func requirePrivateKeyACL(t *testing.T, path, serviceSID string, inheritance uint8) {
	t.Helper()
	sd := keyPathSecurity(t, path)
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("key path %q still inherits its parent ACL: %s", path, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("key path %q has no restricting DACL: %v", path, err)
	}
	// FILE_ALL_ACCESS includes FILE_DELETE_CHILD (0x40), creation, traversal,
	// read/write, deletion and ACL-management rights for these two identities.
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	var serviceAccess, systemAccess windows.ACCESS_MASK
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != inheritance {
			t.Fatalf("key path %q has an unexpected or inherited ACE: %s", path, sd)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != serviceSID && sid != "S-1-5-18" {
			t.Fatalf("key path %q grants another principal access: %s", path, sd)
		}
		if sid == serviceSID {
			serviceAccess |= ace.Mask
		}
		if sid == "S-1-5-18" {
			systemAccess |= ace.Mask
		}
	}
	if serviceAccess&fileAllAccess != fileAllAccess || systemAccess&fileAllAccess != fileAllAccess {
		t.Fatalf("key path %q lost service or SYSTEM rights: %s", path, sd)
	}
}

func TestDNSSECKeyDirectoryACL(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid.String()
	for _, state := range []string{"new directory", "existing directory", "existing key"} {
		t.Run(state, func(t *testing.T) {
			parent := t.TempDir()
			// The unrelated parent deliberately grants inheritable Everyone full
			// control, including DELETE_CHILD, which bypasses a child's file ACL.
			setKeyTestDACL(t, parent, "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;"+serviceSID+")", true)
			parentBefore := keyPathSecurity(t, parent).String()
			dir := filepath.Join(parent, "keys")
			path := filepath.Join(dir, types.DNSSECKeyFileName)
			cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
			var before []byte
			if state != "new directory" {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if state == "existing key" {
					first, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					if err := first.Stop(); err != nil {
						t.Fatal(err)
					}
					before, err = os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					// Model a persisted protected key inside a directory whose
					// inherited grants must be repaired on the existing-key path.
					setKeyTestDACL(t, dir, "D:", false)
				}
				sd := keyPathSecurity(t, dir)
				dacl, _, err := sd.DACL()
				if err != nil || dacl == nil {
					t.Fatalf("read inherited test ACL: %v", err)
				}
				inheritedDeleteChild := false
				for i := uint32(0); i < uint32(dacl.AceCount); i++ {
					var ace *windows.ACCESS_ALLOWED_ACE
					if err := windows.GetAce(dacl, i, &ace); err != nil {
						t.Fatal(err)
					}
					if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags&windows.INHERITED_ACE != 0 && ace.Mask&0x40 != 0 && (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() == "S-1-1-0" {
						inheritedDeleteChild = true
					}
				}
				if !inheritedDeleteChild {
					t.Fatalf("fixture lacks inherited Everyone DELETE_CHILD: %s", sd)
				}
			}

			p := newTestProvider(t, func(c *Config) { c.KeyPath = path })
			requirePrivateKeyACL(t, dir, serviceSID, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE)
			requirePrivateKeyACL(t, path, serviceSID, 0)
			if after := keyPathSecurity(t, parent).String(); after != parentBefore {
				t.Fatalf("changed unrelated parent ACL: %s => %s", parentBefore, after)
			}
			if before != nil {
				if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
					t.Fatalf("replaced existing key while securing its directory: %v", err)
				}
			}
			response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
			key := response.Answer[0].(*dns.DNSKEY)
			verifySection(t, key, response.Answer)
			_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
			if err != nil || ds != key.ToDS(dns.SHA256).String() {
				t.Fatalf("secured key did not expose a usable DNSKEY and DS: %q (%v)", ds, err)
			}
		})
	}
}

func TestDNSSECKeyDirectoryPreservesInheritedCertificate(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	setKeyTestDACL(t, parent, "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;"+user.User.Sid.String()+")", true)
	dir := filepath.Join(parent, "certs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(dir, "fullchain.pem")
	certificate := []byte("preexisting certificate contents\n")
	if err := os.WriteFile(certificatePath, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	// This sibling relies entirely on inherited grants. Replacing the
	// directory DACL without OI/CI would strip all of its usable access.
	sd := keyPathSecurity(t, certificatePath)
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatalf("certificate fixture does not inherit its directory ACL: %s", sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("certificate fixture has no inherited grants: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			t.Fatalf("certificate fixture has an explicit grant: %s", sd)
		}
	}

	path := filepath.Join(dir, types.DNSSECKeyFileName)
	first := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	if data, err := os.ReadFile(certificatePath); err != nil || !bytes.Equal(data, certificate) {
		t.Fatalf("new-key hardening made the inherited certificate unreadable or changed its contents: %v", err)
	}
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}

	// Restore permissive parent inheritance while retaining the protected key.
	// Existing-key initialization must also preserve the sibling's access.
	setKeyTestDACL(t, dir, "D:", false)
	newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	if data, err := os.ReadFile(certificatePath); err != nil || !bytes.Equal(data, certificate) {
		t.Fatalf("existing-key hardening made the inherited certificate unreadable or changed its contents: %v", err)
	}
}

func denyKeyDirectoryACLChanges(t *testing.T, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	original := keyPathSecurity(t, dir)
	dacl, _, err := original.DACL()
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := original.Control()
	if err != nil {
		t.Fatal(err)
	}
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve a real WRITE_DAC handle before revoking future opens;
	// Windows access checks do not revoke rights on an existing handle.
	handle, err := windows.CreateFile(dirPtr, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		flags := windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		if control&windows.SE_DACL_PROTECTED != 0 {
			flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(flags), nil, nil, dacl, nil); err != nil {
			t.Errorf("restore directory ACL: %v", err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close directory ACL handle: %v", err)
		}
	})
	// OWNER RIGHTS removes the owner's implicit WRITE_DAC; Everyone's
	// explicit denial also covers tokens whose owner is a group. All
	// creation/read/write rights remain, isolating the ACL-hardening error.
	setKeyTestDACL(t, dir, "D:P(D;;WD;;;OW)(D;;WD;;;WD)(A;;FA;;;SY)(A;;FA;;;"+user.User.Sid.String()+")", true)
}

func TestDNSSECKeyDirectoryACLFailure(t *testing.T) {
	t.Run("new key", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, types.DNSSECKeyFileName)
		cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
		denyKeyDirectoryACLChanges(t, dir)

		p, err := New(cfg)
		if p != nil {
			_ = p.Stop()
			t.Fatal("exposed a provider despite directory ACL failure")
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("expected directory WRITE_DAC failure: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("created key material before securing its directory: %v", entries)
		}
	})

	t.Run("existing key", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, types.DNSSECKeyFileName)
		cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
		first, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Stop(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		denyKeyDirectoryACLChanges(t, dir)

		p, err := New(cfg)
		if p != nil {
			_ = p.Stop()
			t.Fatal("exposed a provider despite directory ACL failure")
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("expected directory WRITE_DAC failure: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != types.DNSSECKeyFileName {
			t.Fatalf("ACL failure changed key directory entries: %v", entries)
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
			t.Fatalf("ACL failure modified the existing key: %v", err)
		}
	})
}
