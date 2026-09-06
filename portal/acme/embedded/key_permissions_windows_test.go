package embedded

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func keyPathSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read key path ACL %q: %v", path, err)
	}
	return sd
}

func keyPathSecurityBytes(t *testing.T, path string) []byte {
	t.Helper()
	sd := keyPathSecurity(t, path)
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length())))
}

func requireKeyPathSecurityUnchanged(t *testing.T, before map[string][]byte) {
	t.Helper()
	for path, security := range before {
		if after := keyPathSecurityBytes(t, path); !bytes.Equal(after, security) {
			t.Errorf("changed owner/group/DACL bytes of %q", path)
		}
	}
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

func requireWindowsDNSSEC(t *testing.T, p *Provider) string {
	t.Helper()
	response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := response.Answer[0].(*dns.DNSKEY)
	verifySection(t, key, response.Answer)
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() {
		t.Fatalf("protected key did not expose a usable DNSKEY and DS: %q (%v)", ds, err)
	}
	return ds
}

func TestDNSSECNewKeyDirectoryACL(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid.String()
	parent := t.TempDir()
	// Ancestors are not migrated even when they have unrelated permissive ACLs.
	setKeyTestDACL(t, parent, "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;"+serviceSID+")", true)
	certificate := filepath.Join(parent, "fullchain.pem")
	if err := os.WriteFile(certificate, []byte("operator certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{
		parent:      keyPathSecurityBytes(t, parent),
		certificate: keyPathSecurityBytes(t, certificate),
	}
	createdParent := filepath.Join(parent, "private")
	dir := filepath.Join(createdParent, "keys")
	if err := makeKeyDirectory(dir); err != nil {
		t.Fatal(err)
	}
	// Both newly created directories are protected while still empty of key material.
	for _, path := range []string{createdParent, dir} {
		requirePrivateKeyACL(t, path, serviceSID, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("directory creation published key material: %v (%v)", entries, err)
	}
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	requirePrivateKeyACL(t, path, serviceSID, 0)
	requireWindowsDNSSEC(t, p)
	requireKeyPathSecurityUnchanged(t, before)
}

func TestDNSSECKeyTempFilePrivateAtCreation(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid.String()
	dir := t.TempDir()
	// Read/traverse applies to the directory; inherited full control applies
	// only to children. A plain os.CreateTemp would start with Everyone access.
	setKeyTestDACL(t, dir, "D:P(A;OICI;FRFX;;;WD)(A;OICIIO;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;"+serviceSID+")", true)
	before := map[string][]byte{dir: keyPathSecurityBytes(t, dir)}
	if err := makeKeyDirectory(dir); err != nil {
		t.Fatal(err)
	}
	f, err := createKeyTempFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	// Inspect before restrictKeyPermissions and before any material is written.
	requirePrivateKeyACL(t, f.Name(), serviceSID, 0)
	if info, err := f.Stat(); err != nil || info.Size() != 0 {
		t.Fatalf("temporary file was not empty at creation: %v", err)
	}
	if _, err := f.WriteString("private material\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(f.Name()); err != nil || string(data) != "private material\n" {
		t.Fatalf("private temporary file lost writable contents: %v", err)
	}
	requireKeyPathSecurityUnchanged(t, before)
}

func TestDNSSECExistingKeyDirectoryPreservesOperatorACLs(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid.String()
	trusted := "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + serviceSID + ")"
	for _, test := range []struct {
		name      string
		directory string
		inherited bool
	}{
		{"inherited operator read and traverse", "", true},
		{"inherit-only control does not apply to directory", "D:P(A;OICI;FRFX;;;BU)(A;OICIIO;FA;;;WD)" + trusted, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			setKeyTestDACL(t, parent, "D:P(A;OICI;FRFX;;;BU)"+trusted, true)
			dir := filepath.Join(parent, "identity")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if !test.inherited {
				setKeyTestDACL(t, dir, test.directory, true)
			}
			before := map[string][]byte{
				parent: keyPathSecurityBytes(t, parent),
				dir:    keyPathSecurityBytes(t, dir),
			}
			for _, name := range []string{"fullchain.pem", "account.json"} {
				sibling := filepath.Join(dir, name)
				if err := os.WriteFile(sibling, []byte("existing operator material\n"), 0600); err != nil {
					t.Fatal(err)
				}
				before[sibling] = keyPathSecurityBytes(t, sibling)
			}
			path := filepath.Join(dir, types.DNSSECKeyFileName)
			first := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
			ds := requireWindowsDNSSEC(t, first)
			requirePrivateKeyACL(t, path, serviceSID, 0)
			requireKeyPathSecurityUnchanged(t, before)
			key, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.Stop(); err != nil {
				t.Fatal(err)
			}
			second := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
			if recovered := requireWindowsDNSSEC(t, second); recovered != ds {
				t.Fatalf("safe existing directory changed DS: %q => %q", ds, recovered)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, key) {
				t.Fatalf("safe existing directory replaced key bytes: %v", err)
			}
			requirePrivateKeyACL(t, path, serviceSID, 0)
			requireKeyPathSecurityUnchanged(t, before)
			for _, name := range []string{"fullchain.pem", "account.json"} {
				if data, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(data) != "existing operator material\n" {
					t.Fatalf("changed or made sibling %q unreadable: %v", name, err)
				}
			}
		})
	}
}

type sharedKeyDirectoryFixture struct {
	parent      string
	dir         string
	certificate string
	path        string
	serviceSID  string
	trusted     string
}

func newSharedKeyDirectoryFixture(t *testing.T) sharedKeyDirectoryFixture {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	f := sharedKeyDirectoryFixture{parent: t.TempDir(), serviceSID: user.User.Sid.String()}
	f.trusted = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + f.serviceSID + ")"
	setKeyTestDACL(t, f.parent, "D:P(A;OICI;FRFX;;;BU)"+f.trusted, true)
	f.dir = filepath.Join(f.parent, "identity")
	if err := os.Mkdir(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.certificate = filepath.Join(f.dir, "fullchain.pem")
	if err := os.WriteFile(f.certificate, []byte("operator certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.path = filepath.Join(f.dir, types.DNSSECKeyFileName)
	return f
}

func (f sharedKeyDirectoryFixture) grantUnsafeInheritedControl(t *testing.T, rights string) {
	t.Helper()
	// An operator changed the parent policy. Its unsafe grant applies to
	// the shared directory, but not to an already protected key.
	setKeyTestDACL(t, f.parent, "D:P(A;OICI;"+rights+";;;WD)"+f.trusted, true)
	sd := keyPathSecurity(t, f.dir)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read inherited ACL fixture: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags&windows.INHERITED_ACE != 0 && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 && (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() == "S-1-1-0" {
			return
		}
	}
	t.Fatalf("fixture lacks object-applicable inherited Everyone grant: %s", sd)
}

func (f sharedKeyDirectoryFixture) sharedSecurity(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		f.parent:      keyPathSecurityBytes(t, f.parent),
		f.dir:         keyPathSecurityBytes(t, f.dir),
		f.certificate: keyPathSecurityBytes(t, f.certificate),
	}
}

func (f sharedKeyDirectoryFixture) requireRejectedUnchanged(t *testing.T, before map[string][]byte, wantEntries int) {
	t.Helper()
	p, err := New(Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: f.path})
	if p != nil {
		_ = p.Stop()
		t.Fatal("exposed a provider from an unsafe shared directory")
	}
	if err == nil || !strings.Contains(err.Error(), "unsafe dnssec key directory") || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("expected actionable unsafe-directory failure: %v", err)
	}
	requireKeyPathSecurityUnchanged(t, before)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != wantEntries {
		t.Fatalf("rejection changed directory entries: %v", entries)
	}
	if data, err := os.ReadFile(f.certificate); err != nil || string(data) != "operator certificate\n" {
		t.Fatalf("rejection changed certificate contents: %v", err)
	}
}

func TestDNSSECUnsafeExistingDirectoryRejectedUnchanged(t *testing.T) {
	for _, rights := range []string{"FW", "0x40", "WD", "WO", "SD", "GW", "GA"} {
		t.Run(rights+"/new key", func(t *testing.T) {
			f := newSharedKeyDirectoryFixture(t)
			f.grantUnsafeInheritedControl(t, rights)
			before := f.sharedSecurity(t)
			f.requireRejectedUnchanged(t, before, 1)
			if _, err := os.Stat(f.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejection published a key: %v", err)
			}

			// Only the operator repairs shared storage. Creation must preserve
			// those repaired permissions and leave the new key protected.
			setKeyTestDACL(t, f.parent, "D:P(A;OICI;FRFX;;;BU)"+f.trusted, true)
			before = f.sharedSecurity(t)
			recovered := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = f.path })
			requireWindowsDNSSEC(t, recovered)
			requirePrivateKeyACL(t, f.path, f.serviceSID, 0)
			requireKeyPathSecurityUnchanged(t, before)
		})

		t.Run(rights+"/existing key", func(t *testing.T) {
			f := newSharedKeyDirectoryFixture(t)
			first := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = f.path })
			ds := requireWindowsDNSSEC(t, first)
			if err := first.Stop(); err != nil {
				t.Fatal(err)
			}
			key, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			f.grantUnsafeInheritedControl(t, rights)
			before := f.sharedSecurity(t)
			before[f.path] = keyPathSecurityBytes(t, f.path)
			f.requireRejectedUnchanged(t, before, 2)
			if after, err := os.ReadFile(f.path); err != nil || !bytes.Equal(after, key) {
				t.Fatalf("rejection modified the existing key: %v", err)
			}

			// Recovery after explicit operator repair must retain the published
			// key and DS without rewriting either key or shared-storage ACLs.
			setKeyTestDACL(t, f.parent, "D:P(A;OICI;FRFX;;;BU)"+f.trusted, true)
			before = f.sharedSecurity(t)
			before[f.path] = keyPathSecurityBytes(t, f.path)
			recovered := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = f.path })
			if recoveredDS := requireWindowsDNSSEC(t, recovered); recoveredDS != ds {
				t.Fatalf("recovery rotated DS: %q => %q", ds, recoveredDS)
			}
			if after, err := os.ReadFile(f.path); err != nil || !bytes.Equal(after, key) {
				t.Fatalf("recovery replaced existing key bytes: %v", err)
			}
			requirePrivateKeyACL(t, f.path, f.serviceSID, 0)
			requireKeyPathSecurityUnchanged(t, before)
		})
	}
}

func TestDNSSECUninterpretableDirectoryACLRejectedUnchanged(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	trusted := "(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")"
	for _, test := range []struct {
		name string
		sddl string
	}{
		{"NULL DACL", "D:NO_ACCESS_CONTROL"},
		{"conditional grant", "D:P" + trusted + "(XA;;FA;;;WD;(@User.department == \"dns\"))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			certificate := filepath.Join(dir, "fullchain.pem")
			if err := os.WriteFile(certificate, []byte("operator certificate\n"), 0600); err != nil {
				t.Fatal(err)
			}
			setKeyTestDACL(t, dir, test.sddl, true)
			before := map[string][]byte{
				dir:         keyPathSecurityBytes(t, dir),
				certificate: keyPathSecurityBytes(t, certificate),
			}
			if err := makeKeyDirectory(dir); err == nil || !strings.Contains(err.Error(), "unsafe dnssec key directory") {
				t.Fatalf("accepted an uninterpretable granting policy: %v", err)
			}
			requireKeyPathSecurityUnchanged(t, before)
		})
	}
}
