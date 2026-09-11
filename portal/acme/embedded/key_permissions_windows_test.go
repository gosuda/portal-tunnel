package embedded

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func requirePrivateKeyACL(t *testing.T, path, serviceSID string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("key path %q inherits its parent ACL: %s", path, sd)
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
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			t.Fatalf("key path %q has an unexpected ACE: %s", path, sd)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		switch sid {
		case serviceSID:
			serviceAccess |= ace.Mask
		case "S-1-5-18":
			systemAccess |= ace.Mask
		default:
			t.Fatalf("key path %q grants another principal access: %s", path, sd)
		}
	}
	if serviceAccess&fileAllAccess != fileAllAccess || systemAccess&fileAllAccess != fileAllAccess {
		t.Fatalf("key path %q lost service or SYSTEM rights: %s", path, sd)
	}
}

func TestDNSSECNewKeyPathsArePrivate(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid.String()
	parent := t.TempDir()
	dir := filepath.Join(parent, "dnssec")
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	requirePrivateKeyACL(t, path, serviceSID)
}
