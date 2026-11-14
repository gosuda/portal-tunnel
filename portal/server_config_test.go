package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
)

func TestTenantIssuanceStartupRequiresUsableState(t *testing.T) {
	stateDir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	blockedJournal := t.TempDir()
	if err := os.Mkdir(filepath.Join(blockedJournal, "tenant-orders.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, portalURL, directory string
		enabled, wantError         bool
	}{
		{"missing setting", "https://example.com", "", true, true},
		{"missing directory", "https://example.com", filepath.Join(stateDir, "missing"), true, true},
		{"not a directory", "https://example.com", filePath, true, true},
		{"unusable journal", "https://example.com", blockedJournal, true, true},
		{"usable directory", "https://example.com", stateDir, true, false},
		{"disabled", "https://example.com", "", false, false},
		{"local issuance", "https://localhost", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateServerConfig(ServerConfig{
				PortalURL: tc.portalURL, StateDir: t.TempDir(),
				TenantCertificates: tc.enabled,
				ACME:               acme.Config{TenantIssuanceStateDir: tc.directory},
			})
			if (err != nil) != tc.wantError {
				t.Fatalf("ValidateServerConfig() error = %v, want error %v", err, tc.wantError)
			}
			if err != nil && !strings.Contains(err.Error(), "TENANT_ISSUANCE_STATE_DIR") {
				t.Fatalf("startup error does not identify the setting: %v", err)
			}
		})
	}
}
