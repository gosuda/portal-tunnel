package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The command builder in frontend/src/lib/tunnelCommand.ts repeats the rules
// below, because the browser cannot call Go. Both languages run the same rows,
// so a change on one side that the other does not follow fails a test here or in
// the frontend.
func loadFrontendFile(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "frontend", "src", "lib", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type frontendAuthRules struct {
	Allow []struct {
		Method    string `json:"method"`
		Typed     string `json:"typed"`
		Valid     bool   `json:"valid"`
		Canonical string `json:"canonical"`
	} `json:"allow"`
	Issuer []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"issuer"`
	Host []struct {
		Address string `json:"address"`
		Host    string `json:"host"`
	} `json:"host"`
}

func TestFrontendAuthRulesMatchTheGateway(t *testing.T) {
	t.Parallel()

	var rules frontendAuthRules
	loadFrontendFile(t, "authRuleVectors.json", &rules)
	if len(rules.Allow) == 0 || len(rules.Issuer) == 0 || len(rules.Host) == 0 {
		t.Fatalf("authRuleVectors.json has %d allow, %d issuer and %d host rows; want all three", len(rules.Allow), len(rules.Issuer), len(rules.Host))
	}

	t.Run("allowlist entries", func(t *testing.T) {
		t.Parallel()
		for _, row := range rules.Allow {
			got, err := NormalizeApplicationAuthAllowed(row.Method, []string{row.Typed})
			if (err == nil) != row.Valid {
				t.Errorf("%s entry %q: error = %v; the frontend says valid = %v", row.Method, row.Typed, err, row.Valid)
				continue
			}
			comparesForm := row.Valid && row.Canonical != ""
			if comparesForm && (len(got) != 1 || got[0] != row.Canonical) {
				t.Errorf("%s entry %q normalizes to %q; the frontend says %q", row.Method, row.Typed, got, row.Canonical)
			}
		}
	})

	t.Run("OIDC issuers", func(t *testing.T) {
		t.Parallel()
		for _, row := range rules.Issuer {
			err := ValidateApplicationAuthConfig(ApplicationAuthConfig{
				Provider:       ApplicationAuthProviderOIDC,
				AllowedWallets: []string{"alice@example.com"},
				OIDCIssuerURL:  row.Value,
				OIDCClientID:   "client",
			})
			if (err == nil) != row.Valid {
				t.Errorf("issuer %q: error = %v; the frontend says valid = %v", row.Value, err, row.Valid)
			}
		}
	})

	t.Run("hosts of a private link", func(t *testing.T) {
		t.Parallel()
		for _, row := range rules.Host {
			got, err := NormalizeApplicationAuthHost(row.Address)
			if row.Host == "" {
				if err == nil {
					t.Errorf("address %q is accepted as %q; the frontend says it is unusable", row.Address, got)
				}
				continue
			}
			if err != nil || got != row.Host {
				t.Errorf("address %q = %q, %v; the frontend says %q", row.Address, got, err, row.Host)
			}
		}
	})
}
