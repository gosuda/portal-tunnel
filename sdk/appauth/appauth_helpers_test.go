package appauth

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func portalHeaderNames(h http.Header) []string {
	var names []string
	for key := range h {
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(key, "_", "-")), "x-portal-") {
			names = append(names, key)
		}
	}
	slices.Sort(names)
	return names
}

const identityProofTestValue = "test-proof-0123456789"

func newApplicationAuthTestHandler(t *testing.T, allowed []string, identityHeaders bool, next http.Handler) http.Handler {
	t.Helper()
	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(next, tunnelIdentity, Config{Provider: ProviderSIWE, Allow: allowed, IdentityHeaders: identityHeaders})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func applicationAuthTestIdentity() types.Identity {
	return types.Identity{Name: "application-auth-test", Address: "0x0000000000000000000000000000000000000001", TokenSecret: strings.Repeat("k", 32)}
}

func applicationAuthTestWallet(t *testing.T, digit string) identity.LocalAuthority {
	t.Helper()
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + digit)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Name = "application-auth-test"
	return identity.NewLocalAuthority(resolved)
}

func applicationAuthTestTime() time.Time {
	return time.Now().UTC()
}
