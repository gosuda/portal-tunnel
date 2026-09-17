package policy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBanIPCanonicalizesMappedAndPlainForms protects the invariant that the IP
// filter normalizes IPv4-mapped IPv6 addresses so that banning or unbanning
// either form affects the same canonical address.
func TestBanIPCanonicalizesMappedAndPlainForms(t *testing.T) {
	filter := NewIPFilter()

	filter.BanIP("::ffff:198.51.100.7")

	banned := filter.BannedIPs()
	if len(banned) != 1 || banned[0] != "198.51.100.7" {
		t.Fatalf("BannedIPs() = %v, want single canonical entry [198.51.100.7]", banned)
	}
	if !filter.IsIPBanned("198.51.100.7") || !filter.IsIPBanned("::ffff:198.51.100.7") {
		t.Fatal("IsIPBanned() = false for plain and mapped forms after banning the mapped form")
	}

	filter.UnbanIP("198.51.100.7")
	if filter.IsIPBanned("198.51.100.7") || filter.IsIPBanned("::ffff:198.51.100.7") {
		t.Fatal("plain-form unban did not clear the mapped-form ban")
	}
}

// TestSetBannedIPsDeduplicatesEquivalentForms protects the data-integrity
// invariant that SetBannedIPs() produces exactly one entry per distinct address
// in BannedIPs(), regardless of whether the input mixes plain and mapped forms.
func TestSetBannedIPsDeduplicatesEquivalentForms(t *testing.T) {
	filter := NewIPFilter()

	filter.SetBannedIPs([]string{"198.51.100.7", "::ffff:198.51.100.7", "2001:db8::1"})

	if banned := filter.BannedIPs(); len(banned) != 2 {
		t.Fatalf("BannedIPs() = %v, want the two distinct addresses", banned)
	}
	if !filter.IsIPBanned("2001:db8::1") {
		t.Fatal("IsIPBanned(2001:db8::1) = false")
	}
}

// TestExtractClientIPCanonicalizesMappedRemoteAddr protects the contract that
// ExtractClientIP() returns a canonical dotted-quad address from an IPv4-in-IPv6
// mapped RemoteAddr, so bans and identity registrations use consistent keys.
func TestExtractClientIPCanonicalizesMappedRemoteAddr(t *testing.T) {
	runtime, err := NewRuntime(false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/register", nil)
	request.RemoteAddr = "[::ffff:198.51.100.7]:48392"
	if got := runtime.ExtractClientIP(request); got != "198.51.100.7" {
		t.Fatalf("ExtractClientIP() = %q, want canonical dotted quad", got)
	}
}

// TestInfrastructureBanReason protects the security invariant that loopback and
// configured trusted-proxy addresses return a non-empty infrastructure ban reason,
// while regular client addresses return empty (so they are not auto-banned).
func TestInfrastructureBanReason(t *testing.T) {
	runtime, err := NewRuntime(false, false, true, "203.0.113.9/32")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"::ffff:127.0.0.1", "loopback"},
		{"203.0.113.9", "trusted proxy"},
		{"::ffff:203.0.113.9", "trusted proxy"},
	} {
		reason := runtime.InfrastructureBanReason(tc.ip)
		if reason == "" || !strings.Contains(reason, tc.want) {
			t.Fatalf("InfrastructureBanReason(%q) = %q, want a %q reason", tc.ip, reason, tc.want)
		}
	}
	if reason := runtime.InfrastructureBanReason("198.51.100.7"); reason != "" {
		t.Fatalf("InfrastructureBanReason(regular client) = %q, want empty", reason)
	}

	untrusting, err := NewRuntime(false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if reason := untrusting.InfrastructureBanReason("203.0.113.9"); reason != "" {
		t.Fatalf("InfrastructureBanReason without trust config = %q, want empty (not infrastructure)", reason)
	}
}

// TestIdentitiesForIPCountsDistinctIdentities protects the data-integrity contract
// that IdentitiesForIP() counts distinct identities registered for a given address,
// with a canonicalized (non-mapped) address as the lookup key.
func TestIdentitiesForIPCountsDistinctIdentities(t *testing.T) {
	filter := NewIPFilter()

	filter.RegisterIdentityIP("identity-a", "198.51.100.7")
	if got := filter.IdentitiesForIP("::ffff:198.51.100.7"); got != 1 {
		t.Fatalf("IdentitiesForIP() = %d, want 1 (canonicalized)", got)
	}
	filter.RegisterIdentityIP("identity-b", "198.51.100.7")
	if got := filter.IdentitiesForIP("198.51.100.7"); got != 2 {
		t.Fatalf("IdentitiesForIP() = %d, want 2", got)
	}

	filter.RemoveIdentityIP("identity-a")
	if got := filter.IdentitiesForIP("198.51.100.7"); got != 1 {
		t.Fatalf("IdentitiesForIP() after removal = %d, want 1", got)
	}
}
