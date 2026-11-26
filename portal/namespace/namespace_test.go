package namespace

import (
	"cmp"
	"strings"
	"testing"
)

func TestAliasHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		root    string
		want    string
		wantErr bool
	}{
		{name: "composes child hostname", raw: "demo", root: "example.com", want: "demo.example.com"},
		{name: "normalizes name and root", raw: "My App", root: "Example.COM.", want: "my-app.example.com"},
		{name: "rejects empty name", raw: "", root: "example.com", wantErr: true},
		{name: "rejects punctuation-only name", raw: "!!!", root: "example.com", wantErr: true},
		{name: "rejects over-long name", raw: strings.Repeat("a", 64), root: "example.com", wantErr: true},
		{name: "rejects empty root host", raw: "demo", root: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.wantErr {
				rejectInvalidLeaseHostname(t, tt.raw, tt.root)
				return
			}
			checkComposedLeaseHostname(t, tt.raw, tt.root, tt.want)
		})
	}
}

func checkComposedLeaseHostname(t *testing.T, raw, root, want string) {
	t.Helper()
	got, err := AliasHostname(raw, root)
	if err != nil {
		t.Fatalf("AliasHostname(%q, %q) error = %v", raw, root, err)
	}
	if got != want {
		t.Fatalf("AliasHostname(%q, %q) = %q, want %q", raw, root, got, want)
	}
}

func rejectInvalidLeaseHostname(t *testing.T, raw, root string) {
	t.Helper()
	if _, err := AliasHostname(raw, root); err == nil {
		t.Fatalf("AliasHostname(%q, %q) error = nil, want invalid label error", raw, root)
	}
}

func TestServiceNamesCannotTakeCanonicalLabels(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", "x-7A3B2C4D5E6F708192A3B4C5D6E7F8091A2B3C4D"} {
		if _, err := NormalizeServiceName(name); err == nil {
			t.Fatalf("NormalizeServiceName(%q) error = nil", name)
		}
	}
	for _, name := range []string{"myapp", "deadbeef", "my-app-" + strings.Repeat("f", 39), strings.Repeat("f", 41)} {
		if _, err := NormalizeServiceName(name); err != nil {
			t.Fatalf("NormalizeServiceName(%q) error = %v", name, err)
		}
	}
}

func TestCanonicalAddressIgnoresCasePortAndTrailingDot(t *testing.T) {
	t.Parallel()

	const address = "0x1234567890abcdef1234567890abcdef12345678"
	for _, hostname := range []string{
		"default.1234567890abcdef1234567890abcdef12345678.relay.example",
		"demo.1234567890ABCDEF1234567890abcdef12345678.Relay.Example.:8443",
		"myapp.1234567890abcdef1234567890abcdef12345678.relay.example",
	} {
		if got, err := CanonicalAddress(hostname); err != nil || got != address {
			t.Errorf("CanonicalAddress(%q) = %q, %v; want %q", hostname, got, err, address)
		}
	}
	if _, err := CanonicalAddress("myapp.relay.example"); err == nil {
		t.Error("CanonicalAddress accepted a friendly name that embeds no address")
	}
}

func TestLocalTLSNamespace(t *testing.T) {
	address := strings.Repeat("a", 40)
	for _, root := range []string{"example.com", "relay.delegated.example.com", "localhost"} {
		for _, name := range []string{"", "blog", strings.Repeat("x", 63)} {
			host, err := LocalTLSHostname(name, "0x"+address, root)
			if err != nil {
				t.Fatal(err)
			}
			label := cmp.Or(name, "default")
			if host != label+"."+address+"."+root || !IsLocalTLSHostname(host, root) {
				t.Fatalf("unexpected host %q", host)
			}
			if got, err := CanonicalAddress(host); err != nil || got != "0x"+address {
				t.Fatalf("extract %q: %q, %v", host, got, err)
			}
			for _, invalid := range []string{"extra." + host, label + "." + root, address + "." + root, label + ".0x" + address + "." + root, label + "." + address + ".other." + root} {
				if IsLocalTLSHostname(invalid, root) {
					t.Fatalf("accepted noncanonical %q under %q", invalid, root)
				}
			}
		}
	}
	if _, err := LocalTLSHostname("DEFAULT", address, "example.com"); err == nil {
		t.Fatal("explicit reserved name accepted")
	}

}

func TestCanonicalAddressWithHexadecimalRelayRoot(t *testing.T) {
	owner := "0x" + strings.Repeat("a", 40)
	root := strings.Repeat("b", 40) + ".delegated.example.com"
	for _, name := range []string{"", "blog", strings.Repeat("x", 63)} {
		for _, derive := range []func(string, string, string) (string, error){LocalTLSHostname} {
			host, err := derive(name, owner, root)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := CanonicalAddress(host); err != nil || got != owner {
				t.Fatalf("extract %q = %q, %v; want %q", host, got, err, owner)
			}
		}
	}
	for _, service := range []string{strings.Repeat("a", 40), "blog-" + strings.Repeat("a", 40)} {
		host := service + "." + strings.Repeat("b", 40) + "." + root
		if IsLocalTLSHostname(host, root) {
			t.Fatalf("ambiguous legacy-shaped service accepted: %q", host)
		}
	}
}

func TestMatchesAlias(t *testing.T) {
	t.Parallel()

	const root = "relay.example"
	automatic := NewUnnamedAlias() + ".relay.example"
	tests := []struct {
		name, hostname, service string
		want                    bool
	}{
		{"no alias", "", "demo", true},
		{"own alias", "demo.relay.example", "demo", true},
		{"normalized name", "demo.relay.example", "Demo", true},
		{"other name", "other.relay.example", "demo", false},
		{"other root", "demo.other.example", "demo", false},
		{"unnamed service on a chosen name", "demo.relay.example", "", false},
		{"unnamed service on an automatic alias", automatic, "", true},
		{"automatic alias under another root", strings.TrimSuffix(automatic, root) + "other.example", "", false},
		{"named service on an automatic alias", automatic, "demo", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchesAlias(tc.hostname, tc.service, root); got != tc.want {
				t.Fatalf("MatchesAlias(%q, %q) = %v, want %v", tc.hostname, tc.service, got, tc.want)
			}
		})
	}
}

// TestUnnamedAlias protects the automatic alias contract: a short readable
// label with an 80-bit random suffix, no identity data, never claimable as a
// chosen name, and never a Local TLS hostname.
func TestUnnamedAlias(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{})
	for range 1000 {
		label := NewUnnamedAlias()
		if len(label) > 40 {
			t.Fatalf("automatic alias %q is %d characters, want a short label", label, len(label))
		}
		hostname, err := UnnamedAliasHostname(label, "relay.example")
		if err != nil || hostname != label+".relay.example" {
			t.Fatalf("UnnamedAliasHostname(%q) = %q, %v", label, hostname, err)
		}
		if _, err := NormalizeServiceName(label); err == nil {
			t.Fatalf("service name %q may claim an automatic alias", label)
		}
		if IsLocalTLSHostname(hostname, "relay.example") {
			t.Fatalf("automatic alias %q is classified as a Local TLS canonical", hostname)
		}
		if _, dup := seen[label]; dup {
			t.Fatalf("automatic alias %q repeated", label)
		}
		seen[label] = struct{}{}
	}
	for _, label := range []string{
		"demo",
		"sunny-otter-short",
		"sunny-otter-k7m2q6rt3vx5z4a0", // 0 is not base32.
		"Sunny-otter-k7m2q6rt3vx5z4ab",
		"-k7m2q6rt3vx5z4ab",
		"k7m2q6rt3vx5z4ab",
		"demo-" + strings.Repeat("a", 40),
	} {
		if _, err := UnnamedAliasHostname(label, "relay.example"); err == nil {
			t.Fatalf("UnnamedAliasHostname(%q) accepted a label that is not an automatic alias", label)
		}
	}
}
