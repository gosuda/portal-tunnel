package namespace

import (
	"cmp"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestLegacyHostnamePreservesAddressDecodeError(t *testing.T) {
	_, err := LegacyHostname("demo", "0x"+strings.Repeat("z", 40), "example.com")
	var invalidByte hex.InvalidByteError
	if !errors.As(err, &invalidByte) || invalidByte != 'z' {
		t.Fatalf("LegacyHostname() error = %v, want wrapped hex error", err)
	}
}

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

func TestLegacyHostname(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	checkCanonicalBasicName(t, address)
	checkCanonicalMaxLabel(t, address)
	checkCanonicalUnnamedName(t, address)
	const addr = "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
	for name, label := range map[string]string{
		strings.Repeat("a", 23):                 "5e2twslnrzki2h4l7bzvq--" + addr,
		"internal-metrics-dashboard-production": "okm4rhbie4a4gidozw5r5--" + addr,
		strings.Repeat("a", 63):                 "c7pboclanhxavtsfp7efc--" + addr,
	} {
		checkCanonicalHashedName(t, address, name, label)
	}
	for _, name := range []string{
		strings.Repeat("a", 64),
		addr,
		"myapp-" + addr,
		"5e2twslnrzki2h4l7bzvq--" + addr,
	} {
		rejectCanonicalBadName(t, address, name)
	}
	rejectCanonicalShortAddress(t)
}

func checkCanonicalBasicName(t *testing.T, address string) {
	t.Helper()
	want := "herdr-7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com"
	got, err := LegacyHostname("Herdr", address, "Example.COM.")
	if err != nil {
		t.Fatalf("LegacyHostname() error = %v", err)
	}
	if got != want {
		t.Fatalf("LegacyHostname() = %q, want %q", got, want)
	}
}

func checkCanonicalMaxLabel(t *testing.T, address string) {
	t.Helper()
	maxName := strings.Repeat("a", 22)
	got, err := LegacyHostname(maxName, address, "example.com")
	if err != nil {
		t.Fatalf("LegacyHostname(maximum name) error = %v", err)
	}
	if label := strings.SplitN(got, ".", 2)[0]; len(label) != 63 {
		t.Fatalf("canonical label length = %d, want 63", len(label))
	}
}

func checkCanonicalUnnamedName(t *testing.T, address string) {
	t.Helper()
	unnamedWant := "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com"
	got, err := LegacyHostname("", address, "Example.COM.")
	if err != nil {
		t.Fatalf("LegacyHostname(empty name) error = %v", err)
	}
	if got != unnamedWant {
		t.Fatalf("LegacyHostname(empty name) = %q, want %q", got, unnamedWant)
	}
}

func checkCanonicalHashedName(t *testing.T, address, name, label string) {
	t.Helper()
	got, err := LegacyHostname(name, address, "example.com")
	if err != nil {
		t.Fatalf("LegacyHostname(%d-character name) error = %v", len(name), err)
	}
	if got != label+".example.com" {
		t.Fatalf("LegacyHostname(%q) = %q, want %q", name, got, label+".example.com")
	}
}

func rejectCanonicalBadName(t *testing.T, address, name string) {
	t.Helper()
	if _, err := LegacyHostname(name, address, "example.com"); err == nil {
		t.Fatalf("LegacyHostname(%q) error = nil", name)
	}
}

func rejectCanonicalShortAddress(t *testing.T) {
	t.Helper()
	if _, err := LegacyHostname("herdr", "0x1234", "example.com"); err == nil {
		t.Fatal("LegacyHostname(short address) error = nil")
	}
}

func TestServiceNamesCannotTakeCanonicalLabels(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	long, err := LegacyHostname("internal-metrics-dashboard-production", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	hash, _, _ := strings.Cut(long, "--")
	for _, short := range []string{hash, hash + "-", hash + "-k"} {
		got, err := LegacyHostname(short, address, "example.com")
		if err == nil && got == long {
			t.Fatalf("short name %q took the long name's canonical hostname %q", short, long)
		}
	}
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

func TestLegacyHostnameNormalizesFirst(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	fullwidth := strings.Map(func(r rune) rune { return r + 0xFEE0 }, "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d")
	if _, err := NormalizeServiceName(fullwidth); err == nil {
		t.Fatalf("NormalizeServiceName(fullwidth address) error = nil")
	}

	unicode, err := LegacyHostname("bücher-abcdefghij", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ascii, err := LegacyHostname("xn--bcher-abcdefghij-jzb", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if unicode != ascii || !strings.HasSuffix(unicode, "--7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com") {
		t.Fatalf("canonical hostnames = (%q, %q), want the same hashed form", unicode, ascii)
	}
}

func TestLegacyHostnameKeepsServiceIdentityAcrossRelays(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	relayA, err := LegacyHostname("herdr", address, "relay-a.example")
	if err != nil {
		t.Fatal(err)
	}
	relayB, err := LegacyHostname("herdr", address, "relay-b.example")
	if err != nil {
		t.Fatal(err)
	}
	labelA, _, _ := strings.Cut(relayA, ".")
	labelB, _, _ := strings.Cut(relayB, ".")
	if labelA != labelB || relayA == relayB {
		t.Fatalf("relay canonical hostnames = (%q, %q), want the same service label under different relay origins", relayA, relayB)
	}
}

func TestCanonicalAddressIgnoresCasePortAndTrailingDot(t *testing.T) {
	t.Parallel()

	const address = "0x1234567890abcdef1234567890abcdef12345678"
	for _, hostname := range []string{
		"1234567890abcdef1234567890abcdef12345678.relay.example",
		"1234567890ABCDEF1234567890abcdef12345678.Relay.Example.:8443",
		"myapp-1234567890abcdef1234567890abcdef12345678.relay.example",
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
			parent := AddressParent(host)
			if parent != address+"."+root || !IsAddressHostname(parent, root) || IsAddressHostname(host, root) {
				t.Fatalf("unexpected address parent %q for %q", parent, host)
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
	if _, err := LegacyHostname("default", address, "example.com"); err != nil {
		t.Fatal("legacy default rejected", err)
	}
}

func TestCanonicalAddressWithHexadecimalRelayRoot(t *testing.T) {
	owner := "0x" + strings.Repeat("a", 40)
	root := strings.Repeat("b", 40) + ".delegated.example.com"
	for _, name := range []string{"", "blog", strings.Repeat("x", 63)} {
		for _, derive := range []func(string, string, string) (string, error){LegacyHostname, LocalTLSHostname} {
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

	const canonical = "demo-0123456789abcdef0123456789abcdef01234567.relay.example"
	tests := []struct {
		name, hostname, service string
		want                    bool
	}{
		{"no alias", "", "demo", true},
		{"own alias", "demo.relay.example", "demo", true},
		{"normalized name", "demo.relay.example", "Demo", true},
		{"other name", "other.relay.example", "demo", false},
		{"other root", "demo.other.example", "demo", false},
		{"unnamed service", "demo.relay.example", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchesAlias(tc.hostname, tc.service, canonical); got != tc.want {
				t.Fatalf("MatchesAlias(%q, %q) = %v, want %v", tc.hostname, tc.service, got, tc.want)
			}
		})
	}
}
