package utils

import (
	"strings"
	"testing"
)

func TestHostnameMatchesPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact match", pattern: "foo.example.com", host: "foo.example.com", want: true},
		{name: "wildcard matches one level", pattern: "*.example.com", host: "foo.example.com", want: true},
		{name: "wildcard rejects multi-level", pattern: "*.example.com", host: "a.b.example.com", want: false},
		{name: "wildcard rejects apex", pattern: "*.example.com", host: "example.com", want: false},
		{name: "wildcard requires dotted suffix", pattern: "*.com", host: "foo.com", want: false},
		{name: "bare star matches nothing", pattern: "*", host: "foo.example.com", want: false},
		{name: "mismatch", pattern: "bar.example.com", host: "foo.example.com", want: false},
		{name: "empty pattern", pattern: "", host: "foo.example.com", want: false},
		{name: "empty hostname", pattern: "*.example.com", host: "", want: false},
		{name: "normalizes case and trailing dot", pattern: "*.Example.COM.", host: "FOO.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := HostnameMatchesPattern(tt.pattern, tt.host); got != tt.want {
				t.Fatalf("HostnameMatchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestLeaseHostname(t *testing.T) {
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

			got, err := LeaseHostname(tt.raw, tt.root)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LeaseHostname(%q, %q) error = nil, want invalid label error", tt.raw, tt.root)
				}
				return
			}
			if err != nil {
				t.Fatalf("LeaseHostname(%q, %q) error = %v", tt.raw, tt.root, err)
			}
			if got != tt.want {
				t.Fatalf("LeaseHostname(%q, %q) = %q, want %q", tt.raw, tt.root, got, tt.want)
			}
		})
	}
}

func TestCanonicalLeaseHostname(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	want := "herdr-7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com"
	got, err := CanonicalLeaseHostname("Herdr", address, "Example.COM.")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname() error = %v", err)
	}
	if got != want {
		t.Fatalf("CanonicalLeaseHostname() = %q, want %q", got, want)
	}

	maxName := strings.Repeat("a", 22)
	got, err = CanonicalLeaseHostname(maxName, address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname(maximum name) error = %v", err)
	}
	if label := strings.SplitN(got, ".", 2)[0]; len(label) != 63 {
		t.Fatalf("canonical label length = %d, want 63", len(label))
	}

	unnamedWant := "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com"
	got, err = CanonicalLeaseHostname("", address, "Example.COM.")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname(empty name) error = %v", err)
	}
	if got != unnamedWant {
		t.Fatalf("CanonicalLeaseHostname(empty name) = %q, want %q", got, unnamedWant)
	}

	// Names over 22 characters keep the full address and replace the name
	// with a 21-character hash (golden values computed independently).
	const addr = "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
	for name, label := range map[string]string{
		strings.Repeat("a", 23):                 "5e2twslnrzki2h4l7bzvq--" + addr,
		"internal-metrics-dashboard-production": "okm4rhbie4a4gidozw5r5--" + addr,
		strings.Repeat("a", 63):                 "c7pboclanhxavtsfp7efc--" + addr,
	} {
		got, err := CanonicalLeaseHostname(name, address, "example.com")
		if err != nil {
			t.Fatalf("CanonicalLeaseHostname(%d-character name) error = %v", len(name), err)
		}
		if got != label+".example.com" {
			t.Fatalf("CanonicalLeaseHostname(%q) = %q, want %q", name, got, label+".example.com")
		}
	}

	for _, name := range []string{
		strings.Repeat("a", 64),          // over the DNS label limit
		addr,                             // an address-only canonical label
		"myapp-" + addr,                  // a short-name canonical label
		"5e2twslnrzki2h4l7bzvq--" + addr, // a long-name canonical label
	} {
		if _, err := CanonicalLeaseHostname(name, address, "example.com"); err == nil {
			t.Fatalf("CanonicalLeaseHostname(%q) error = nil", name)
		}
	}
	if _, err := CanonicalLeaseHostname("herdr", "0x1234", "example.com"); err == nil {
		t.Fatal("CanonicalLeaseHostname(short address) error = nil")
	}
}

// A normalized name never ends with a hyphen, so no short name produces the
// canonical label of a long one, and no service name is shaped like either.
func TestServiceNamesCannotTakeCanonicalLabels(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	long, err := CanonicalLeaseHostname("internal-metrics-dashboard-production", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	hash, _, _ := strings.Cut(long, "--")
	for _, short := range []string{hash, hash + "-", hash + "-k"} {
		got, err := CanonicalLeaseHostname(short, address, "example.com")
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

// Shape and length rules apply to the normalized ASCII label, after case
// folding and IDNA conversion.
func TestCanonicalLeaseHostnameNormalizesFirst(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	fullwidth := strings.Map(func(r rune) rune { return r + 0xFEE0 }, "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d")
	if _, err := NormalizeServiceName(fullwidth); err == nil {
		t.Fatalf("NormalizeServiceName(fullwidth address) error = nil")
	}

	// "bücher-abcdefghij" is 17 code points but 24 octets in ASCII form, so
	// it takes the hashed form, the same as its punycode spelling.
	unicode, err := CanonicalLeaseHostname("bücher-abcdefghij", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ascii, err := CanonicalLeaseHostname("xn--bcher-abcdefghij-jzb", address, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if unicode != ascii || !strings.HasSuffix(unicode, "--7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com") {
		t.Fatalf("canonical hostnames = (%q, %q), want the same hashed form", unicode, ascii)
	}
}

func TestCanonicalLeaseHostnameKeepsServiceIdentityAcrossRelays(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	relayA, err := CanonicalLeaseHostname("herdr", address, "relay-a.example")
	if err != nil {
		t.Fatal(err)
	}
	relayB, err := CanonicalLeaseHostname("herdr", address, "relay-b.example")
	if err != nil {
		t.Fatal(err)
	}
	labelA, _, _ := strings.Cut(relayA, ".")
	labelB, _, _ := strings.Cut(relayB, ".")
	if labelA != labelB || relayA == relayB {
		t.Fatalf("relay canonical hostnames = (%q, %q), want the same service label under different relay origins", relayA, relayB)
	}
}

func TestEnsurePortHandlesBracketedIPv6(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want string
	}{
		{name: "loopback", host: "[::1]", want: "[::1]:443"},
		{name: "zone id", host: "[fe80::1%eth0]", want: "[fe80::1%eth0]:443"},
		{name: "existing port", host: "[::1]:8443", want: "[::1]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EnsurePort(tc.host); got != tc.want {
				t.Fatalf("EnsurePort(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
