package utils

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestCanonicalLeaseHostnamePreservesAddressDecodeError(t *testing.T) {
	_, err := CanonicalLeaseHostname("demo", "0x"+strings.Repeat("z", 40), "example.com")
	var invalidByte hex.InvalidByteError
	if !errors.As(err, &invalidByte) || invalidByte != 'z' {
		t.Fatalf("CanonicalLeaseHostname() error = %v, want wrapped hex error", err)
	}
}

func TestCanonicalLeaseHostname(t *testing.T) {
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
	got, err := CanonicalLeaseHostname("Herdr", address, "Example.COM.")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname() error = %v", err)
	}
	if got != want {
		t.Fatalf("CanonicalLeaseHostname() = %q, want %q", got, want)
	}
}

func checkCanonicalMaxLabel(t *testing.T, address string) {
	t.Helper()
	maxName := strings.Repeat("a", 22)
	got, err := CanonicalLeaseHostname(maxName, address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname(maximum name) error = %v", err)
	}
	if label := strings.SplitN(got, ".", 2)[0]; len(label) != 63 {
		t.Fatalf("canonical label length = %d, want 63", len(label))
	}
}

func checkCanonicalUnnamedName(t *testing.T, address string) {
	t.Helper()
	unnamedWant := "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.example.com"
	got, err := CanonicalLeaseHostname("", address, "Example.COM.")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname(empty name) error = %v", err)
	}
	if got != unnamedWant {
		t.Fatalf("CanonicalLeaseHostname(empty name) = %q, want %q", got, unnamedWant)
	}
}

func checkCanonicalHashedName(t *testing.T, address, name, label string) {
	t.Helper()
	got, err := CanonicalLeaseHostname(name, address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname(%d-character name) error = %v", len(name), err)
	}
	if got != label+".example.com" {
		t.Fatalf("CanonicalLeaseHostname(%q) = %q, want %q", name, got, label+".example.com")
	}
}

func rejectCanonicalBadName(t *testing.T, address, name string) {
	t.Helper()
	if _, err := CanonicalLeaseHostname(name, address, "example.com"); err == nil {
		t.Fatalf("CanonicalLeaseHostname(%q) error = nil", name)
	}
}

func rejectCanonicalShortAddress(t *testing.T) {
	t.Helper()
	if _, err := CanonicalLeaseHostname("herdr", "0x1234", "example.com"); err == nil {
		t.Fatal("CanonicalLeaseHostname(short address) error = nil")
	}
}

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
		if _, err := types.NormalizeServiceName(name); err == nil {
			t.Fatalf("NormalizeServiceName(%q) error = nil", name)
		}
	}
	for _, name := range []string{"myapp", "deadbeef", "my-app-" + strings.Repeat("f", 39), strings.Repeat("f", 41)} {
		if _, err := types.NormalizeServiceName(name); err != nil {
			t.Fatalf("NormalizeServiceName(%q) error = %v", name, err)
		}
	}
}

func TestCanonicalLeaseHostnameNormalizesFirst(t *testing.T) {
	t.Parallel()

	const address = "0x7A3B2C4d5E6F708192a3B4C5D6E7F8091A2b3C4D"
	fullwidth := strings.Map(func(r rune) rune { return r + 0xFEE0 }, "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d")
	if _, err := types.NormalizeServiceName(fullwidth); err == nil {
		t.Fatalf("NormalizeServiceName(fullwidth address) error = nil")
	}

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

func TestNormalizeTargetAddrIPv6(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "::1", want: "[::1]:80"},
		{input: "[::1]", want: "[::1]:80"},
		{input: "[::1]:8080", want: "[::1]:8080"},
		{input: "http://[::1]", want: "[::1]:80"},
		{input: "http://[::1]:8080", want: "[::1]:8080"},
		{input: "fe80::1%eth0", want: "[fe80::1%eth0]:80"},
		{input: "[fe80::1%eth0]", want: "[fe80::1%eth0]:80"},
		{input: "http://[fe80::1%25eth0]", want: "[fe80::1%eth0]:80"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeTargetAddr(tc.input)
			if err != nil {
				t.Fatalf("NormalizeTargetAddr(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeTargetAddr(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
	for _, input := range []string{"[::1", "::1]", "[not-an-ip]", "http://[not-an-ip]"} {
		t.Run(input, func(t *testing.T) {
			if got, err := NormalizeTargetAddr(input); err == nil {
				t.Fatalf("NormalizeTargetAddr(%q) = %q, want invalid address", input, got)
			}
		})
	}
}
