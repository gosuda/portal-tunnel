package utils

import (
	"cmp"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLocalTLSNamespace(t *testing.T) {
	address := strings.Repeat("a", 40)
	for _, root := range []string{"example.com", "relay.delegated.example.com", "localhost"} {
		for _, name := range []string{"", "blog", strings.Repeat("x", 63)} {
			host, err := LocalTLSLeaseHostname(name, "0x"+address, root)
			if err != nil {
				t.Fatal(err)
			}
			label := cmp.Or(name, "default")
			if host != label+"."+address+"."+root || !types.IsLocalTLSHostname(host, root) {
				t.Fatalf("unexpected host %q", host)
			}
			if got, err := types.ExtractCanonicalHostnameAddress(host); err != nil || got != "0x"+address {
				t.Fatalf("extract %q: %q, %v", host, got, err)
			}
			for _, invalid := range []string{"extra." + host, label + "." + root, address + "." + root, label + ".0x" + address + "." + root, label + "." + address + ".other." + root} {
				if types.IsLocalTLSHostname(invalid, root) {
					t.Fatalf("accepted noncanonical %q under %q", invalid, root)
				}
			}
		}
	}
	if _, err := LocalTLSLeaseHostname("DEFAULT", address, "example.com"); err == nil {
		t.Fatal("explicit reserved name accepted")
	}
	if _, err := CanonicalLeaseHostname("default", address, "example.com"); err != nil {
		t.Fatal("legacy default rejected", err)
	}
}

func TestCanonicalAddressWithHexadecimalRelayRoot(t *testing.T) {
	owner := "0x" + strings.Repeat("a", 40)
	root := strings.Repeat("b", 40) + ".delegated.example.com"
	for _, name := range []string{"", "blog", strings.Repeat("x", 63)} {
		for _, derive := range []func(string, string, string) (string, error){CanonicalLeaseHostname, LocalTLSLeaseHostname} {
			host, err := derive(name, owner, root)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := types.ExtractCanonicalHostnameAddress(host); err != nil || got != owner {
				t.Fatalf("extract %q = %q, %v; want %q", host, got, err, owner)
			}
		}
	}
	for _, service := range []string{strings.Repeat("a", 40), "blog-" + strings.Repeat("a", 40)} {
		host := service + "." + strings.Repeat("b", 40) + "." + root
		if types.IsLocalTLSHostname(host, root) {
			t.Fatalf("ambiguous legacy-shaped service accepted: %q", host)
		}
	}
}
