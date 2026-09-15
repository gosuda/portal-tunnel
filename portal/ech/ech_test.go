package ech

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func testTenantIdentity(t *testing.T, name string) types.Identity {
	t.Helper()
	id, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("identity.ResolveSecp256k1Identity() error = %v", err)
	}
	id.Name = name
	return id
}

func TestPrepareDerivesStableTenantMaterials(t *testing.T) {
	t.Parallel()
	id := testTenantIdentity(t, "demo")

	first, err := Prepare(id, "demo.example.com", "example.com")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	second, err := Prepare(id, "demo.example.com", "example.com")
	if err != nil {
		t.Fatalf("Prepare() second error = %v", err)
	}
	if first.RouteHostname != second.RouteHostname || first.HostnameHash != second.HostnameHash {
		t.Fatal("Prepare() derivation not deterministic for one identity")
	}
	if !bytes.Equal(first.ConfigList, second.ConfigList) {
		t.Fatal("Prepare() config list not deterministic for one identity")
	}
	if !strings.HasPrefix(first.RouteHostname, "ech-") || !strings.HasSuffix(first.RouteHostname, ".example.com") {
		t.Fatalf("Prepare() route hostname = %q, want ech- label under the relay root", first.RouteHostname)
	}
	if first.RouteHostname == "demo.example.com" {
		t.Fatal("Prepare() route hostname leaks the public hostname")
	}
	if first.HostnameHash != HostnameHash("demo.example.com") {
		t.Fatalf("Prepare() hostname hash = %q, want hash of the public hostname", first.HostnameHash)
	}
	if len(first.Keys) == 0 || len(first.ConfigList) == 0 {
		t.Fatal("Prepare() returned no ECH key material")
	}

	other := testTenantIdentity(t, "demo")
	otherMaterials, err := Prepare(other, "demo.example.com", "example.com")
	if err != nil {
		t.Fatalf("Prepare(other identity) error = %v", err)
	}
	if otherMaterials.RouteHostname == first.RouteHostname {
		t.Fatal("Prepare() route hostname collides across identities")
	}
}

func TestHostnameHashNormalizesAndDistinguishes(t *testing.T) {
	t.Parallel()
	if HostnameHash("") != "" {
		t.Fatal("HostnameHash(empty) not empty")
	}
	normalized := HostnameHash("Demo.Example.COM.")
	if normalized != HostnameHash("demo.example.com") {
		t.Fatal("HostnameHash() not case and trailing-dot insensitive")
	}
	if normalized == HostnameHash("other.example.com") {
		t.Fatal("HostnameHash() collision across hostnames")
	}
}

func TestNormalizeRegistration(t *testing.T) {
	t.Parallel()
	const (
		root           = "example.com"
		route          = "ech-abc123.example.com"
		publicHostname = "demo.example.com"
	)
	validList := func(t *testing.T) []byte {
		t.Helper()
		_, configList, err := keyless.EncryptedClientHelloMaterials("test-seed", route)
		if err != nil {
			t.Fatalf("EncryptedClientHelloMaterials() error = %v", err)
		}
		return configList
	}

	for _, tc := range []struct {
		name          string
		routeHostname string
		hostnameHash  string
		echConfigList []byte
		publicHost    string
		wantErr       string
	}{
		{name: "hostname hash requires route", hostnameHash: "hash", wantErr: "hostname hash requires route hostname"},
		{name: "config list requires route", echConfigList: []byte("x"), wantErr: "ech config list requires route hostname"},
		{name: "route outside relay root", routeHostname: "ech-x.other.com", wantErr: "route hostname must be a child of relay root hostname"},
		{name: "hostname hash mismatch", routeHostname: route, hostnameHash: "wrong", wantErr: "hostname hash does not match public hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := NormalizeRegistration(tc.routeHostname, tc.hostnameHash, tc.echConfigList, tc.publicHost, root)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NormalizeRegistration() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("fills expected hash for route without hash", func(t *testing.T) {
		t.Parallel()
		hostnameHash, echConfigList, err := NormalizeRegistration(route, "", nil, publicHostname, root)
		if err != nil {
			t.Fatalf("NormalizeRegistration() error = %v", err)
		}
		if hostnameHash != HostnameHash(publicHostname) {
			t.Fatalf("hostname hash = %q, want hash of %q", hostnameHash, publicHostname)
		}
		if len(echConfigList) != 0 {
			t.Fatal("NormalizeRegistration() invented an ECH config list")
		}
	})

	t.Run("accepts matching registration and normalizes the config list", func(t *testing.T) {
		t.Parallel()
		configList := validList(t)
		expected, err := keyless.NormalizeEncryptedClientHelloConfigList(configList)
		if err != nil {
			t.Fatalf("NormalizeEncryptedClientHelloConfigList() error = %v", err)
		}
		hostnameHash, normalized, err := NormalizeRegistration(route, HostnameHash(publicHostname), configList, publicHostname, root)
		if err != nil {
			t.Fatalf("NormalizeRegistration() error = %v", err)
		}
		if hostnameHash != HostnameHash(publicHostname) {
			t.Fatalf("hostname hash = %q, want hash of %q", hostnameHash, publicHostname)
		}
		if !bytes.Equal(normalized, expected) {
			t.Fatal("NormalizeRegistration() config list not normalized")
		}
	})

	t.Run("plain registration stays plain", func(t *testing.T) {
		t.Parallel()
		hostnameHash, echConfigList, err := NormalizeRegistration("", "", nil, "", root)
		if err != nil {
			t.Fatalf("NormalizeRegistration() error = %v", err)
		}
		if hostnameHash != "" || len(echConfigList) != 0 {
			t.Fatalf("NormalizeRegistration() = %q, %v, want empty plain registration", hostnameHash, echConfigList)
		}
	})
}

func TestHTTPSRecordValue(t *testing.T) {
	t.Parallel()
	_, configList, err := keyless.EncryptedClientHelloMaterials("test-seed", "ech-demo.example.com")
	if err != nil {
		t.Fatalf("EncryptedClientHelloMaterials() error = %v", err)
	}
	echParam := `ech="` + base64.StdEncoding.EncodeToString(configList) + `"`
	for _, tc := range []struct {
		port int
		want string
	}{
		{port: 0, want: echParam},
		{port: 443, want: echParam},
		{port: 8443, want: echParam + " port=8443"},
	} {
		got, err := HTTPSRecordValue(configList, tc.port)
		if err != nil {
			t.Fatalf("HTTPSRecordValue(port=%d) error = %v", tc.port, err)
		}
		if got != tc.want {
			t.Fatalf("HTTPSRecordValue(port=%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
	if _, err := HTTPSRecordValue([]byte("garbage"), 443); err == nil {
		t.Fatal("HTTPSRecordValue(garbage) error = nil, want invalid config list rejection")
	}
}

func TestRelayMaterials(t *testing.T) {
	t.Parallel()
	id := testTenantIdentity(t, "relay.example.com")

	firstKeys, firstList, err := RelayMaterials(id, "seed-a", "relay.example.com")
	if err != nil {
		t.Fatalf("RelayMaterials() error = %v", err)
	}
	_, replayList, err := RelayMaterials(id, "seed-a", "relay.example.com")
	if err != nil {
		t.Fatalf("RelayMaterials() replay error = %v", err)
	}
	if len(firstKeys) == 0 || len(firstList) == 0 {
		t.Fatal("RelayMaterials() returned no key material")
	}
	if !bytes.Equal(firstList, replayList) {
		t.Fatal("RelayMaterials() not deterministic for one seed")
	}

	_, otherList, err := RelayMaterials(id, "seed-b", "relay.example.com")
	if err != nil {
		t.Fatalf("RelayMaterials(other seed) error = %v", err)
	}
	if bytes.Equal(firstList, otherList) {
		t.Fatal("RelayMaterials() config list collides across seeds")
	}
}
