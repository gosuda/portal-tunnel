package types

import (
	"encoding/json"
	"testing"
)

func TestDomainProtocolCompatibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		domain DomainResponse
		want   bool
	}{
		{"old relay", DomainResponse{ProtocolVersion: "10"}, true},
		{"old incompatible relay", DomainResponse{ProtocolVersion: "9"}, false},
		{"explicit compatibility", DomainResponse{ProtocolVersion: "11", SupportedProtocolVersions: []string{"10", "11"}}, true},
		{"explicit exclusion", DomainResponse{ProtocolVersion: "10", SupportedProtocolVersions: []string{"11"}}, false},
		{"explicit empty list", DomainResponse{ProtocolVersion: "10", SupportedProtocolVersions: []string{}}, false},
		{"missing version", DomainResponse{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.domain)
			if err != nil {
				t.Fatal(err)
			}
			var domain DomainResponse
			if err := json.Unmarshal(encoded, &domain); err != nil {
				t.Fatal(err)
			}
			if got := domain.SupportsProtocol("10"); got != test.want {
				t.Fatalf("SupportsProtocol(10) = %v, want %v", got, test.want)
			}
			if domain.SupportsProtocol("") {
				t.Fatal("an absent SDK protocol must not be compatible")
			}
		})
	}
}
