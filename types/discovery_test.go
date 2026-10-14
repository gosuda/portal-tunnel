package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestDiscoveryResponseLimits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"self and maximum peers", `{"relays":[` + strings.Repeat("{},", MaxDiscoveryEntries) + `{}]}`, true},
		{"too many peers", `{"relays":[` + strings.Repeat("{},", MaxDiscoveryEntries+1) + `{}]}`, false},
		{"too many incompatible relays", `{"incompatible_relays":[` + strings.Repeat("{},", MaxDiscoveryEntries) + `{}]}`, false},
		{"too many map members", `{"relay_release_versions":{` + strings.Repeat(`"same":"v",`, MaxDiscoveryEntries) + `"last":"v"}}`, false},
		{"duplicate relays", `{"relays":[],"relays":[]}`, false},
		{"duplicate incompatible relays", `{"incompatible_relays":[],"incompatible_relays":[]}`, false},
		{"case-folded duplicate versions", `{"relay_release_versions":{},"Relay_Release_Versions":{}}`, false},
		{"maximum version", `{"release_version":"` + strings.Repeat("v", MaxDiscoveryVersionBytes) + `"}`, true},
		{"oversized release version", `{"release_version":"` + strings.Repeat("v", MaxDiscoveryVersionBytes+1) + `"}`, false},
		{"oversized protocol version", `{"protocol_version":"` + strings.Repeat("v", MaxDiscoveryVersionBytes+1) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response DiscoveryResponse
			if err := json.Unmarshal([]byte(tc.body), &response); (err == nil) != tc.valid {
				t.Fatalf("decode error = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestDiscoveryResponseDecodeReplacesOnlyOnSuccess(t *testing.T) {
	var response DiscoveryResponse
	for _, prefix := range []string{"first", "second"} {
		versions := make(map[string]string, MaxDiscoveryEntries)
		for i := range MaxDiscoveryEntries {
			versions[fmt.Sprintf("%s-%d", prefix, i)] = "v"
		}
		data, err := json.Marshal(DiscoveryResponse{RelayReleaseVersions: versions})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.RelayReleaseVersions) != MaxDiscoveryEntries || response.RelayReleaseVersions[prefix+"-0"] != "v" {
			t.Fatal("repeated decoding accumulated or lost map entries")
		}
	}
	invalid := `{"relay_release_versions":{"bad":"v"},"protocol_version":"` + strings.Repeat("v", MaxDiscoveryVersionBytes+1) + `"}`
	if err := json.Unmarshal([]byte(invalid), &response); err == nil {
		t.Fatal("oversized version accepted")
	}
	if len(response.RelayReleaseVersions) != MaxDiscoveryEntries || response.RelayReleaseVersions["second-0"] != "v" {
		t.Fatal("rejected decoding changed the previous response")
	}
	if err := json.Unmarshal([]byte(`{}`), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.RelayReleaseVersions) != 0 {
		t.Fatal("omitted collection retained previous entries")
	}
}
