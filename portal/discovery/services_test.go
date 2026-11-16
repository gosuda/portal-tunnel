package discovery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const serviceTestAddress = "0x1111111111111111111111111111111111111111"

func TestServiceLookupBoundsObservationsAndResults(t *testing.T) {
	now := time.Now().UTC()
	set := NewRelaySet(nil)
	lookup := NewServiceLookup(set)
	for i := range serviceRelayLimit + 3 {
		relay := fmt.Sprintf("https://relay-%02d.example", i)
		set.relays[relay] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
		lookup.cache[relay] = serviceObservation{at: now, until: now.Add(serviceCacheTTL)}
	}
	var local []types.Lease
	for i := range serviceResultLimit + 1 {
		name := fmt.Sprintf("service-%03d", i)
		local = append(local, types.Lease{Name: name, Address: serviceTestAddress, Hostname: name + ".local.example", ExpiresAt: now.Add(time.Minute)})
	}
	result := lookup.Lookup(t.Context(), "https://local.example", local, serviceTestAddress, nil)
	if !result.Partial || result.RelaysChecked != serviceRelayLimit+1 || result.RelaysSkipped != 3 || len(result.Services) != serviceResultLimit {
		t.Fatalf("lookup did not report its bounds: %+v", result)
	}
}

func TestServiceLookupGroupsIdentityAndRelayLocations(t *testing.T) {
	now := time.Now().UTC()
	set := NewRelaySet(nil)
	lookup := NewServiceLookup(set)
	self := "https://local.example:444"
	remote := "https://remote.example:445"
	set.relays[remote] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: remote, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
	first := types.Lease{Name: "blog", Address: serviceTestAddress, Hostname: "blog.local.example", Ready: 1, ExpiresAt: now.Add(time.Minute)}
	otherOwner := first
	otherOwner.Address = "0x2222222222222222222222222222222222222222"
	otherOwner.Hostname = "blog.remote.example"
	remoteBlog := first
	remoteBlog.Hostname = "blog.remote.example"
	hidden := remoteBlog
	hidden.Name, hidden.Hostname, hidden.Metadata.Hide = "secret", "secret.remote.example", true
	api := remoteBlog
	api.Name, api.Hostname = "api", "api.remote.example"
	spoofed := remoteBlog
	spoofed.Name, spoofed.Hostname = "spoofed", "spoofed.evil.example"
	expired := remoteBlog
	expired.Name, expired.Hostname, expired.ExpiresAt = "expired", "expired.remote.example", now.Add(-time.Second)
	lookup.cache[remote] = serviceObservation{leases: []types.Lease{remoteBlog, remoteBlog, otherOwner, api, hidden, spoofed, expired}, at: now, until: now.Add(serviceCacheTTL)}
	result := lookup.Lookup(t.Context(), self, []types.Lease{first}, serviceTestAddress, nil)
	if result.Partial || result.RelaysChecked != 2 || len(result.Services) != 2 {
		t.Fatalf("unexpected lookup: %+v", result)
	}
	if result.Services[0].Name != "api" || result.Services[1].Name != "blog" || len(result.Services[1].Locations) != 2 {
		t.Fatalf("identity grouping lost services or duplicated locations: %+v", result.Services)
	}
	blog := result.Services[1]
	if blog.Locations[0].URL != "https://blog.local.example:444/" || !blog.Locations[0].CurrentRelay || blog.Locations[1].URL != "https://blog.remote.example:445/" {
		t.Fatalf("relay URLs lost their independent origins: %+v", blog.Locations)
	}
	for _, service := range result.Services {
		for _, location := range service.Locations {
			if location.Verification != "relay-reported" || location.ObservedAt.IsZero() || location.ExpiresAt.After(location.ObservedAt.Add(serviceCacheTTL)) {
				t.Fatalf("observation promoted to verified or unbounded: %+v", location)
			}
		}
	}
	name := "blog"
	filtered := lookup.Lookup(t.Context(), self, []types.Lease{first}, serviceTestAddress, &name)
	if len(filtered.Services) != 1 || filtered.Services[0].Name != name || len(filtered.Services[0].Locations) != 2 {
		t.Fatalf("name lookup differs from address lookup: %+v", filtered)
	}
}

func TestServiceLookupExcludesIneligibleCachedRelays(t *testing.T) {
	for _, condition := range []string{"banned", "suppressed", "dead", "expired", "unverified", "private"} {
		t.Run(condition, func(t *testing.T) {
			now := time.Now().UTC()
			relay := "https://remote.example"
			state := relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
			switch condition {
			case "banned":
				state.Banned = true
			case "suppressed":
				state.suppressActiveUntil = now.Add(time.Minute)
			case "dead":
				state.Dead = true
			case "expired":
				state.Descriptor.ExpiresAt = now.Add(-time.Second)
			case "unverified":
				state.Trust = relayCandidate
			case "private":
				relay = "https://127.0.0.1"
				state.Descriptor.APIHTTPSAddr = relay
			}
			set := NewRelaySet(nil)
			set.relays[relay] = state
			lookup := NewServiceLookup(set)
			lookup.cache[relay] = serviceObservation{leases: []types.Lease{{Name: "blog", Address: serviceTestAddress, Hostname: "blog.remote.example", ExpiresAt: now.Add(time.Minute)}}, at: now, until: now.Add(time.Minute)}
			result := lookup.Lookup(t.Context(), "https://local.example", nil, serviceTestAddress, nil)
			if len(result.Services) != 0 || result.RelaysChecked != 1 {
				t.Fatalf("ineligible cache entry exposed: %+v", result)
			}
		})
	}
}

func TestServiceLookupDoesNotServeStaleDataOnFailure(t *testing.T) {
	for _, negative := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "negative"}[negative], func(t *testing.T) {
			now := time.Now().UTC()
			remote := "https://remote.example"
			set := NewRelaySet(nil)
			set.relays[remote] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: remote, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
			lookup := NewServiceLookup(set)
			until := now.Add(-time.Second)
			if negative {
				until = now.Add(serviceNegativeTTL)
			}
			lookup.cache[remote] = serviceObservation{leases: []types.Lease{{Name: "stale", Address: serviceTestAddress, Hostname: "stale.remote.example", ExpiresAt: now.Add(time.Minute)}}, at: now.Add(-time.Minute), until: until, failed: negative}
			ctx, cancel := context.WithCancel(t.Context())
			cancel() // An expired observation cannot be refreshed; no network is needed.
			local := types.Lease{Name: "blog", Address: serviceTestAddress, Hostname: "blog.local.example", ExpiresAt: now.Add(time.Minute)}
			result := lookup.Lookup(ctx, "https://local.example", []types.Lease{local}, serviceTestAddress, nil)
			if !result.Partial || result.RelaysSkipped != 1 || len(result.Services) != 1 || result.Services[0].Name != "blog" {
				t.Fatalf("remote failure damaged local directory or revived stale data: %+v", result)
			}
		})
	}
}

func TestServiceLocationValidatesNamespaceAndDoesNotPromoteLegacyURLs(t *testing.T) {
	now := time.Now().UTC()
	id := types.Identity{Name: "blog", Address: serviceTestAddress}
	canonical, err := namespace.LocalTLSHostname(id.Name, id.Address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		lease types.Lease
		valid bool
		want  string
	}{
		{"legacy alias", types.Lease{Hostname: "blog.relay.example", CanonicalHostname: "blog-" + strings.TrimPrefix(id.Address, "0x") + ".relay.example"}, true, "https://blog.relay.example:444/"},
		{"legacy canonical only", types.Lease{CanonicalHostname: "blog-" + strings.TrimPrefix(id.Address, "0x") + ".relay.example"}, false, ""},
		{"canonical", types.Lease{Namespace: types.LocalTLSNamespaceV1, CanonicalHostname: canonical, CanonicalReady: true}, true, "https://" + canonical + ":444/"},
		{"pending canonical", types.Lease{Namespace: types.LocalTLSNamespaceV1, CanonicalHostname: canonical}, true, ""},
		{"spoofed alias", types.Lease{Hostname: "blog.evil.example"}, false, ""},
		{"spoofed canonical", types.Lease{Namespace: types.LocalTLSNamespaceV1, CanonicalHostname: "blog." + strings.Repeat("2", 40) + ".relay.example", CanonicalReady: true}, false, ""},
		{"port in alias", types.Lease{Hostname: "blog.relay.example:443"}, false, ""},
		{"unknown namespace", types.Lease{Namespace: "unknown", Hostname: "blog.relay.example"}, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			location, valid := serviceLocation("https://relay.example:444", test.lease, id, now, now.Add(serviceCacheTTL))
			if valid != test.valid || location.URL != test.want {
				t.Fatalf("location=%+v valid=%v", location, valid)
			}
		})
	}
}
