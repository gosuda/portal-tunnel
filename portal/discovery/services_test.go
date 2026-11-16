package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
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
	if !result.Partial || result.RelaysChecked != serviceRelayLimit+4 || result.RelaysSkipped != 0 || len(result.Services) != serviceResultLimit {
		t.Fatalf("lookup did not report its bounds: %+v", result)
	}
}

// Real HTTPS exercises directory fetching at its owner. Only the fixture's
// destination/trust is substituted; production public-IP policy has separate
// tests in public_relay_test.go. No production injection seam is introduced.
func serviceLookupHTTPSFixture(t *testing.T, handler http.Handler) *ServiceLookup {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	lookup := NewServiceLookup(NewRelaySet(nil))
	lookup.client = &http.Client{Transport: transport, CheckRedirect: rejectDiscoveryRedirect}
	return lookup
}

func serveLookupDirectory(w http.ResponseWriter, r *http.Request) {
	utils.WriteAPIData(w, http.StatusOK, types.PublicStateResponse{Leases: []types.Lease{{
		Name: "blog", Address: serviceTestAddress, Hostname: "blog." + r.Host,
		ExpiresAt: time.Now().Add(time.Minute), Ready: 1,
	}}})
}

func TestServiceLookupColdCacheObservesEightHealthyRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), serviceLookupTimeout)
	defer cancel()
	gate, release := context.WithCancel(ctx)
	defer release()
	entered := make(chan struct{}, serviceRelayLimit)
	var calls, active, peak atomic.Int32
	lookup := serviceLookupHTTPSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-gate.Done():
			serveLookupDirectory(w, r)
		case <-r.Context().Done():
		}
	}))
	now := time.Now().UTC()
	for i := range serviceRelayLimit {
		relay := fmt.Sprintf("https://relay-%02d.example", i)
		lookup.relays.relays[relay] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
	}
	result := make(chan types.ServiceDiscoveryResponse, 1)
	go func() { result <- lookup.Lookup(ctx, "https://local.example", nil, serviceTestAddress, nil) }()
	for range serviceConcurrency {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("first wave did not reach the directories")
		}
	}
	release()
	select {
	case response := <-result:
		if response.Partial || response.RelaysChecked != 9 || len(response.Services) != 1 || len(response.Services[0].Locations) != 8 {
			t.Fatalf("healthy cold-cache relays were omitted: %+v", response)
		}
	case <-ctx.Done():
		t.Fatal("cold lookup did not finish")
	}
	if calls.Load() != 8 || peak.Load() > serviceConcurrency {
		t.Fatalf("directory requests=%d concurrent=%d", calls.Load(), peak.Load())
	}
}

func TestServiceLookupRotatesAndRetainsObservedLocations(t *testing.T) {
	lookup := serviceLookupHTTPSFixture(t, http.HandlerFunc(serveLookupDirectory))
	now := time.Now().UTC()
	for i := range serviceRelayLimit + 3 {
		relay := fmt.Sprintf("https://relay-%02d.example", i)
		lookup.relays.relays[relay] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
	}
	first := lookup.Lookup(t.Context(), "https://local.example", nil, serviceTestAddress, nil)
	if !first.Partial || first.RelaysChecked != 9 || first.RelaysSkipped != 3 {
		t.Fatalf("first refresh window: %+v", first)
	}
	second := lookup.Lookup(t.Context(), "https://local.example", nil, serviceTestAddress, nil)
	if second.Partial || second.RelaysChecked != 12 || second.RelaysSkipped != 0 || len(second.Services) != 1 || len(second.Services[0].Locations) != 11 {
		t.Fatalf("later relays or prior cached locations were lost: %+v", second)
	}
}

func TestServiceLookupWaitsForSameRelayInFlight(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), serviceLookupTimeout)
	defer cancel()
	gate, release := context.WithCancel(ctx)
	defer release()
	entered := make(chan struct{}, 2)
	var calls atomic.Int32
	lookup := serviceLookupHTTPSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-gate.Done():
			serveLookupDirectory(w, r)
		case <-r.Context().Done():
		}
	}))
	first, second := make(chan serviceObservation, 1), make(chan serviceObservation, 1)
	go func() { first <- lookup.observe(ctx, "https://relay.example") }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("directory request did not start")
	}
	go func() { second <- lookup.observe(ctx, "https://relay.example") }()
	select {
	case <-second:
		t.Fatal("pending directory lookup was returned as a completed result")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	for _, result := range []chan serviceObservation{first, second} {
		select {
		case observation := <-result:
			if observation.failed || len(observation.leases) != 1 {
				t.Fatalf("shared observation=%+v", observation)
			}
		case <-ctx.Done():
			t.Fatal("shared lookup did not finish")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("same relay fetched %d times", calls.Load())
	}
}

func TestServiceLookupCanceledLeaderDoesNotNegativeCacheRelay(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	lookup := serviceLookupHTTPSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		serveLookupDirectory(w, r)
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan serviceObservation, 1)
	go func() { result <- lookup.observe(ctx, "https://relay.example") }()
	select {
	case <-entered:
	case <-time.After(serviceRelayTimeout):
		t.Fatal("directory request did not start")
	}
	cancel()
	if observation := <-result; !observation.failed {
		t.Fatal("canceled lookup unexpectedly succeeded")
	}
	if observation := lookup.observe(t.Context(), "https://relay.example"); observation.failed || len(observation.leases) != 1 {
		t.Fatalf("caller cancellation poisoned the next lookup: %+v", observation)
	}
}

func TestServiceLookupSlotWaitHonorsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lookup := NewServiceLookup(nil)
		for range serviceConcurrency {
			lookup.slots <- struct{}{}
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan serviceObservation, 1)
		go func() { result <- lookup.observe(ctx, "https://relay.example") }()
		synctest.Wait()
		select {
		case <-result:
			t.Fatal("full slots failed instead of waiting")
		default:
		}
		cancel()
		synctest.Wait()
		if observation := <-result; !observation.failed {
			t.Fatal("canceled queue wait succeeded")
		}
	})
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
	var err error
	remoteBlog.CanonicalHostname, err = namespace.LegacyHostname(remoteBlog.Name, remoteBlog.Address, "remote.example")
	if err != nil {
		t.Fatal(err)
	}
	// The other owner may repeat the alias claim, but cannot borrow the first
	// identity's tally by claiming its canonical hostname.
	otherOwner.CanonicalHostname = remoteBlog.CanonicalHostname
	hidden := remoteBlog
	hidden.Name, hidden.Hostname, hidden.Metadata.Hide = "secret", "secret.remote.example", true
	api := remoteBlog
	api.Name, api.Hostname = "api", "api.remote.example"
	spoofed := remoteBlog
	spoofed.Name, spoofed.Hostname = "spoofed", "spoofed.evil.example"
	expired := remoteBlog
	expired.Name, expired.Hostname, expired.ExpiresAt = "expired", "expired.remote.example", now.Add(-time.Second)
	lookup.cache[remote] = serviceObservation{
		leases:     []types.Lease{remoteBlog, remoteBlog, otherOwner, api, hidden, spoofed, expired},
		reputation: parseObservedReputation(fmt.Appendf(nil, `[{"hostname":%q,"up":4,"down":1,"total":5}]`, remoteBlog.CanonicalHostname)),
		at:         now, until: now.Add(serviceCacheTTL),
	}
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
	network := lookup.Lookup(t.Context(), self, []types.Lease{first}, "", nil)
	if network.Partial || len(network.Services) != 3 {
		t.Fatalf("unfiltered lookup omitted remote owners or exposed invalid entries: %+v", network)
	}
	if network.Services[0].Name != "api" || network.Services[0].Locations[0].CurrentRelay ||
		network.Services[1].Name != "blog" || network.Services[1].Address != serviceTestAddress || len(network.Services[1].Locations) != 2 ||
		network.Services[2].Name != "blog" || network.Services[2].Address != otherOwner.Address || len(network.Services[2].Locations) != 1 {
		t.Fatalf("network directory lost remote-only services or merged distinct owners: %+v", network.Services)
	}
	localTally := network.Services[1].Locations[0].Reputation
	remoteTally := network.Services[1].Locations[1].Reputation
	otherOwnerTally := network.Services[2].Locations[0].Reputation
	if localTally != nil || remoteTally == nil || remoteTally.Up != 4 || remoteTally.Down != 1 || otherOwnerTally != nil {
		t.Fatalf("reputation was lost or attributed to the wrong source/identity: %+v", network.Services)
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

func TestObservedReputationKeepsUnknownDistinctFromZero(t *testing.T) {
	tallies := parseObservedReputation([]byte(`[
		{"hostname":"zero.example","up":0,"down":0,"total":0},
		{"hostname":"missing.example","up":1,"total":1},
		{"hostname":"negative.example","up":-1,"down":2,"total":1},
		{"hostname":"incorrect.example","up":1,"down":1,"total":100},
		{"hostname":"overflow.example","up":4294967295,"down":2,"total":1},
		{"hostname":"duplicate.example","up":3,"down":1,"total":4},
		{"hostname":"DUPLICATE.example","up":1,"down":0,"total":1},
		{"hostname":"good.example","up":2,"down":1,"total":3}
	]`))
	if zero, good := tallies["zero.example"], tallies["good.example"]; zero == nil || zero.Up != 0 || zero.Down != 0 || good == nil || good.Up != 2 {
		t.Fatalf("valid reports were lost: %+v", tallies)
	}
	for _, name := range []string{"missing", "negative", "incorrect", "overflow", "duplicate"} {
		if tallies[name+".example"] != nil {
			t.Fatalf("invalid or ambiguous %s report was treated as observed", name)
		}
	}
	if unknown := parseObservedReputation([]byte(`{}`)); unknown != nil {
		t.Fatalf("malformed optional reputation must be unknown: %+v", unknown)
	}
}
