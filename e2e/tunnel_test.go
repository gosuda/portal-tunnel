package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func assertFriendlyTunnelServes(t *testing.T, h *harness, friendlyURL string) {
	t.Helper()
	if got := h.get(friendlyURL); got != marker {
		t.Fatalf("friendly tenant response = %q, want %q", got, marker)
	}
	if relays := h.exposure.Relays(); len(relays) != 1 || relays[0].AliasURL != friendlyURL {
		t.Fatalf("relay status = %+v, want AliasURL %q", relays, friendlyURL)
	}
}

func assertFriendlyCanonical(t *testing.T, h *harness, publicOrigin *url.URL, leases []types.Lease) {
	t.Helper()
	friendlyURL := *publicOrigin
	friendlyURL.Host = leases[0].Hostname
	if port := publicOrigin.Port(); port != "" {
		friendlyURL.Host = net.JoinHostPort(leases[0].Hostname, port)
	}
	assertFriendlyTunnelServes(t, h, friendlyURL.String())
}

func assertCanonicalTunnel(t *testing.T, h *harness, publicURL string) {
	t.Helper()
	publicOrigin, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	portalOrigin, err := url.Parse(h.server.PortalURL())
	if err != nil {
		t.Fatalf("parse portal URL: %v", err)
	}
	if publicOrigin.Port() != portalOrigin.Port() {
		t.Fatalf("public URL port = %q, want canonical PORTAL_URL port %q", publicOrigin.Port(), portalOrigin.Port())
	}
	leases := h.server.PublicLeases()
	if len(leases) != 1 || publicOrigin.Hostname() != leases[0].CanonicalHostname {
		t.Fatalf("public URL hostname = %q, leases = %+v; want returned canonical hostname", publicOrigin.Hostname(), leases)
	}
	if got := h.get(publicURL); got != marker {
		t.Fatalf("canonical tenant response = %q, want %q", got, marker)
	}
	assertFriendlyCanonical(t, h, publicOrigin, leases)
}

func TestCanonicalTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			h := newHarnessWithName(t, "e2e", host, "", sdk.WithAutomaticTLS(t.TempDir(), true))
			assertCanonicalTunnel(t, h, h.waitForPublicURL())
		})
	}
}

func assertUnnamedCanonicalTunnel(t *testing.T, h *harness, publicURL string) {
	t.Helper()
	publicOrigin, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	portalOrigin, err := url.Parse(h.server.PortalURL())
	if err != nil {
		t.Fatalf("parse portal URL: %v", err)
	}
	if publicOrigin.Port() != portalOrigin.Port() {
		t.Fatalf("public URL port = %q, want canonical PORTAL_URL port %q", publicOrigin.Port(), portalOrigin.Port())
	}
	leases := h.server.PublicLeases()
	if len(leases) != 1 || publicOrigin.Hostname() != leases[0].CanonicalHostname {
		t.Fatalf("public URL hostname = %q, leases = %+v; want returned canonical hostname", publicOrigin.Hostname(), leases)
	}
	assertAutomaticAlias(t, leases[0].Hostname, leases[0].Address)
	if got := h.get(publicURL); got != marker {
		t.Fatalf("canonical tenant response = %q, want %q", got, marker)
	}
	// Local TLS stays independent: the Keyless automatic alias also serves.
	assertFriendlyCanonical(t, h, publicOrigin, leases)
}

// assertAutomaticAlias checks the public contract of an automatic alias: a
// short label that the relay accepts as automatic and that does not carry
// the signing address.
func assertAutomaticAlias(t *testing.T, hostname, address string) string {
	t.Helper()
	label, root, _ := strings.Cut(hostname, ".")
	if _, err := namespace.UnnamedAliasHostname(label, root); err != nil || len(label) > 40 {
		t.Fatalf("alias %q is not a short automatic alias: %v", hostname, err)
	}
	if strings.Contains(hostname, strings.ToLower(strings.TrimPrefix(address, "0x"))) {
		t.Fatalf("automatic alias %q exposes the signing address", hostname)
	}
	return label
}

func exposeUnnamed(t *testing.T, ctx context.Context, id types.Identity, relays ...membershipRelay) *sdk.Exposure {
	t.Helper()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	t.Cleanup(service.Close)
	target, _ := url.Parse(service.URL)
	relayURLs := make([]string, 0, len(relays))
	for _, relay := range relays {
		relayURLs = append(relayURLs, relay.relayURL)
	}
	exposure, err := sdk.Expose(ctx, id, relayURLs)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sdk.Proxy(ctx, exposure, target.Host) }()
	t.Cleanup(func() {
		_ = exposure.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("unnamed proxy did not stop")
		}
	})
	return exposure
}

// waitKeylessAlias waits for a ready alias on one relay and checks that it
// serves and that the lease never entered the Local TLS namespace.
func waitKeylessAlias(t *testing.T, server *portal.Server, exposure *sdk.Exposure, id types.Identity, relay membershipRelay) string {
	t.Helper()
	publicURL := waitPublicURLOnPort(t, exposure, relay.sniPort, time.Now().Add(15*time.Second))
	status, _ := relayStatusOnPort(exposure.Relays(), relay.sniPort)
	if status.AliasURL != publicURL || status.CertificateError != nil {
		t.Fatalf("unnamed readiness = %+v, want a Keyless alias URL", status)
	}
	parsed, _ := url.Parse(publicURL)
	assertAutomaticAlias(t, parsed.Hostname(), id.Address)
	for _, lease := range server.PublicLeases() {
		if lease.Address == id.Address && (lease.Namespace != "" || lease.CanonicalHostname != "") {
			t.Fatalf("unnamed Keyless lease entered Local TLS: %+v", lease)
		}
	}
	waitServesMarker(t, "automatic alias", relay, publicURL, 15*time.Second)
	return publicURL
}

// TestUnnamedKeylessDefault protects the one-command default on a relay
// without tenant certificate issuance: an unnamed HTTP exposure gets a short
// random Keyless URL, distinct exposures get distinct URLs, and no URL is
// derived from the identity.
func TestUnnamedKeylessDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay, server := startMembershipRelayServer(t, ctx)
	first, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	firstURL := waitKeylessAlias(t, server, exposeUnnamed(t, ctx, first, relay), first, relay)
	secondURL := waitKeylessAlias(t, server, exposeUnnamed(t, ctx, second, relay), second, relay)
	if firstURL == secondURL {
		t.Fatalf("two unnamed exposures share %q", firstURL)
	}
	// A new exposure of the same identity draws a new alias; the URL is per
	// exposure, not per identity.
	again := exposeUnnamed(t, ctx, first, relay)
	if againURL := waitKeylessAlias(t, server, again, first, relay); againURL == firstURL || againURL == secondURL {
		t.Fatalf("new exposure reused alias %q", againURL)
	}
}

// TestUnnamedAliasCollisionRetry holds the exposure's alias on a second relay
// for another identity. The exposure must draw a fresh alias there and keep
// its original alias on the first relay.
func TestUnnamedAliasCollisionRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relayA, serverA := startMembershipRelayServer(t, ctx)
	relayB, serverB := startMembershipRelayServer(t, ctx)
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	exposure := exposeUnnamed(t, ctx, id, relayA)
	aliasURL := waitKeylessAlias(t, serverA, exposure, id, relayA)
	parsed, _ := url.Parse(aliasURL)
	label, _, _ := strings.Cut(parsed.Hostname(), ".")

	squatter, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(relayB.relayURL)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}
	held, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: squatter, Alias: label})
	if err != nil || !strings.HasPrefix(held.Hostname, label+".") {
		t.Fatalf("hold alias %q on relay B = %q, %v", label, held.Hostname, err)
	}
	if err := exposure.AddRelay(relayB.relayURL); err != nil {
		t.Fatal(err)
	}
	retried := waitKeylessAlias(t, serverB, exposure, id, relayB)
	retriedHost, _ := url.Parse(retried)
	if retriedHost.Hostname() == parsed.Hostname() {
		t.Fatalf("exposure took alias %q held by another identity", retried)
	}
	if status, _ := relayStatusOnPort(exposure.Relays(), relayA.sniPort); status.AliasURL != aliasURL {
		t.Fatalf("relay A alias = %q, want unchanged %q", status.AliasURL, aliasURL)
	}
}

// TestUnnamedAliasSurvivesRelayRestart protects reconnect continuity: the
// same exposure registers its alias again after the relay loses all leases.
func TestUnnamedAliasSurvivesRelayRestart(t *testing.T) {
	h := newHarnessWithName(t, "", "127.0.0.1", "")
	publicURL := h.waitForPublicURL()
	if relays := h.exposure.Relays(); len(relays) != 1 || relays[0].AliasURL != publicURL {
		t.Fatalf("unnamed readiness = %+v, want the alias as PublicURL", relays)
	}
	parsed, _ := url.Parse(publicURL)
	assertAutomaticAlias(t, parsed.Hostname(), h.server.PublicLeases()[0].Address)
	if got := h.get(publicURL); got != marker {
		t.Fatalf("alias response before restart = %q", got)
	}
	shutdownRelayForRestart(t, h)
	startRestartedRelay(t, h)
	if !awaitExposureRouted(t, h, publicURL) {
		t.Fatal("unnamed exposure did not route its alias again after relay restart")
	}
}

func TestUnnamedCanonicalTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			h := newHarnessWithName(t, "", host, "", sdk.WithAutomaticTLS(t.TempDir(), true))
			assertUnnamedCanonicalTunnel(t, h, h.waitForPublicURL())
		})
	}
}

func exposeSecondIdentity(t *testing.T, ctx context.Context, sniAddr string) ([]sdk.RelayStatus, *sdk.Exposure) {
	t.Helper()
	other, err := identity.Generate("e2e")
	if err != nil {
		t.Fatal(err)
	}
	exposure, err := sdk.Expose(ctx, other, []string{"https://" + sniAddr}, sdk.WithAutomaticTLS(t.TempDir(), true))
	if err != nil {
		t.Fatalf("expose second identity: %v", err)
	}
	ready, err := exposure.WaitReady(ctx)
	if err != nil {
		t.Fatalf("second identity did not become ready: %v", err)
	}
	return ready, exposure
}

func TestAliasURLOnlyForAliasOwner(t *testing.T) {
	h := newHarnessWithName(t, "e2e", "127.0.0.1", "", sdk.WithAutomaticTLS(t.TempDir(), true))
	h.waitForPublicURL()
	owner := h.exposure.Relays()
	if len(owner) != 1 || owner[0].AliasURL == "" {
		t.Fatalf("alias owner status = %+v, want AliasURL", owner)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ready, exposure := exposeSecondIdentity(t, ctx, h.sniAddr)
	defer exposure.Close()
	if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].PublicURL == owner[0].PublicURL {
		t.Fatalf("second identity status = %+v, want its own canonical PublicURL", ready)
	}
	if ready[0].AliasURL != "" {
		t.Fatalf("second identity AliasURL = %q, want empty after canonical fallback", ready[0].AliasURL)
	}
	if got := h.exposure.Relays(); len(got) != 1 || got[0].AliasURL != owner[0].AliasURL {
		t.Fatalf("alias owner status after fallback = %+v, want AliasURL %q", got, owner[0].AliasURL)
	}
}

func refuteUntrustedHandshake(t *testing.T, h *harness, parsed *url.URL) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", h.sniAddr, &tls.Config{
		ServerName: parsed.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("untrusted tenant TLS handshake unexpectedly succeeded")
	}
	var verificationErr *tls.CertificateVerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("tenant TLS handshake error = %v, want certificate verification failure", err)
	}
}

func TestTunnelRemainsUsableAfterFailedTenantHandshake(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	parsed, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	refuteUntrustedHandshake(t, h, parsed)

	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response after failed handshake = %q, want %q", got, marker)
	}
}
