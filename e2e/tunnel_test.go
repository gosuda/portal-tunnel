package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
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
			h := newHarnessWithName(t, "e2e", host, "")
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
	if leases[0].Hostname != "" {
		t.Fatalf("unnamed lease hostname = %q, want empty", leases[0].Hostname)
	}
	if relays := h.exposure.Relays(); len(relays) != 1 || relays[0].AliasURL != "" {
		t.Fatalf("relay status = %+v, want no AliasURL", relays)
	}
	if got := h.get(publicURL); got != marker {
		t.Fatalf("canonical tenant response = %q, want %q", got, marker)
	}
}

func TestUnnamedCanonicalTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			h := newHarnessWithName(t, "", host, "")
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
	exposure, err := sdk.Expose(ctx, other, []string{"https://" + sniAddr})
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
	h := newHarnessWithName(t, "e2e", "127.0.0.1", "")
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
