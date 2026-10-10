package e2e_test

import (
	"net"
	"net/url"
	"testing"
)

func TestCanonicalTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			h := newHarnessWithName(t, "e2e", host)
			publicURL := h.waitForPublicURL()
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
			friendlyURL := *publicOrigin
			friendlyURL.Host = leases[0].Hostname
			if port := publicOrigin.Port(); port != "" {
				friendlyURL.Host = net.JoinHostPort(leases[0].Hostname, port)
			}
			if got := h.get(friendlyURL.String()); got != marker {
				t.Fatalf("friendly tenant response = %q, want %q", got, marker)
			}
		})
	}
}

func TestUnnamedCanonicalTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			h := newHarnessWithName(t, "", host)
			publicURL := h.waitForPublicURL()
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
			if got := h.get(publicURL); got != marker {
				t.Fatalf("canonical tenant response = %q, want %q", got, marker)
			}
		})
	}
}
