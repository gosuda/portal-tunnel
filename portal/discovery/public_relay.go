package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The non-public exceptions to Go's IsGlobalUnicast and IsPrivate checks
// include shared, benchmark, documentation, and transition address space.
var nonPublicIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var nonPublicIPv6 = [...]netip.Prefix{
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3ffe::/16"),
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

// requirePublicRelayURL checks the static part of the discovery trust boundary.
// Names must also pass the resolved-address check on every new connection.
func requirePublicRelayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("discovered relay must have a public HTTPS URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || strings.Contains(host, "%") ||
		host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") {
		return fmt.Errorf("discovered relay host %q is local-only", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !isPublicRelayIP(ip) {
		return fmt.Errorf("discovered relay address %q is not public", host)
	}
	return nil
}

// isPublicRelayIP excludes locally reachable and special-use destinations,
// including IPv4-mapped IPv6 addresses.
func isPublicRelayIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.Is4() {
		for _, prefix := range nonPublicIPv4 {
			if prefix.Contains(ip) {
				return false
			}
		}
		return true
	}
	if !globalIPv6.Contains(ip) {
		return false
	}
	for _, prefix := range nonPublicIPv6 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// dialPublicRelay resolves a discovery hostname and dials only a vetted IP.
// Dialing the IP, rather than the hostname, prevents a second DNS lookup from
// rebinding to an internal address. net/http retains the original hostname
// for TLS certificate verification and the HTTP Host header.
func dialPublicRelay(ctx context.Context, network, address string) (net.Conn, error) {
	// HTTP transports can keep a dial alive after its request times out.
	// Bound DNS resolution and all connection attempts independently.
	ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported discovery dial network %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid discovery dial address: %w", err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve discovery relay %q: %w", host, err)
	}
	ips = slices.DeleteFunc(ips, func(ip netip.Addr) bool { return !isPublicRelayIP(ip) })
	deadline, _ := ctx.Deadline()
	var dialErr error
	for index, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("dial discovery relay %q: %w", host, err)
		}
		// Leave time for later vetted addresses if this one is unreachable.
		dialer := net.Dialer{Timeout: time.Until(deadline) / time.Duration(len(ips)-index)}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	if dialErr != nil {
		return nil, fmt.Errorf("dial discovery relay %q: %w", host, dialErr)
	}
	return nil, fmt.Errorf("discovery relay %q has no public IP addresses", host)
}

func rejectDiscoveryRedirect(_ *http.Request, _ []*http.Request) error {
	return errors.New("discovery redirects are not allowed")
}
