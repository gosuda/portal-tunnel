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

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
	if ip, err := netip.ParseAddr(host); err == nil && !utils.IsPublicIP(ip) {
		return fmt.Errorf("discovered relay address %q is not public", host)
	}
	return nil
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
	ips = slices.DeleteFunc(ips, func(ip netip.Addr) bool { return !utils.IsPublicIP(ip) })
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
