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

var (
	errDiscoveredRelayMustHavePublicHTTPS = errors.New("discovered relay must have a public HTTPS URL")
	errDiscoveryRedirectsAreNotAllowed    = errors.New("discovery redirects are not allowed")
)

func requirePublicRelayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", errDiscoveredRelayMustHavePublicHTTPS, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errDiscoveredRelayMustHavePublicHTTPS
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if utils.IsLocalOnlyRelayHost(host) {
		return fmt.Errorf("discovered relay host %q is local-only", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !utils.IsPublicIP(ip) {
		return fmt.Errorf("discovered relay address %q is not public", host)
	}
	return nil
}

func dialPublicRelay(ctx context.Context, network, address string) (net.Conn, error) {
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
	return errDiscoveryRedirectsAreNotAllowed
}
