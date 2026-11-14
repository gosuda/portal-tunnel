package sdk

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	pgnsHappyEyeballsDelay = 250 * time.Millisecond
	pgnsMaxResolveBytes    = 256 << 10
)

var (
	errPGNSWitnessSetRequired   = errors.New("sdk: pgns witness set is required")
	errPGNSResolverRequired     = errors.New("sdk: pgns resolver is required")
	errPGNSResolveURLInvalid    = errors.New("sdk: pgns resolve url is invalid")
	errPGNSTargetListEmpty      = errors.New("sdk: pgns leaf has no dialable endpoints")
	errPGNSSPKIMismatch         = errors.New("sdk: pgns peer certificate spki does not match leaf")
	errPGNSALPNMismatch         = errors.New("sdk: pgns peer did not negotiate portal-cb-v1")
	errPGNSResolveMirrorEmpty   = errors.New("sdk: pgns resolve urls yielded no valid endpoints")
	errPGNSPeerCertificateEmpty = errors.New("sdk: pgns peer did not present a certificate")
)

// PGNSResolverConfig configures client-side verification and dialing for PGNS FQDNs.
type PGNSResolverConfig struct {
	Zone        string
	Witnesses   pgns.WitnessSet
	ResolveURLs []string
	HTTPClient  *http.Client
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Now         func() time.Time
}

// PGNSResolver verifies CDN-cached ResolveBundles against a k-of-m witness quorum
// and enforces monotonic epoch anti-rollback tracking.
type PGNSResolver struct {
	zone        string
	witnesses   pgns.WitnessSet
	resolveURLs []string
	httpClient  *http.Client
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	nowFn       func() time.Time

	mu           sync.Mutex
	hasSeenEpoch bool
	maxSeenEpoch uint64
}

// NewPGNSResolver constructs a verified PGNS resolver.
func NewPGNSResolver(cfg PGNSResolverConfig) (*PGNSResolver, error) {
	zoneInput := strings.TrimSpace(cfg.Zone)
	if zoneInput == "" {
		zoneInput = pgns.DefaultZone
	}
	zone, err := pgns.NormalizeZone(zoneInput)
	if err != nil {
		return nil, err
	}
	if cfg.Witnesses.Threshold <= 0 || cfg.Witnesses.Threshold > len(cfg.Witnesses.Witnesses) {
		return nil, errPGNSWitnessSetRequired
	}
	resolveURLs, err := normalizeResolveURLs(cfg.ResolveURLs, zone)
	if err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = utils.NewHTTPClient(utils.WithHTTPTimeout(10 * time.Second))
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	dialFn := cfg.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{Timeout: defaultDialTimeout}).DialContext
	}
	return &PGNSResolver{
		zone:        zone,
		witnesses:   cfg.Witnesses,
		resolveURLs: resolveURLs,
		httpClient:  httpClient,
		dialContext: dialFn,
		nowFn:       nowFn,
	}, nil
}

func normalizeResolveURLs(raw []string, zone string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"https://pgns." + zone}, nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimRight(strings.TrimSpace(item), "/")
		if trimmed == "" {
			continue
		}
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("%w: %q", errPGNSResolveURLInvalid, item)
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, errPGNSResolveMirrorEmpty
	}
	return out, nil
}

// Resolve fetches and cryptographically verifies the PGNS leaf and checkpoint for fqdn.
func (r *PGNSResolver) Resolve(ctx context.Context, fqdn string) (pgns.PortalLeafRecord, pgns.Checkpoint, error) {
	if r == nil {
		return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, errPGNSResolverRequired
	}
	if ctx == nil {
		return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, errPortalSDKContextIsNil
	}
	if err := ctx.Err(); err != nil {
		return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, err
	}
	normFQDN := utils.NormalizeHostWithoutPort(fqdn)
	if _, err := pgns.ParseScopedFQDN(normFQDN, r.zone); err != nil {
		return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, err
	}

	var lastErr error
	for _, baseURL := range r.resolveURLs {
		if err := ctx.Err(); err != nil {
			return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, err
		}
		targetURL := baseURL + types.PathV1ResolvePrefix + url.PathEscape(normFQDN)
		rawBundle, err := r.fetchResolveBundle(ctx, targetURL)
		if err != nil {
			lastErr = err
			continue
		}
		nowSec := uint64(max(0, r.nowFn().UTC().Unix()))
		leaf, cp, err := pgns.VerifyResolveBundle(rawBundle, normFQDN, r.zone, r.witnesses, nowSec)
		if err != nil {
			lastErr = err
			continue
		}
		if err := r.acceptEpoch(cp.Epoch); err != nil {
			lastErr = err
			continue
		}
		return leaf, cp, nil
	}
	return pgns.PortalLeafRecord{}, pgns.Checkpoint{}, lastErr
}

func (r *PGNSResolver) acceptEpoch(epoch uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasSeenEpoch && epoch < r.maxSeenEpoch {
		return fmt.Errorf("%w: checkpoint epoch %d < max seen %d", pgns.ErrStaleCheckpoint, epoch, r.maxSeenEpoch)
	}
	r.hasSeenEpoch = true
	r.maxSeenEpoch = epoch
	return nil
}

func (r *PGNSResolver) fetchResolveBundle(ctx context.Context, targetURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pgns resolve %s returned HTTP %d", targetURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pgnsMaxResolveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > pgnsMaxResolveBytes {
		return nil, fmt.Errorf("%w: resolve bundle exceeds %d bytes", pgns.ErrInvalidWire, pgnsMaxResolveBytes)
	}
	return body, nil
}

// DialPGNS resolves fqdn via resolver, validates all leaf endpoints are public,
// and races TLS-complete + portal-cb-v1 channel-bound connections with a 250ms Happy Eyeballs stagger.
func DialPGNS(ctx context.Context, resolver *PGNSResolver, fqdn string) (net.Conn, error) {
	if resolver == nil {
		return nil, errPGNSResolverRequired
	}
	if ctx == nil {
		return nil, errPortalSDKContextIsNil
	}
	normFQDN := utils.NormalizeHostWithoutPort(fqdn)
	leaf, _, err := resolver.Resolve(ctx, normFQDN)
	if err != nil {
		return nil, err
	}
	return dialPGNSLeaf(ctx, leaf, normFQDN, resolver.dialContext, resolver.nowFn)
}

// NewPGNSHTTPClient returns an HTTP client configured to dial PGNS hostnames
// over SPKI-pinned, portal-cb-v1 channel-bound TLS streams without trusting relays or WebPKI.
func NewPGNSHTTPClient(resolver *PGNSResolver) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return DialPGNS(ctx, resolver, utils.NormalizeHostWithoutPort(addr))
			},
		},
	}
}

func dialPGNSLeaf(
	ctx context.Context,
	leaf pgns.PortalLeafRecord,
	fqdn string,
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error),
	nowFn func() time.Time,
) (net.Conn, error) {
	targets, err := pgnsCandidateTargets(leaf)
	if err != nil {
		return nil, err
	}
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: defaultDialTimeout}).DialContext
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	tlsConf := buildPGNSDialTLSConfig(fqdn, leaf, nowFn)
	return racePGNSAttempts(ctx, targets, fqdn, leaf.OwnerPubKey, tlsConf, dialContext)
}

func pgnsCandidateTargets(leaf pgns.PortalLeafRecord) ([]netip.AddrPort, error) {
	if err := pgns.ValidateEndpoints(leaf.Endpoints); err != nil {
		return nil, err
	}
	targets := make([]netip.AddrPort, 0, len(leaf.Endpoints)*2)
	for _, ep := range leaf.Endpoints {
		if ep.IPv6 != ([16]byte{}) {
			addr6 := netip.AddrFrom16(ep.IPv6).Unmap()
			if !utils.IsPublicIP(addr6) {
				return nil, fmt.Errorf("%w: non-public ipv6 %s", pgns.ErrInvalidEndpoint, addr6)
			}
			targets = append(targets, netip.AddrPortFrom(addr6, ep.Port))
		}
		if ep.IPv4 != ([4]byte{}) {
			addr4 := netip.AddrFrom4(ep.IPv4)
			if !utils.IsPublicIP(addr4) {
				return nil, fmt.Errorf("%w: non-public ipv4 %s", pgns.ErrInvalidEndpoint, addr4)
			}
			targets = append(targets, netip.AddrPortFrom(addr4, ep.Port))
		}
	}
	if len(targets) == 0 {
		return nil, errPGNSTargetListEmpty
	}
	return targets, nil
}

func buildPGNSDialTLSConfig(fqdn string, leaf pgns.PortalLeafRecord, nowFn func() time.Time) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         fqdn,
		NextProtos:         []string{types.ALPNPortalCBV1},
		InsecureSkipVerify: true, // Authenticated via SPKI pin + portal-cb-v1 OwnerPubKey channel binding.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPGNSConnectionState(cs, fqdn, leaf, nowFn())
		},
	}
}

func verifyPGNSConnectionState(cs tls.ConnectionState, fqdn string, leaf pgns.PortalLeafRecord, now time.Time) error {
	if cs.NegotiatedProtocol != types.ALPNPortalCBV1 {
		return fmt.Errorf("%w: got %q", errPGNSALPNMismatch, cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) == 0 {
		return errPGNSPeerCertificateEmpty
	}
	cert := cs.PeerCertificates[0]
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("%w: peer certificate outside validity window", errPGNSSPKIMismatch)
	}
	if err := cert.VerifyHostname(fqdn); err != nil {
		return err
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	matchesCurrent := subtle.ConstantTimeCompare(spki[:], leaf.TLSSPKISHA256[:]) == 1
	matchesNext := leaf.NextTLSSPKISHA256 != ([32]byte{}) &&
		subtle.ConstantTimeCompare(spki[:], leaf.NextTLSSPKISHA256[:]) == 1
	if !matchesCurrent && !matchesNext {
		return errPGNSSPKIMismatch
	}
	return nil
}

type pgnsDialResult struct {
	conn net.Conn
	err  error
}

func racePGNSAttempts(
	ctx context.Context,
	targets []netip.AddrPort,
	fqdn string,
	ownerPubKey [33]byte,
	tlsConf *tls.Config,
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error),
) (net.Conn, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	results := make(chan pgnsDialResult, len(targets))
	var wg sync.WaitGroup

	launch := func(idx int) {
		addr := targets[idx].String()
		wg.Go(func() {
			conn, err := dialPGNSAttempt(raceCtx, dialContext, addr, fqdn, ownerPubKey, tlsConf)
			results <- pgnsDialResult{conn: conn, err: err}
		})
	}

	nextIdx := 0
	launch(nextIdx)
	nextIdx++

	var staggerTimer *time.Timer
	var staggerCh <-chan time.Time
	if nextIdx < len(targets) {
		staggerTimer = time.NewTimer(pgnsHappyEyeballsDelay)
		defer staggerTimer.Stop()
		staggerCh = staggerTimer.C
	}

	completed := 0
	var lastErr error
	var winner net.Conn
	for completed < len(targets) && winner == nil {
		select {
		case res := <-results:
			completed++
			if res.conn != nil {
				winner = res.conn
				break
			}
			lastErr = res.err
			if nextIdx < len(targets) {
				launch(nextIdx)
				nextIdx++
				if nextIdx < len(targets) && staggerTimer != nil {
					resetTimer(staggerTimer, pgnsHappyEyeballsDelay)
				} else {
					staggerCh = nil
				}
			}
		case <-staggerCh:
			if nextIdx < len(targets) {
				launch(nextIdx)
				nextIdx++
			}
			if nextIdx < len(targets) && staggerTimer != nil {
				staggerTimer.Reset(pgnsHappyEyeballsDelay)
			} else {
				staggerCh = nil
			}
		case <-ctx.Done():
			lastErr = ctx.Err()
			completed = len(targets)
		}
	}

	raceCancel()
	wg.Wait()
	close(results)
	for res := range results {
		if res.conn != nil {
			_ = res.conn.Close()
		}
	}
	if winner != nil {
		return winner, nil
	}
	if lastErr == nil {
		lastErr = context.Canceled
	}
	return nil, lastErr
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func dialPGNSAttempt(
	ctx context.Context,
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error),
	addr string,
	fqdn string,
	ownerPubKey [33]byte,
	tlsConf *tls.Config,
) (net.Conn, error) {
	rawConn, err := dialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	tlsConn := tls.Client(rawConn, tlsConf.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		stopClose()
		_ = tlsConn.Close()
		return nil, err
	}
	if err := VerifyPGNSChannelBinding(ctx, tlsConn, fqdn, ownerPubKey); err != nil {
		stopClose()
		_ = tlsConn.Close()
		return nil, err
	}
	if !stopClose() {
		_ = tlsConn.Close()
		return nil, ctx.Err()
	}
	return tlsConn, nil
}
