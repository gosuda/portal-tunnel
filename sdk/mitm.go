package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var errMITMDetected = errors.New("tls termination suspected by self-probe")

// keyingMaterialExporter is the direct TLS 1.3 keying material exporter the
// MITM responder side needs from an accepted TLS connection, so both sides
// can compare exporter values. The keyless_tls t13server conn satisfies it
// through its own RFC 8446 Section 7.5 exporter.
// Stock crypto/tls conns cannot satisfy this interface: Go's tls.Conn does
// not expose the method, and its tls.ConnectionState exporter callback is
// unexported, so external TLS implementations cannot populate it. Those
// conns are served through the ConnectionState snapshot instead (see
// probeExporter); tls.ConnectionState is deliberately never called on
// t13server conns, whose snapshot carries no working callback.
type keyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// probeExporter resolves how the responder side exports keying material from
// an accepted conn. Conns with a native exporter export directly; stock
// crypto/tls conns export through the ConnectionState snapshot, which
// carries Go's own exporter closure. Conns with neither capability report
// false so the caller can skip them before the probe-inspection peek.
func probeExporter(conn net.Conn) (func(label string, context []byte, length int) ([]byte, error), bool) {
	if direct, ok := conn.(keyingMaterialExporter); ok {
		return direct.ExportKeyingMaterial, true
	}
	if stateful, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return func(label string, context []byte, length int) ([]byte, error) {
			state := stateful.ConnectionState()
			return (&state).ExportKeyingMaterial(label, context, length)
		}, true
	}
	return nil, false
}

const (
	mitmProbeExporterLabel = "Portal-MITM-Probe-v1"
	mitmProbePeekTimeout   = 100 * time.Millisecond
	mitmProbeMaxPeekBytes  = 512
	mitmProbePaddingMin    = 96
	mitmProbePaddingMax    = 320

	defaultMITMProbeCooldownMin = 15 * time.Second
	defaultMITMProbeCooldownMax = 45 * time.Second
	defaultMITMProbeJitterMax   = 250 * time.Millisecond
	defaultMITMProbeTimeout     = 30 * time.Second
)

var mitmProbeHTTPPaths = [...]string{
	"/",
	"/index.html",
	"/favicon.ico",
	"/assets/app.js",
	"/api/health",
}

var mitmProbeUserAgents = [...]string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}

type mitmProbeReport struct {
	RelayURL  string
	PublicURL string
	Address   string
	Detected  bool
	Reason    string
}

type mitmProbePending struct {
	expected []byte
	resultCh chan string
}

type mitmProbeNonce [16]byte

type mitmManager struct {
	ctx context.Context
	// responderCapable reports whether terminated tenant connections can
	// export keying material. Only then can the listener answer initiator
	// probes; the manager stays dormant otherwise.
	responderCapable bool
	listener         *listener
	ban              bool

	mu       sync.Mutex
	pending  map[mitmProbeNonce]*mitmProbePending
	inFlight bool
	nextAt   time.Time
}

func newMITMManager(ctx context.Context, listener *listener, ban bool) *mitmManager {
	return &mitmManager{
		ctx:      ctx,
		ban:      ban,
		listener: listener,
		pending:  make(map[mitmProbeNonce]*mitmProbePending),
	}
}

func (m *mitmManager) reset() {
	m.mu.Lock()
	clear(m.pending)
	m.inFlight = false
	m.nextAt = time.Time{}
	m.mu.Unlock()
}

// setResponderCapable arms the responder side once the tenant TLS client is
// known to support keying material export.
func (m *mitmManager) setResponderCapable(capable bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.responderCapable = capable
	m.mu.Unlock()
}

func randomDurationBetween(minDur, maxDur time.Duration) time.Duration {
	if maxDur <= minDur {
		return minDur
	}
	var raw [8]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return minDur
	}
	span := uint64(maxDur - minDur)
	return minDur + time.Duration(binary.LittleEndian.Uint64(raw[:])%span)
}

// buildMITMProbeHTTPRequest constructs an HTTP/1.1 request carrying the hex
// probe nonce in X-Request-ID and variable-length base64 padding in Cookie so
// the post-handshake TLS record length and plaintext structure resemble
// ordinary browser traffic rather than a fixed binary frame (#645).
func buildMITMProbeHTTPRequest(hostname string, nonce mitmProbeNonce, padding []byte) []byte {
	path := mitmProbeHTTPPaths[int(nonce[0])%len(mitmProbeHTTPPaths)]
	ua := mitmProbeUserAgents[int(nonce[1])%len(mitmProbeUserAgents)]
	nonceHex := hex.EncodeToString(nonce[:])
	padToken := base64.RawURLEncoding.EncodeToString(padding)
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nX-Request-ID: %s\r\nCookie: _ps=%s\r\nConnection: close\r\n\r\n",
		path,
		hostname,
		ua,
		nonceHex,
		padToken,
	)
	return []byte(req)
}

func (m *mitmManager) matchPendingProbe(peeked []byte) (mitmProbeNonce, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 {
		return mitmProbeNonce{}, false
	}
	if len(peeked) >= len(mitmProbeNonce{}) {
		var rawNonce mitmProbeNonce
		copy(rawNonce[:], peeked[:len(mitmProbeNonce{})])
		if _, ok := m.pending[rawNonce]; ok {
			return rawNonce, true
		}
	}
	text := string(peeked)
	if !strings.HasPrefix(text, "GET /") {
		return mitmProbeNonce{}, false
	}
	for candidate := range m.pending {
		if strings.Contains(text, hex.EncodeToString(candidate[:])) {
			return candidate, true
		}
	}
	return mitmProbeNonce{}, false
}

func (m *mitmManager) probeTLSPassthrough(ctx context.Context) (mitmProbeReport, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return mitmProbeReport{}, errors.New("listener is not ready")
	}

	lease, ok := l.leaseSnapshot()
	if !ok {
		return mitmProbeReport{}, errors.New("listener is not registered")
	}
	if lease.hostname == "" {
		return mitmProbeReport{}, errors.New("listener hostname is unavailable")
	}

	publicURL := l.publicURLForLease(lease)
	if publicURL == "" {
		return mitmProbeReport{}, errors.New("listener is not registered")
	}

	report := mitmProbeReport{
		RelayURL:  l.api.relayURL.String(),
		PublicURL: publicURL,
		Address:   l.identity.Address,
	}

	probeCtx, cancel := context.WithTimeout(ctx, defaultMITMProbeTimeout)
	defer cancel()

	var nonce mitmProbeNonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return report, fmt.Errorf("generate probe nonce: %w", err)
	}

	dialAddr, err := m.probeDialAddress(publicURL)
	if err != nil {
		return report, err
	}

	if lease.tenantTLS == nil {
		return report, errors.New("listener relay materials are unavailable")
	}
	relayPool := lease.tenantTLS.RelayCertPool()
	if relayPool == nil {
		return report, errors.New("listener relay certificate pool is unavailable")
	}

	probeTLSConf := &tls.Config{
		ServerName: lease.hostname,
		RootCAs:    relayPool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}

	rawConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(probeCtx, "tcp", dialAddr)
	if err != nil {
		return report, fmt.Errorf("dial mitm probe: %w", err)
	}
	tlsConn := tls.Client(rawConn, probeTLSConf)
	defer tlsConn.Close()

	// Reserve the nonce once the TCP connection exists but before the TLS
	// handshake: the reverse side can hand the connection to Accept as soon
	// as its handshake completes, which can race ahead of the probe side
	// exporting keying material. Reserving after the TCP connect keeps the
	// probe-inspection window off address resolution and connection setup.
	resultCh := m.reserveProbe(nonce)
	defer m.releaseProbe(nonce)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		return report, fmt.Errorf("mitm probe tls handshake: %w", err)
	}

	clientState := tlsConn.ConnectionState()
	expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return report, fmt.Errorf("export client probe keying material: %w", err)
	}
	m.attachExpected(nonce, expected)

	paddingLen := mitmProbePaddingMin
	if paddingRange := mitmProbePaddingMax - mitmProbePaddingMin; paddingRange > 0 {
		var paddingSeed [1]byte
		if _, err := io.ReadFull(rand.Reader, paddingSeed[:]); err != nil {
			return report, fmt.Errorf("generate probe padding length: %w", err)
		}
		paddingLen += int(paddingSeed[0]) % (paddingRange + 1)
	}

	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return report, fmt.Errorf("generate probe frame: %w", err)
	}
	frame := buildMITMProbeHTTPRequest(lease.hostname, nonce, padding)
	if _, err := tlsConn.Write(frame); err != nil {
		return report, fmt.Errorf("write mitm probe: %w", err)
	}

	select {
	case reason := <-resultCh:
		report.Detected = reason != ""
		report.Reason = reason
	case <-probeCtx.Done():
		report.Reason = types.MITMProbeReasonProbeTimeout
		if !errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return report, probeCtx.Err()
		}
	}
	return report, nil
}

func (m *mitmManager) probeDialAddress(publicURL string) (string, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return "", errors.New("listener is not ready")
	}
	parsedURL, err := url.Parse(publicURL)
	if err != nil {
		return "", fmt.Errorf("parse public url: %w", err)
	}

	dialHost := parsedURL.Host
	entryRelayURL, err := url.Parse(l.api.relayURL.String())
	if err != nil {
		return "", fmt.Errorf("parse ingress relay url: %w", err)
	}
	if utils.IsLocalRelayHost(entryRelayURL.Hostname()) {
		dialHost = entryRelayURL.Host
	}
	return utils.EnsurePort(dialHost), nil
}

func (m *mitmManager) maybeStart() {
	m.mu.Lock()
	capable := m.responderCapable
	m.mu.Unlock()
	if !capable {
		return
	}
	l := m.listener
	if l.cache != nil {
		return // This exposure explicitly permits relay TLS termination.
	}
	select {
	case <-l.doneCh:
		return
	default:
	}

	now := time.Now()
	m.mu.Lock()
	if m.inFlight || (!m.nextAt.IsZero() && now.Before(m.nextAt)) {
		m.mu.Unlock()
		return
	}
	m.inFlight = true
	m.mu.Unlock()

	go func() {
		if jitter := randomDurationBetween(0, defaultMITMProbeJitterMax); jitter > 0 {
			if !utils.SleepOrDone(m.ctx, jitter) {
				m.mu.Lock()
				m.inFlight = false
				m.mu.Unlock()
				return
			}
		}
		report, err := m.probeTLSPassthrough(m.ctx)
		success := err == nil && report.Reason != types.MITMProbeReasonProbeTimeout
		m.mu.Lock()
		m.inFlight = false
		if success {
			m.nextAt = time.Now().Add(randomDurationBetween(defaultMITMProbeCooldownMin, defaultMITMProbeCooldownMax))
		}
		m.mu.Unlock()
		m.logResult(report, err)
	}()
}

func (m *mitmManager) logResult(report mitmProbeReport, err error) {
	l := m.listener
	if l == nil {
		return
	}
	closed := false
	select {
	case <-l.doneCh:
		closed = true
	default:
	}
	relayURL := ""
	if l.api != nil && l.api.relayURL != nil {
		relayURL = l.api.relayURL.String()
	}
	switch {
	case closed:
		return
	case err != nil:
		if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return
		}
		log.Warn().
			Err(err).
			Str("relay_url", relayURL).
			Str("address", l.identity.Address).
			Msg("tls passthrough self-probe failed")
	case report.Reason == types.MITMProbeReasonProbeTimeout:
		log.Warn().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls self-probe timed out before passthrough could be verified")
	case report.Detected:
		event := log.Warn().
			Bool("ban_mitm", m.ban).
			Str("reason", report.Reason).
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address)
		if m.ban {
			event.Msg("tls termination suspected by self-probe; closing listener")
			l.report(listenerStatus{state: RelayFailed, failure: RelayFailureMITM, err: errMITMDetected})
			_ = l.Close()
			return
		}
		event.Msg("tls termination suspected by self-probe")
	default:
		log.Debug().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls passthrough self-probe passed")
	}
}

func (m *mitmManager) maybeHandleConn(conn net.Conn) (net.Conn, bool, error) {
	if conn == nil {
		return conn, false, nil
	}

	m.mu.Lock()
	hasPending := len(m.pending) > 0
	m.mu.Unlock()
	if !hasPending {
		return conn, false, nil
	}

	exportFn, ok := probeExporter(conn)
	if !ok {
		return conn, false, nil
	}

	reader := bufio.NewReaderSize(conn, mitmProbeMaxPeekBytes)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	_, _ = reader.Peek(len(mitmProbeNonce{}))
	peeked, _ := reader.Peek(reader.Buffered())
	defer conn.SetReadDeadline(time.Time{})
	if len(peeked) < len(mitmProbeNonce{}) {
		return wrapBufferedConn(conn, reader), false, nil
	}

	nonce, ok := m.matchPendingProbe(peeked)
	if !ok {
		return wrapBufferedConn(conn, reader), false, nil
	}

	defer conn.Close()

	actual, err := exportFn(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return nil, true, fmt.Errorf("export server probe keying material: %w", err)
	}

	m.completeProbe(nonce, actual)
	return nil, true, nil
}

// reserveProbe registers the probe nonce before the TLS dial so the reverse
// side recognizes the connection even if Accept runs the moment the reverse
// handshake completes. attachExpected arms the reservation afterwards; until
// then the entry holds no exporter value and a completion attempt reports a
// mismatch.
func (m *mitmManager) reserveProbe(nonce mitmProbeNonce) <-chan string {
	state := &mitmProbePending{
		resultCh: make(chan string, 1),
	}
	m.mu.Lock()
	m.pending[nonce] = state
	m.mu.Unlock()

	return state.resultCh
}

func (m *mitmManager) releaseProbe(nonce mitmProbeNonce) {
	m.mu.Lock()
	delete(m.pending, nonce)
	m.mu.Unlock()
}

// attachExpected arms a reserved probe with the exporter value the reverse
// side must reproduce for the connection to count as untampered.
func (m *mitmManager) attachExpected(nonce mitmProbeNonce, expected []byte) {
	m.mu.Lock()
	if state := m.pending[nonce]; state != nil {
		state.expected = bytes.Clone(expected)
	}
	m.mu.Unlock()
}

func (m *mitmManager) completeProbe(nonce mitmProbeNonce, actual []byte) {
	m.mu.Lock()
	state := m.pending[nonce]
	if state == nil {
		m.mu.Unlock()
		return
	}
	reason := ""
	if !bytes.Equal(state.expected, actual) {
		reason = types.MITMProbeReasonExporterMismatch
	}
	resultCh := state.resultCh
	m.mu.Unlock()

	select {
	case resultCh <- reason:
	default:
	}
}

type mitmProbeConn struct {
	net.Conn
	manager   *mitmManager
	startOnce sync.Once
}

func (c *mitmProbeConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (c *mitmProbeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.startOnce.Do(func() {
			c.manager.maybeStart()
		})
	}
	return n, err
}

func (c *mitmProbeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.startOnce.Do(func() {
			c.manager.maybeStart()
		})
	}
	return n, err
}
