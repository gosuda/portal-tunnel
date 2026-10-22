package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
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
	mitmProbePaddingMin    = 96
	mitmProbePaddingMax    = 320

	defaultMITMProbeInterval   = 45 * time.Second
	defaultMITMProbeMaxDelay   = 120 * time.Second
	defaultMITMProbeRetryDelay = 30 * time.Second
	defaultMITMProbeTimeout    = 30 * time.Second
	mitmProbeBurst             = 3

	tlsChannelBindingExporterLabel = "EXPORTER-Portal-TLS-Channel-Binding-v1"
	tlsChannelBindingDomainContext = "portal-tls-channel-binding-v1"
	tlsChannelBindingMagic         = "PTCB\x01"
	tlsChannelBindingNonceSize     = 32
	tlsChannelBindingExporterSize  = 32
	tlsChannelBindingSignatureSize = 65
	tlsChannelBindingRequestSize   = len(tlsChannelBindingMagic) + tlsChannelBindingNonceSize
	tlsChannelBindingResponseSize  = tlsChannelBindingExporterSize + tlsChannelBindingSignatureSize
	defaultChannelBindingTimeout   = 10 * time.Second
)

// channelBindingRequestTimeout is how long the tunnel waits for the rest of a
// binding request once its magic is recognized. A client sends the 37 bytes at
// once, so this is far shorter than the client's round-trip budget: a client
// that withholds the nonce holds an admitting slot for it without any credential.
const channelBindingRequestTimeout = time.Second

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
	// responderCapable reports whether terminated tenant connections can
	// export keying material. Only then can the listener answer initiator
	// probes; the manager stays dormant otherwise.
	responderCapable bool
	listener         *listener
	ban              bool

	mu      sync.Mutex
	pending map[mitmProbeNonce]*mitmProbePending
}

func newMITMManager(listener *listener, ban bool) *mitmManager {
	return &mitmManager{
		ban:      ban,
		listener: listener,
		pending:  make(map[mitmProbeNonce]*mitmProbePending),
	}
}

func (m *mitmManager) reset() {
	m.mu.Lock()
	clear(m.pending)
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
	}

	rawConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(probeCtx, "tcp", dialAddr)
	if err != nil {
		return report, fmt.Errorf("dial mitm probe: %w", err)
	}
	tlsConn := tls.Client(rawConn, probeTLSConf)
	defer tlsConn.Close()
	deadline, _ := probeCtx.Deadline()
	if err := rawConn.SetDeadline(deadline); err != nil {
		return report, fmt.Errorf("set mitm probe deadline: %w", err)
	}
	stopClose := context.AfterFunc(probeCtx, func() { _ = rawConn.Close() })
	defer stopClose()

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

	frame := make([]byte, len(nonce)+paddingLen)
	if _, err := io.ReadFull(rand.Reader, frame); err != nil {
		return report, fmt.Errorf("generate probe frame: %w", err)
	}
	copy(frame, nonce[:])
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

// run is one worker of runLease. That owner cancels and joins it before
// replacing the lease, so attempts and results cannot overlap lease lifetimes.
func (m *mitmManager) run(ctx context.Context, ready <-chan struct{}) {
	m.mu.Lock()
	capable := m.responderCapable
	m.mu.Unlock()
	if !capable || m.listener.cache != nil || runtime.GOOS == "js" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-ready:
	}
	budget := rate.NewLimiter(rate.Every(defaultMITMProbeInterval), mitmProbeBurst)
	var backoff time.Duration
	for ctx.Err() == nil {
		if m.listener.readySessions.Load() > 0 {
			if err := budget.Wait(ctx); err != nil {
				return
			}
			report, err := m.probeTLSPassthrough(ctx)
			if ctx.Err() != nil {
				return
			}
			m.logResult(report, err)
			if err != nil || report.Reason == types.MITMProbeReasonProbeTimeout {
				if backoff == 0 {
					backoff = defaultMITMProbeRetryDelay
				} else {
					backoff = min(2*backoff, defaultMITMProbeMaxDelay)
				}
			} else {
				backoff = 0
			}
		}
		// Successful comparisons have no fixed quiet interval. Capping the
		// exponential sample, the token budget, and failure backoff make this
		// a bounded renewal schedule rather than a pure Poisson process.
		delay := min(time.Duration(mathrand.ExpFloat64()*float64(defaultMITMProbeInterval)), defaultMITMProbeMaxDelay)
		delay = max(delay, backoff)
		if !utils.SleepOrDone(ctx, delay) {
			return
		}
	}
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

func tlsChannelBindingPayload(hostname string, nonce, exported []byte) []byte {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	buf := make([]byte, 0, len(tlsChannelBindingDomainContext)+1+len(normalizedHost)+1+len(nonce)+len(exported))
	buf = append(buf, tlsChannelBindingDomainContext...)
	buf = append(buf, 0)
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, nonce...)
	buf = append(buf, exported...)
	return buf
}

// VerifyTLSChannelBinding performs the client-side identity-bound TLS channel
// binding handshake (#653) on an established TLS connection to a canonical
// Portal hostname. It verifies that the tunnel endpoint terminated the exact
// same TLS session (Ec == Et) and signed (context || hostname || nonce || Et)
// with the secp256k1 identity embedded in hostname. On any mismatch, it closes
// conn immediately so no application bytes are ever sent over a MITMed stream.
//
// hostname must be the lease's canonical hostname exactly as the relay
// publishes it: the tunnel signs that name, so another canonical form that
// embeds the same address fails with a signer mismatch. The exchange sets a
// deadline on conn and clears it when it returns, so a deadline set earlier
// does not survive; set it again afterwards.
func VerifyTLSChannelBinding(ctx context.Context, conn net.Conn, hostname string) error {
	if conn == nil {
		return errors.New("tls connection is required")
	}
	expectedAddr, err := utils.ExtractCanonicalHostnameAddress(hostname)
	if err != nil {
		_ = conn.Close()
		return err
	}
	expectedAddr, err = identity.NormalizeEVMAddress(expectedAddr)
	if err != nil {
		_ = conn.Close()
		return err
	}
	exportFn, ok := probeExporter(conn)
	if !ok {
		_ = conn.Close()
		return errors.New("tls connection does not support keying material export")
	}
	clientExporter, err := exportFn(tlsChannelBindingExporterLabel, nil, tlsChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("export client tls keying material: %w", err)
	}

	var nonce [tlsChannelBindingNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = conn.Close()
		return fmt.Errorf("generate channel binding nonce: %w", err)
	}

	deadline := time.Now().Add(defaultChannelBindingTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	reqFrame := make([]byte, tlsChannelBindingRequestSize)
	copy(reqFrame, tlsChannelBindingMagic)
	copy(reqFrame[len(tlsChannelBindingMagic):], nonce[:])
	if _, err := conn.Write(reqFrame); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write channel binding request: %w", err)
	}

	var respFrame [tlsChannelBindingResponseSize]byte
	if _, err := io.ReadFull(conn, respFrame[:]); err != nil {
		_ = conn.Close()
		return fmt.Errorf("read channel binding response: %w", err)
	}

	tunnelExporter := respFrame[:tlsChannelBindingExporterSize]
	compactSig := respFrame[tlsChannelBindingExporterSize:]
	if subtle.ConstantTimeCompare(clientExporter, tunnelExporter) != 1 {
		_ = conn.Close()
		return errors.New("tls channel binding exporter mismatch: relay terminated client tls")
	}

	payload := tlsChannelBindingPayload(hostname, nonce[:], clientExporter)
	pubKey, err := identity.RecoverSHA256Secp256k1Compact(payload, compactSig)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("recover channel binding signer: %w", err)
	}
	recoveredAddr, err := identity.AddressFromCompressedPublicKeyHex(hex.EncodeToString(pubKey.SerializeCompressed()))
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("resolve channel binding signer address: %w", err)
	}
	if !strings.EqualFold(recoveredAddr, expectedAddr) {
		_ = conn.Close()
		return fmt.Errorf("tls channel binding signer %s does not match canonical hostname identity %s", recoveredAddr, expectedAddr)
	}
	return nil
}

// DialCanonicalTLS dials addr, completes a TLS 1.3 handshake for the canonical
// Portal hostname, and enforces identity-bound TLS channel binding (#653)
// before returning the connection for application traffic.
func DialCanonicalTLS(ctx context.Context, addr, hostname string, baseTLSConfig *tls.Config) (net.Conn, error) {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	if _, err := utils.ExtractCanonicalHostnameAddress(normalizedHost); err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{}
	if baseTLSConfig != nil {
		tlsConf = baseTLSConfig.Clone()
	}
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = normalizedHost
	}
	if tlsConf.MinVersion < tls.VersionTLS13 {
		tlsConf.MinVersion = tls.VersionTLS13
	}

	rawConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, "tcp", utils.EnsurePort(addr))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if err := VerifyTLSChannelBinding(ctx, tlsConn, normalizedHost); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (m *mitmManager) serveChannelBindingHandshake(conn net.Conn, reader *bufio.Reader, exportFn func(string, []byte, int) ([]byte, error)) (net.Conn, error) {
	l := m.listener
	if l == nil || strings.TrimSpace(l.identity.PrivateKey) == "" {
		_ = conn.Close()
		return nil, errors.New("listener identity signing key is unavailable for channel binding")
	}
	hostname := ""
	if lease, ok := l.leaseSnapshot(); ok {
		hostname = lease.hostname
	}
	if hostname == "" {
		_ = conn.Close()
		return nil, errors.New("listener canonical hostname is unavailable for channel binding")
	}

	var reqFrame [tlsChannelBindingRequestSize]byte
	if _, err := io.ReadFull(reader, reqFrame[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read channel binding request: %w", err)
	}
	nonce := reqFrame[len(tlsChannelBindingMagic):]

	exported, err := exportFn(tlsChannelBindingExporterLabel, nil, tlsChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("export server channel binding keying material: %w", err)
	}

	payload := tlsChannelBindingPayload(hostname, nonce, exported)
	authority := identity.NewLocalAuthority(l.identity)
	sig, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sign channel binding payload: %w", err)
	}
	compactSig, err := sig.Compact()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("encode channel binding signature: %w", err)
	}

	var respFrame [tlsChannelBindingResponseSize]byte
	copy(respFrame[:tlsChannelBindingExporterSize], exported)
	copy(respFrame[tlsChannelBindingExporterSize:], compactSig)
	// The answer is small, but a client that never reads it must not hold the
	// slot either. maybeHandleConn clears the deadline when it returns.
	_ = conn.SetWriteDeadline(time.Now().Add(channelBindingRequestTimeout))
	if _, err := conn.Write(respFrame[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write channel binding response: %w", err)
	}
	return wrapBufferedConn(conn, reader), nil
}

func (m *mitmManager) maybeHandleConn(conn net.Conn) (net.Conn, bool, error) {
	if conn == nil {
		return conn, false, nil
	}

	exportFn, ok := probeExporter(conn)
	if !ok {
		return conn, false, nil
	}

	m.mu.Lock()
	hasPending := len(m.pending) > 0
	capable := m.responderCapable
	m.mu.Unlock()
	// Channel binding shares the self-probe's capability boundary and is not
	// offered for cache exposures, where relay TLS termination is allowed.
	canChannelBind := capable && m.listener != nil && m.listener.cache == nil && strings.TrimSpace(m.listener.identity.PrivateKey) != ""
	if !hasPending && !canChannelBind {
		return conn, false, nil
	}

	// Peek until the preamble that can identify the stream is complete: the
	// probe nonce while a probe is pending, else the channel binding magic.
	// Peek blocks for the full length, so a preamble split across TLS records
	// is still recognized.
	frameSize := len(mitmProbeNonce{})
	peekLen := len(tlsChannelBindingMagic)
	if hasPending {
		peekLen = frameSize
	}
	reader := bufio.NewReaderSize(conn, frameSize)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	peeked, _ := reader.Peek(peekLen)
	defer conn.SetDeadline(time.Time{})

	if canChannelBind && len(peeked) >= len(tlsChannelBindingMagic) && string(peeked[:len(tlsChannelBindingMagic)]) == tlsChannelBindingMagic {
		// The sniff window only covered recognition: the rest of the request
		// gets channelBindingRequestTimeout, far shorter than the client's
		// round-trip budget.
		_ = conn.SetReadDeadline(time.Now().Add(channelBindingRequestTimeout))
		boundConn, err := m.serveChannelBindingHandshake(conn, reader, exportFn)
		if err != nil {
			return nil, true, err
		}
		return boundConn, false, nil
	}

	if len(peeked) != frameSize || !hasPending {
		return wrapBufferedConn(conn, reader), false, nil
	}

	var nonce mitmProbeNonce
	copy(nonce[:], peeked[:frameSize])
	m.mu.Lock()
	_, ok = m.pending[nonce]
	m.mu.Unlock()
	if !ok {
		return wrapBufferedConn(conn, reader), false, nil
	}

	defer conn.Close()

	frame := make([]byte, frameSize)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, true, fmt.Errorf("read mitm probe frame: %w", err)
	}

	actual, err := exportFn(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return nil, true, fmt.Errorf("export server probe keying material: %w", err)
	}

	m.completeProbe(nonce, actual)
	return nil, true, nil
}

// reserveProbe registers the probe nonce before the TLS handshake so the reverse
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
