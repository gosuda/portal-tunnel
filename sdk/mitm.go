package sdk

import (
	"bufio"
	"bytes"
	"cmp"
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
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errListenerIsNotReady                                 = errors.New("listener is not ready")
	errListenerIsNotRegistered                            = errors.New("listener is not registered")
	errListenerHostnameIsUnavailable                      = errors.New("listener hostname is unavailable")
	errListenerRelayMaterialsAreUnavailable               = errors.New("listener relay materials are unavailable")
	errTLSConnectionIsRequired                            = errors.New("tls connection is required")
	errTLSConnectionDoesNotSupportKeying                  = errors.New("tls connection does not support keying material export")
	errTunnelDidNotAnswerChannelBinding                   = errors.New("tunnel did not answer channel binding")
	errTLSChannelBindingExporterMismatchRelay             = errors.New("tls channel binding exporter mismatch: relay terminated client tls")
	errListenerCanonicalHostnameUnavailableChannelBinding = errors.New("listener canonical hostname is unavailable for channel binding")
)

var errMITMDetected = errors.New("tls termination suspected by self-probe")

type keyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

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

	defaultChannelBindingTimeout = 10 * time.Second
)

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
	listener *listener
	ban      bool

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

func (m *mitmManager) probeTLSPassthrough(ctx context.Context) (mitmProbeReport, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return mitmProbeReport{}, errListenerIsNotReady
	}

	lease, ok := l.leaseSnapshot()
	if !ok {
		return mitmProbeReport{}, errListenerIsNotRegistered
	}
	if endpoint, ok := lease.tenantTLS.(*namespaceTLS); ok {
		// Probe the relay-owned certificate path even before local issuance is
		// ready. The canonical hostname uses independent local TLS material.
		lease.hostname = lease.legacyHostname
		lease.tenantTLS = endpoint.legacy
	}
	if lease.hostname == "" {
		return mitmProbeReport{}, errListenerHostnameIsUnavailable
	}

	publicURL := l.publicURLForLease(lease)
	if publicURL == "" {
		return mitmProbeReport{}, errListenerIsNotRegistered
	}

	report := mitmProbeReport{
		RelayURL:  l.api.relayURL.String(),
		PublicURL: publicURL,
		Address:   l.identity.Address,
	}

	probeCtx, cancel := context.WithTimeout(ctx, defaultMITMProbeTimeout)
	defer cancel()
	nonce, frame, dialAddr, probeTLSConf, err := m.prepareprobeTLSPassthroughDial(publicURL, lease)
	if err != nil {
		return report, err
	}
	_, tlsConn, stopClose, err := dialProbeTLS(probeCtx, dialAddr, probeTLSConf)
	if err != nil {
		return report, err
	}
	defer tlsConn.Close()
	defer stopClose()
	resultCh := m.reserveProbe(nonce)
	defer m.releaseProbe(nonce)
	if err := m.finishprobeTLSPassthroughHandshake(probeCtx, tlsConn, nonce, frame); err != nil {
		return report, err
	}
	return collectProbeResult(probeCtx, resultCh, report)
}

func (m *mitmManager) prepareprobeTLSPassthroughDial(publicURL string, lease listenerSnapshot) (mitmProbeNonce, []byte, string, *tls.Config, error) {
	var nonce mitmProbeNonce
	var frame []byte
	n, f, err := generateProbeFrame()
	if err != nil {
		return nonce, nil, "", nil, err
	}
	nonce, frame = n, f
	var dialAddr string
	d, err := m.probeDialAddress(publicURL)
	if err != nil {
		return nonce, nil, "", nil, err
	}
	dialAddr = d
	var probeTLSConf *tls.Config
	c, err := probeTLSConfig(lease)
	if err != nil {
		return nonce, nil, "", nil, err
	}
	probeTLSConf = c
	return nonce, frame, dialAddr, probeTLSConf, nil
}

func (m *mitmManager) finishprobeTLSPassthroughHandshake(probeCtx context.Context, tlsConn *tls.Conn, nonce mitmProbeNonce, frame []byte) error {
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		return fmt.Errorf("mitm probe tls handshake: %w", err)
	}
	clientState := tlsConn.ConnectionState()
	var expected []byte
	e, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return fmt.Errorf("export client probe keying material: %w", err)
	}
	expected = e
	m.attachExpected(nonce, expected)
	if _, err := tlsConn.Write(frame); err != nil {
		return fmt.Errorf("write mitm probe: %w", err)
	}
	return nil
}

func collectProbeResult(probeCtx context.Context, resultCh <-chan string, report mitmProbeReport) (mitmProbeReport, error) {
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

func generateProbeFrame() (mitmProbeNonce, []byte, error) {
	var nonce mitmProbeNonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nonce, nil, fmt.Errorf("generate probe nonce: %w", err)
	}
	paddingLen := mitmProbePaddingMin
	if paddingRange := mitmProbePaddingMax - mitmProbePaddingMin; paddingRange > 0 {
		var paddingSeed [1]byte
		if _, err := io.ReadFull(rand.Reader, paddingSeed[:]); err != nil {
			return nonce, nil, fmt.Errorf("generate probe padding length: %w", err)
		}
		paddingLen += int(paddingSeed[0]) % (paddingRange + 1)
	}
	frame := make([]byte, len(nonce)+paddingLen)
	if _, err := io.ReadFull(rand.Reader, frame); err != nil {
		return nonce, nil, fmt.Errorf("generate probe frame: %w", err)
	}
	copy(frame, nonce[:])
	return nonce, frame, nil
}

func probeTLSConfig(lease listenerSnapshot) (*tls.Config, error) {
	if lease.tenantTLS == nil {
		return nil, errListenerRelayMaterialsAreUnavailable
	}
	return lease.tenantTLS.TenantTLSConfig(), nil
}

func dialProbeTLS(probeCtx context.Context, dialAddr string, probeTLSConf *tls.Config) (net.Conn, *tls.Conn, func() bool, error) {
	rawConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(probeCtx, "tcp", dialAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial mitm probe: %w", err)
	}
	tlsConn := tls.Client(rawConn, probeTLSConf)
	deadline, _ := probeCtx.Deadline()
	if err := rawConn.SetDeadline(deadline); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, fmt.Errorf("set mitm probe deadline: %w", err)
	}
	stopClose := context.AfterFunc(probeCtx, func() { _ = rawConn.Close() })
	return rawConn, tlsConn, stopClose, nil
}

func (m *mitmManager) probeDialAddress(publicURL string) (string, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return "", errListenerIsNotReady
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

func (m *mitmManager) run(ctx context.Context, ready <-chan struct{}) {
	if m.listener.cache != nil || runtime.GOOS == "js" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-ready:
	}
	budget := rate.NewLimiter(rate.Every(defaultMITMProbeInterval), mitmProbeBurst)
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		if m.listener.readySessions.Load() > 0 {
			var stop bool
			backoff, stop = m.probeCycle(ctx, budget, backoff)
			if stop {
				return
			}
		}

		delay := min(time.Duration(mathrand.ExpFloat64()*float64(defaultMITMProbeInterval)), defaultMITMProbeMaxDelay)
		delay = max(delay, backoff)
		if !utils.SleepOrDone(ctx, delay) {
			return
		}
	}
}

func (m *mitmManager) probeCycle(ctx context.Context, budget *rate.Limiter, backoff time.Duration) (time.Duration, bool) {
	if err := budget.Wait(ctx); err != nil {
		return backoff, true
	}
	report, err := m.probeTLSPassthrough(ctx)
	if ctx.Err() != nil {
		return backoff, true
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
	return backoff, false
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
		m.reportProbeDetection(l, report)
	default:
		log.Debug().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls passthrough self-probe passed")
	}
}

func (m *mitmManager) reportProbeDetection(l *listener, report mitmProbeReport) {
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
}

// VerifyTLSChannelBinding performs the client-side identity-bound TLS channel
// binding handshake (#653) on an established TLS connection to a canonical
// Portal hostname. It verifies that the tunnel endpoint terminated the exact
// same TLS session (Ec == Et) and signed (context || hostname || nonce || Et)
// with the secp256k1 identity embedded in hostname. On any mismatch, it closes
// conn immediately so no application bytes are ever sent over a MITMed stream.
// A reply without the answer tag, such as one from a tunnel that does not
// offer binding, also closes conn, with an error that says the tunnel did not
// answer rather than an exporter mismatch.
//
// hostname must be the lease's canonical hostname exactly as the relay
// publishes it: the tunnel signs that name, so another canonical form that
// embeds the same address fails with a signer mismatch. The exchange ends,
// closing conn, as soon as ctx is done. It sets a deadline on conn and clears
// it when it returns, so a deadline set earlier does not survive; set it again
// afterwards.
func VerifyTLSChannelBinding(ctx context.Context, conn net.Conn, hostname string) error {
	if conn == nil {
		return errTLSConnectionIsRequired
	}
	var clientExporter []byte
	var expectedAddr string
	var nonce [types.TLSChannelBindingNonceSize]byte
	c, e, n, err := prepareChannelBindingClient(conn, hostname)
	if err != nil {
		return err
	}
	clientExporter, expectedAddr, nonce = c, e, n
	_ = conn.SetDeadline(time.Now().Add(defaultChannelBindingTimeout))
	defer conn.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	flow := &exchangeVerifyTLSChannelBindingFlow{
		conn:           conn,
		hostname:       hostname,
		nonce:          nonce,
		clientExporter: clientExporter,
		expectedAddr:   expectedAddr,
		stop:           stop,
	}
	return flow.completeVerifyTLSChannelBinding(ctx)
}

func prepareChannelBindingClient(conn net.Conn, hostname string) ([]byte, string, [types.TLSChannelBindingNonceSize]byte, error) {
	var nonce [types.TLSChannelBindingNonceSize]byte
	var expectedAddr string
	e, err := namespace.CanonicalAddress(hostname)
	if err != nil {
		_ = conn.Close()
		return nil, "", nonce, err
	}
	expectedAddr = e
	exportFn, ok := probeExporter(conn)
	if !ok {
		_ = conn.Close()
		return nil, "", nonce, errTLSConnectionDoesNotSupportKeying
	}
	var clientExporter []byte
	c, err := exportFn(types.TLSChannelBindingExporterLabel, nil, types.TLSChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return nil, "", nonce, fmt.Errorf("export client tls keying material: %w", err)
	}
	clientExporter = c
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = conn.Close()
		return nil, "", nonce, fmt.Errorf("generate channel binding nonce: %w", err)
	}
	return clientExporter, expectedAddr, nonce, nil
}

type exchangeVerifyTLSChannelBindingFlow struct {
	conn           net.Conn
	hostname       string
	nonce          [types.TLSChannelBindingNonceSize]byte
	clientExporter []byte
	expectedAddr   string
	stop           func() bool
}

func (f *exchangeVerifyTLSChannelBindingFlow) completeVerifyTLSChannelBinding(ctx context.Context) error {
	reqFrame := make([]byte, types.TLSChannelBindingRequestSize)
	copy(reqFrame, types.TLSChannelBindingRequestMagic)
	copy(reqFrame[len(types.TLSChannelBindingRequestMagic):], f.nonce[:])
	if _, err := f.conn.Write(reqFrame); err != nil {
		_ = f.conn.Close()
		return fmt.Errorf("write channel binding request: %w", cmp.Or(ctx.Err(), err))
	}
	var compactSig []byte
	s, err := f.readBindingFlowAnswer(ctx)
	if err != nil {
		return err
	}
	compactSig = s
	if err := verifyChannelBindingSigner(f.hostname, f.nonce[:], f.clientExporter, f.expectedAddr, compactSig); err != nil {
		_ = f.conn.Close()
		return err
	}
	if !f.stop() {
		_ = f.conn.Close()
		return ctx.Err()
	}
	return nil
}

func (f *exchangeVerifyTLSChannelBindingFlow) readBindingFlowAnswer(ctx context.Context) ([]byte, error) {
	tunnelExporter, compactSig, err := readChannelBindingAnswer(ctx, f.conn)
	if err != nil {
		_ = f.conn.Close()
		return nil, err
	}
	if subtle.ConstantTimeCompare(f.clientExporter, tunnelExporter) != 1 {
		_ = f.conn.Close()
		return nil, errTLSChannelBindingExporterMismatchRelay
	}
	return compactSig, nil
}

func readChannelBindingAnswer(ctx context.Context, conn net.Conn) ([]byte, []byte, error) {
	var answer [types.TLSChannelBindingAnswerSize]byte
	tag := answer[:len(types.TLSChannelBindingAnswerTag)]
	if _, err := io.ReadFull(conn, tag); err != nil {
		return nil, nil, fmt.Errorf("read channel binding answer: %w", cmp.Or(ctx.Err(), err))
	}
	if string(tag) != types.TLSChannelBindingAnswerTag {
		return nil, nil, errTunnelDidNotAnswerChannelBinding
	}
	signed := answer[len(tag):]
	if _, err := io.ReadFull(conn, signed); err != nil {
		return nil, nil, fmt.Errorf("read channel binding answer: %w", cmp.Or(ctx.Err(), err))
	}
	tunnelExporter := append([]byte(nil), signed[:types.TLSChannelBindingExporterSize]...)
	compactSig := append([]byte(nil), signed[types.TLSChannelBindingExporterSize:]...)
	return tunnelExporter, compactSig, nil
}

// DialCanonicalTLS dials addr, completes a TLS 1.3 handshake for the canonical
// Portal hostname, and enforces identity-bound TLS channel binding (#653)
// before returning the connection for application traffic.
func DialCanonicalTLS(ctx context.Context, addr, hostname string, baseTLSConfig *tls.Config) (net.Conn, error) {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	if _, err := namespace.CanonicalAddress(normalizedHost); err != nil {
		return nil, err
	}
	tlsConf := buildDialCanonicalTLSConfig(normalizedHost, baseTLSConfig)
	tlsConn, err := dialCanonicalTLSTransport(ctx, addr, tlsConf)
	if err != nil {
		return nil, err
	}
	if err := VerifyTLSChannelBinding(ctx, tlsConn, normalizedHost); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func buildDialCanonicalTLSConfig(normalizedHost string, baseTLSConfig *tls.Config) *tls.Config {
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
	return tlsConf
}

func dialCanonicalTLSTransport(ctx context.Context, addr string, tlsConf *tls.Config) (*tls.Conn, error) {
	var rawConn net.Conn
	c, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, "tcp", utils.EnsurePort(addr))
	if err != nil {
		return nil, err
	}
	rawConn = c
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func tlsChannelBindingPayload(hostname string, nonce, exported []byte) []byte {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	buf := make([]byte, 0, len(types.TLSChannelBindingDomain)+1+len(normalizedHost)+1+len(nonce)+len(exported))
	buf = append(buf, types.TLSChannelBindingDomain...)
	buf = append(buf, 0)
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, nonce...)
	buf = append(buf, exported...)
	return buf
}
func verifyChannelBindingSigner(hostname string, nonce, clientExporter []byte, expectedAddr string, compactSig []byte) error {
	payload := tlsChannelBindingPayload(hostname, nonce, clientExporter)
	pubKey, err := identity.RecoverSHA256Secp256k1Compact(payload, compactSig)
	if err != nil {
		return fmt.Errorf("recover channel binding signer: %w", err)
	}
	recoveredAddr, err := identity.AddressFromCompressedPublicKeyHex(hex.EncodeToString(pubKey.SerializeCompressed()))
	if err != nil {
		return fmt.Errorf("resolve channel binding signer address: %w", err)
	}
	if !strings.EqualFold(recoveredAddr, expectedAddr) {
		return fmt.Errorf("tls channel binding signer %s does not match canonical hostname identity %s", recoveredAddr, expectedAddr)
	}
	return nil
}
func (m *mitmManager) serveChannelBindingHandshake(conn net.Conn, reader *bufio.Reader, exportFn func(string, []byte, int) ([]byte, error)) (net.Conn, error) {
	l := m.listener
	hostname := ""
	if lease, ok := l.leaseSnapshot(); ok {
		hostname = lease.hostname
		if stateful, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			if sni := utils.NormalizeHostname(stateful.ConnectionState().ServerName); sni != "" {
				if sni != lease.hostname && sni != lease.legacyHostname {
					_ = conn.Close()
					return nil, errListenerCanonicalHostnameUnavailableChannelBinding
				}
				hostname = sni
			}
		}
	}
	if hostname == "" {
		_ = conn.Close()
		return nil, errListenerCanonicalHostnameUnavailableChannelBinding
	}
	var reqFrame [types.TLSChannelBindingRequestSize]byte
	if _, err := io.ReadFull(reader, reqFrame[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read channel binding request: %w", err)
	}
	nonce := bytes.Clone(reqFrame[len(types.TLSChannelBindingRequestMagic):])
	var exported []byte
	e, err := exportFn(types.TLSChannelBindingExporterLabel, nil, types.TLSChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("export server channel binding keying material: %w", err)
	}
	exported = e
	var compactSig []byte
	s, err := signChannelBindingPayload(hostname, nonce, exported, l.identity)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	compactSig = s
	return m.writeChannelBindingAnswer(conn, reader, exported, compactSig)
}

func signChannelBindingPayload(hostname string, nonce, exported []byte, id types.Identity) ([]byte, error) {
	payload := tlsChannelBindingPayload(hostname, nonce, exported)
	authority := identity.NewLocalAuthority(id)
	var compactSig []byte
	sig, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		return nil, fmt.Errorf("sign channel binding payload: %w", err)
	}
	c, err := sig.Compact()
	if err != nil {
		return nil, fmt.Errorf("encode channel binding signature: %w", err)
	}
	compactSig = c
	return compactSig, nil
}

func (m *mitmManager) writeChannelBindingAnswer(conn net.Conn, reader *bufio.Reader, exported, compactSig []byte) (net.Conn, error) {
	var answer [types.TLSChannelBindingAnswerSize]byte
	n := copy(answer[:], types.TLSChannelBindingAnswerTag)
	n += copy(answer[n:], exported)
	copy(answer[n:], compactSig)
	_ = conn.SetWriteDeadline(time.Now().Add(channelBindingRequestTimeout))
	if _, err := conn.Write(answer[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write channel binding answer: %w", err)
	}
	return wrapBufferedConn(conn, reader), nil
}

func (m *mitmManager) maybeHandleConn(conn net.Conn) (net.Conn, bool, error) {
	if conn == nil {
		return conn, false, nil
	}
	// HTTP/2 framing starts immediately after ALPN. Native channel binding
	// uses the HTTP/1.1/raw path, never an h2 application stream.
	if conn, ok := conn.(*tls.Conn); ok && conn.ConnectionState().NegotiatedProtocol == "h2" {
		return conn, false, nil
	}

	exportFn, ok := probeExporter(conn)
	if !ok {
		return conn, false, nil
	}

	m.mu.Lock()
	hasPending := len(m.pending) > 0
	m.mu.Unlock()

	canChannelBind := m.listener != nil && m.listener.cache == nil
	if m.listener != nil && m.listener.cache != nil {
		if lease, ok := m.listener.leaseSnapshot(); ok {
			if conn, ok := conn.(*tls.Conn); ok {
				_, canonical := lease.tenantTLS.(*namespaceTLS)
				canChannelBind = canonical && utils.NormalizeHostname(conn.ConnectionState().ServerName) == lease.hostname
			}
		}
	}
	if !hasPending && !canChannelBind {
		return conn, false, nil
	}

	frameSize := len(mitmProbeNonce{})
	peekLen := len(types.TLSChannelBindingRequestMagic)
	if hasPending {
		peekLen = frameSize
	}
	reader := bufio.NewReaderSize(conn, frameSize)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	peeked, _ := reader.Peek(peekLen)
	defer conn.SetDeadline(time.Time{})

	if canChannelBind && bytes.HasPrefix(peeked, []byte(types.TLSChannelBindingRequestMagic)) {

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
	return m.consumePendingProbe(conn, reader, exportFn, peeked)
}

func (m *mitmManager) consumePendingProbe(conn net.Conn, reader *bufio.Reader, exportFn func(string, []byte, int) ([]byte, error), peeked []byte) (net.Conn, bool, error) {
	frameSize := len(mitmProbeNonce{})
	var nonce mitmProbeNonce
	copy(nonce[:], peeked[:frameSize])
	m.mu.Lock()
	_, ok := m.pending[nonce]
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
