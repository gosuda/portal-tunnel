package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errListenerIsNotReady                                 = errors.New("listener is not ready")
	errListenerIsNotRegistered                            = errors.New("listener is not registered")
	errListenerHostnameIsUnavailable                      = errors.New("listener hostname is unavailable")
	errListenerRelayMaterialsAreUnavailable               = errors.New("listener relay materials are unavailable")
	errListenerRelayCertificatePoolUnavailable            = errors.New("listener relay certificate pool is unavailable")
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
	relayPool := lease.tenantTLS.RelayCertPool()
	if relayPool == nil {
		return nil, errListenerRelayCertificatePoolUnavailable
	}
	return &tls.Config{
		ServerName: lease.hostname,
		RootCAs:    relayPool,
		MinVersion: tls.VersionTLS13,
	}, nil
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
