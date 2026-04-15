package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	mitmProbeExporterLabel = "Portal-MITM-Probe-v1"
	mitmProbePeekTimeout   = 100 * time.Millisecond
	mitmProbePaddingMin    = 96
	mitmProbePaddingMax    = 320

	defaultMITMProbeCooldown = 30 * time.Second
	defaultMITMProbeTimeout  = 5 * time.Second
)

type MITMProbeReport struct {
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

type mitmManager struct {
	ctx      context.Context
	listener *listener
	ban      bool

	mu       sync.Mutex
	pending  map[string]*mitmProbePending
	inFlight bool
	lastAt   time.Time
}

func newMITMManager(ctx context.Context, listener *listener, ban bool) *mitmManager {
	return &mitmManager{
		ctx:      ctx,
		ban:      ban,
		listener: listener,
		pending:  make(map[string]*mitmProbePending),
	}
}

func (m *mitmManager) reset() {
	m.mu.Lock()
	clear(m.pending)
	m.inFlight = false
	m.lastAt = time.Time{}
	m.mu.Unlock()
}

func (m *mitmManager) probeTLSPassthrough(ctx context.Context) (MITMProbeReport, error) {
	l := m.listener
	if l == nil || l.relayURL == nil {
		return MITMProbeReport{}, errors.New("listener is not ready")
	}

	lease, ok := l.leaseSnapshot()
	if !ok {
		return MITMProbeReport{}, errors.New("listener is not registered")
	}
	if lease.hostname == "" {
		return MITMProbeReport{}, errors.New("listener hostname is unavailable")
	}

	publicURL := l.publicURLForHostname(lease.hostname)
	if publicURL == "" {
		return MITMProbeReport{}, errors.New("listener is not registered")
	}

	report := MITMProbeReport{
		RelayURL:  l.relayURL.String(),
		PublicURL: publicURL,
		Address:   l.identity.Address,
	}

	probeCtx, cancel := context.WithTimeout(ctx, defaultMITMProbeTimeout)
	defer cancel()

	nonceRaw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceRaw); err != nil {
		return report, fmt.Errorf("generate probe nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonceRaw)

	dialAddr, err := m.probeDialAddress(publicURL)
	if err != nil {
		return report, err
	}

	probeTLSConf := &tls.Config{
		ServerName:         lease.hostname,
		InsecureSkipVerify: true,
	}
	if lease.tlsConfig != nil {
		probeTLSConf.MinVersion = lease.tlsConfig.MinVersion
		probeTLSConf.MaxVersion = lease.tlsConfig.MaxVersion
		if len(lease.tlsConfig.NextProtos) > 0 {
			probeTLSConf.NextProtos = append([]string(nil), lease.tlsConfig.NextProtos...)
		}
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: l.dialTimeout},
		Config:    probeTLSConf,
	}
	conn, err := dialer.DialContext(probeCtx, "tcp", dialAddr)
	if err != nil {
		return report, fmt.Errorf("dial mitm probe: %w", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return report, errors.New("mitm probe connection is not tls")
	}

	clientState := tlsConn.ConnectionState()
	expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return report, fmt.Errorf("export client probe keying material: %w", err)
	}
	resultCh, cleanupProbe := m.startProbe(nonceHex, expected)
	defer cleanupProbe()

	paddingLen := mitmProbePaddingMin
	if paddingRange := mitmProbePaddingMax - mitmProbePaddingMin; paddingRange > 0 {
		var paddingSeed [1]byte
		if _, err := io.ReadFull(rand.Reader, paddingSeed[:]); err != nil {
			return report, fmt.Errorf("generate probe padding length: %w", err)
		}
		paddingLen += int(paddingSeed[0]) % (paddingRange + 1)
	}

	frame := make([]byte, len(nonceRaw)+paddingLen)
	if _, err := io.ReadFull(rand.Reader, frame); err != nil {
		return report, fmt.Errorf("generate probe frame: %w", err)
	}
	copy(frame, nonceRaw)
	if _, err := conn.Write(frame); err != nil {
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
	if l == nil || l.relayURL == nil {
		return "", errors.New("listener is not ready")
	}
	parsedURL, err := url.Parse(publicURL)
	if err != nil {
		return "", fmt.Errorf("parse public url: %w", err)
	}

	dialHost := parsedURL.Host
	if utils.IsLocalRelayHost(l.relayURL.Hostname()) {
		dialHost = l.relayURL.Host
	}
	return utils.EnsurePort(dialHost), nil
}

func (m *mitmManager) maybeStart() {
	l := m.listener
	select {
	case <-l.doneCh:
		return
	default:
	}

	m.mu.Lock()
	if m.inFlight || !m.lastAt.IsZero() && time.Since(m.lastAt) < defaultMITMProbeCooldown {
		m.mu.Unlock()
		return
	}
	m.inFlight = true
	m.mu.Unlock()

	go func() {
		report, err := m.probeTLSPassthrough(m.ctx)
		success := err == nil && report.Reason != types.MITMProbeReasonProbeTimeout
		m.mu.Lock()
		m.inFlight = false
		if success {
			m.lastAt = time.Now()
		}
		m.mu.Unlock()
		m.logResult(report, err)
	}()
}

func (m *mitmManager) logResult(report MITMProbeReport, err error) {
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
	if l.relayURL != nil {
		relayURL = l.relayURL.String()
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
			event.Msg("tls termination suspected by self-probe; banning relay")
			if l.relaySet != nil && report.RelayURL != "" {
				l.relaySet.UnconfirmRelayURL(report.RelayURL)
				l.relaySet.BanRelayURL(report.RelayURL)
			}
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

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn, false, nil
	}

	frameSize := 16
	reader := bufio.NewReaderSize(conn, frameSize)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	peeked, err := reader.Peek(frameSize)
	defer conn.SetReadDeadline(time.Time{})
	if err != nil {
		return wrapBufferedConn(conn, reader), false, nil
	}

	nonceHex := hex.EncodeToString(peeked[:frameSize])
	m.mu.Lock()
	_, ok = m.pending[nonceHex]
	m.mu.Unlock()
	if !ok {
		return wrapBufferedConn(conn, reader), false, nil
	}

	defer conn.Close()

	frame := make([]byte, frameSize)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, true, fmt.Errorf("read mitm probe frame: %w", err)
	}

	serverState := tlsConn.ConnectionState()
	actual, err := (&serverState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return nil, true, fmt.Errorf("export server probe keying material: %w", err)
	}

	m.completeProbe(nonceHex, actual)
	return nil, true, nil
}

func (m *mitmManager) startProbe(nonce string, expected []byte) (<-chan string, func()) {
	m.mu.Lock()
	state := &mitmProbePending{
		expected: append([]byte(nil), expected...),
		resultCh: make(chan string, 1),
	}
	m.pending[nonce] = state
	m.mu.Unlock()

	return state.resultCh, func() {
		m.mu.Lock()
		delete(m.pending, nonce)
		m.mu.Unlock()
	}
}

func (m *mitmManager) completeProbe(nonce string, actual []byte) {
	m.mu.Lock()
	state := m.pending[nonce]
	m.mu.Unlock()
	if state == nil {
		return
	}

	reason := ""
	if !bytes.Equal(state.expected, actual) {
		reason = types.MITMProbeReasonExporterMismatch
	}

	select {
	case state.resultCh <- reason:
	default:
	}
}

type mitmProbeConn struct {
	net.Conn
	manager   *mitmManager
	startOnce sync.Once
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
