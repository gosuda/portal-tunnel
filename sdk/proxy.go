package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errPortalSDKExposureIsNil       = errors.New("portal sdk: exposure is nil")
	errPortalSDKLeastOneProxyTarget = errors.New("portal sdk: at least one proxy target is required")
	errRelayDidNotExposeAnyUDP      = errors.New("relay did not expose any UDP listeners")
	errUDPFlowCapacityReached       = errors.New("UDP flow capacity reached")
)

// maxTCPConnections bounds local TCP proxy sockets and workers independently
// of relay admission limits.
const maxTCPConnections = 128

// ProxyConfig selects local TCP and UDP targets.
type ProxyConfig struct {
	TCPTarget string
	UDPTarget string
}

// Proxy copies tenant streams to a local TCP target.
func Proxy(ctx context.Context, exposure *Exposure, target string) error {
	return ProxyWithConfig(ctx, exposure, ProxyConfig{TCPTarget: target})
}

// ProxyUDP copies relayed datagrams to a local UDP target.
func ProxyUDP(ctx context.Context, exposure *Exposure, target string) error {
	return ProxyWithConfig(ctx, exposure, ProxyConfig{UDPTarget: target})
}

// ProxyWithConfig is the sole stream and datagram consumer and closes the
// exposure when proxying stops.
func ProxyWithConfig(ctx context.Context, exposure *Exposure, config ProxyConfig) error {
	if exposure == nil {
		return errPortalSDKExposureIsNil
	}
	if ctx == nil {
		return errPortalSDKContextIsNil
	}

	config, err := normalizeProxyTargets(config)
	if err != nil {
		return err
	}
	if config.TCPTarget == "" && config.UDPTarget == "" {
		return errPortalSDKLeastOneProxyTarget
	}

	tcpTarget := config.TCPTarget
	udpTarget := config.UDPTarget
	exposure.logTunnelStart(tcpTarget, udpTarget)

	proxyCtx, cancel := context.WithCancel(ctx)
	workerCount := 0
	if tcpTarget != "" {
		workerCount++
	}
	if udpTarget != "" {
		workerCount++
	}
	results := make(chan error, workerCount)
	if tcpTarget != "" {
		go func() { results <- proxyRelayConnections(proxyCtx, exposure, tcpTarget) }()
	}
	if udpTarget != "" {
		go func() { results <- runUDPProxy(proxyCtx, exposure, udpTarget) }()
	}

	primary, closeErr := collectProxyResults(ctx, results, workerCount, cancel, exposure)
	if closeErr != nil {
		log.Warn().Err(closeErr).Msg("relay shutdown completed with cleanup errors")
	}

	if ctx.Err() != nil {
		log.Info().Msg("tunnel shutting down")
	}

	log.Info().Msg("tunnel shutdown complete")
	if ctx.Err() != nil {
		primary = nil
		closeErr = nil
	}
	return errors.Join(primary, closeErr)
}

func normalizeProxyTargets(config ProxyConfig) (ProxyConfig, error) {
	if config.TCPTarget != "" {
		target, err := utils.NormalizeLoopbackTarget(config.TCPTarget)
		if err != nil {
			return ProxyConfig{}, err
		}
		config.TCPTarget = target
	}
	if config.UDPTarget != "" {
		target, err := utils.NormalizeLoopbackTarget(config.UDPTarget)
		if err != nil {
			return ProxyConfig{}, err
		}
		config.UDPTarget = target
	}
	return config, nil
}

func (e *Exposure) logTunnelStart(tcpTarget, udpTarget string) {
	identity := e.identity
	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("tcp_target", tcpTarget).
		Str("service_name", identity.Name).
		Strs("relays", e.listenerRelayURLs()).
		Msg("starting portal tunnel; public URLs will be logged as relays become ready")
	if udpTarget != "" {
		log.Info().
			Str("udp_target", udpTarget).
			Str("service_name", identity.Name).
			Msg("udp relay enabled")
	}
}

func collectProxyResults(ctx context.Context, results chan error, workerCount int, cancel context.CancelFunc, exposure *Exposure) (error, error) {
	var primary error
	received := 0
	select {
	case <-ctx.Done():
	case primary = <-results:
		received = 1
	}
	cancel()
	closeErr := exposure.Close()
	for received < workerCount {
		workerErr := <-results
		received++
		if primary == nil && workerErr != nil && !errors.Is(workerErr, context.Canceled) && !errors.Is(workerErr, net.ErrClosed) {
			primary = workerErr
		}
	}
	return primary, closeErr
}

func proxyRelayConnections(ctx context.Context, exposure *Exposure, localAddr string) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	return proxyRelayConnectionsServe(ctx, exposure, localAddr, &workers)
}

func proxyRelayConnectionsAcceptError(ctx context.Context, acceptErr error) error {
	switch {
	case errors.Is(acceptErr, context.Canceled):
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return acceptErr
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(acceptErr, net.ErrClosed):
		return net.ErrClosed
	default:
		return acceptErr
	}
}

func proxyRelayConnectionsTrySlot(slots chan struct{}, relayConn net.Conn) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		_ = relayConn.Close()
		return false
	}
}

func proxyRelayConnectionsServeConn(ctx context.Context, localAddr string, relayConn net.Conn, connID int64) {
	if err := proxyConnection(ctx, localAddr, relayConn); err != nil {
		log.Debug().Err(err).Int64("conn_id", connID).Msg("proxy connection closed with an I/O error")
	}
	log.Debug().Int64("conn_id", connID).Msg("proxy connection closed")
}

func proxyRelayConnectionsServe(ctx context.Context, exposure *Exposure, localAddr string, workers *sync.WaitGroup) error {
	slots := make(chan struct{}, maxTCPConnections)
	var connCount int64
	for {
		relayConn, err := exposure.Accept()
		if err != nil {
			return proxyRelayConnectionsAcceptError(ctx, err)
		}
		if !proxyRelayConnectionsTrySlot(slots, relayConn) {
			continue
		}
		connCount++
		connID := connCount
		log.Debug().
			Int64("conn_id", connID).
			Str("remote_addr", relayConn.RemoteAddr().String()).
			Msg("accepted relay connection")
		workers.Add(1)
		go func(connID int64, relayConn net.Conn) {
			defer workers.Done()
			defer func() { <-slots }()
			proxyRelayConnectionsServeConn(ctx, localAddr, relayConn, connID)
		}(connID, relayConn)
	}
}

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func proxyConnection(ctx context.Context, localAddr string, relayConn net.Conn) error {
	defer relayConn.Close()
	relayClosed := make(chan struct{})
	stopRelay := context.AfterFunc(ctx, func() {
		_ = relayConn.SetDeadline(time.Now())
		_ = relayConn.Close()
		close(relayClosed)
	})
	defer func() {
		if !stopRelay() {
			<-relayClosed
		}
	}()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		return answerOriginUnavailable(ctx, relayConn)
	}
	defer localConn.Close()
	localClosed := make(chan struct{})
	stopLocal := context.AfterFunc(ctx, func() {
		_ = localConn.Close()
		close(localClosed)
	})
	defer func() {
		if !stopLocal() {
			<-localClosed
		}
	}()

	firstErr := relayProxyCopies(localConn, relayConn)
	if errors.Is(firstErr, io.EOF) || errors.Is(firstErr, net.ErrClosed) {
		return nil
	}
	return firstErr
}

func answerOriginUnavailable(ctx context.Context, relayConn net.Conn) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_ = relayConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return writeEmptyHTTPResponse(relayConn)
}

func relayProxyCopies(localConn, relayConn net.Conn) error {
	errCh := make(chan error, 2)

	go relayProxyCopiesForward(localConn, relayConn, errCh)

	go relayProxyCopiesBackward(localConn, relayConn, errCh)

	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func relayProxyCopiesForward(localConn, relayConn net.Conn, errCh chan error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	_, err := io.CopyBuffer(localConn, relayConn, *bufPtr)
	if err != nil {
		_ = relayConn.SetDeadline(time.Now())
		_ = relayConn.Close()
		_ = localConn.Close()
	} else if tcpConn, ok := localConn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	errCh <- err
}

func relayProxyCopiesBackward(localConn, relayConn net.Conn, errCh chan error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	_, err := io.CopyBuffer(relayConn, localConn, *bufPtr)
	if err != nil {
		_ = relayConn.SetDeadline(time.Now())
		_ = relayConn.Close()
		_ = localConn.Close()
	} else if half, ok := relayConn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
	errCh <- err
}

func writeEmptyHTTPResponse(conn net.Conn) error {
	htmlBody := `<!DOCTYPE html>
<html>
<head><title>Service Unavailable</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
<h1>Service Unavailable</h1>
<p>The local service is not currently running.</p>
<p>Please start your local application and refresh this page.</p>
</body>
</html>`
	response := fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", len(htmlBody), htmlBody)
	_, err := conn.Write([]byte(response))
	return err
}

func runUDPProxy(ctx context.Context, exposure *Exposure, udpTarget string) error {
	udpRelays, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return ctx.Err()
		}
		return fmt.Errorf("wait for udp readiness: %w", err)
	}
	if len(udpRelays) == 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errRelayDidNotExposeAnyUDP
	}

	for _, relay := range udpRelays {
		log.Info().
			Str("udp_addr", relay.UDPAddr).
			Str("relay_url", relay.RelayURL).
			Msg("UDP tunnel ready")
	}

	return proxyExposureDatagrams(ctx, exposure, udpTarget)
}

func proxyExposureDatagrams(ctx context.Context, exposure *Exposure, localAddr string) error {
	resolvedAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr %q: %w", localAddr, err)
	}
	return proxyExposureDatagramsServe(ctx, exposure, resolvedAddr, localAddr)
}

func proxyExposureDatagramsServe(ctx context.Context, exposure *Exposure, resolvedAddr *net.UDPAddr, localAddr string) error {
	mgr := newUDPFlowManager(resolvedAddr, exposure)
	mgr.workers.Add(1)
	go func() { defer mgr.workers.Done(); mgr.runCleanup(ctx) }()
	defer mgr.Close()
	log.Info().Str("target", localAddr).Msg("udp proxy loop started, waiting for datagrams")
	return proxyExposureDatagramsLoop(ctx, exposure, mgr, localAddr)
}

func proxyExposureDatagramsLoop(ctx context.Context, exposure *Exposure, mgr *udpFlowManager, localAddr string) error {
	for {
		frame, err := exposure.AcceptDatagram()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				break
			}
			return fmt.Errorf("accept datagram: %w", err)
		}
		proxyExposureDatagramsForward(ctx, mgr, frame, localAddr)
	}
	return nil
}

func proxyExposureDatagramsForward(ctx context.Context, mgr *udpFlowManager, frame types.DatagramFrame, localAddr string) {
	log.Debug().
		Uint32("flow_id", frame.FlowID).
		Int("bytes", len(frame.Payload)).
		Str("address", frame.Address).
		Str("relay_url", frame.RelayURL).
		Str("udp_addr", frame.UDPAddr).
		Str("target", localAddr).
		Msg("datagram received from relay, forwarding to local")
	localConn, err := mgr.getOrCreate(ctx, frame)
	if err != nil {
		return
	}
	if _, err := localConn.Write(frame.Payload); err != nil {
		log.Warn().
			Err(err).
			Uint32("flow_id", frame.FlowID).
			Str("address", frame.Address).
			Str("relay_url", frame.RelayURL).
			Msg("write to local udp failed")
	}
}

type udpFlowKey struct {
	flowID    uint32
	address   string
	relayURL  string
	leaseDone <-chan struct{}
}

type udpFlowEntry struct {
	conn     *net.UDPConn
	lastSeen time.Time
	frame    types.DatagramFrame
}

type udpFlowManager struct {
	target   *net.UDPAddr
	exposure *Exposure
	mu       sync.Mutex
	flows    map[udpFlowKey]*udpFlowEntry
	done     chan struct{}
	workers  sync.WaitGroup
	readers  int
}

func newUDPFlowManager(target *net.UDPAddr, exposure *Exposure) *udpFlowManager {
	return &udpFlowManager{
		target:   target,
		exposure: exposure,
		flows:    make(map[udpFlowKey]*udpFlowEntry),
		done:     make(chan struct{}),
	}
}

func (m *udpFlowManager) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.closeSockets()
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for key, f := range m.flows {
				if now.Sub(f.lastSeen) > types.DefaultUDPFlowIdleTimeout {
					_ = f.conn.Close()
					delete(m.flows, key)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *udpFlowManager) Close() {
	m.closeSockets()
	m.workers.Wait()
}

func (m *udpFlowManager) closeSockets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return
	default:
		close(m.done)
	}
	for key, entry := range m.flows {
		_ = entry.conn.Close()
		delete(m.flows, key)
	}
}

func (m *udpFlowManager) getOrCreate(ctx context.Context, frame types.DatagramFrame) (*net.UDPConn, error) {
	key := udpFlowKey{flowID: frame.FlowID, address: frame.Address, relayURL: frame.RelayURL, leaseDone: frame.LeaseDone}
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-frame.LeaseDone:
		return nil, net.ErrClosed
	default:
	}
	if f := m.flows[key]; f != nil {
		f.lastSeen = time.Now()
		return f.conn, nil
	}
	if m.readers >= types.DefaultUDPMaxFlows {
		return nil, errUDPFlowCapacityReached
	}
	localConn, err := net.DialUDP("udp", nil, m.target)
	if err != nil {
		return nil, err
	}
	frame.Payload = nil
	entry := &udpFlowEntry{conn: localConn, lastSeen: time.Now(), frame: frame}
	m.flows[key] = entry
	m.workers.Add(1)
	m.readers++
	go func() {
		defer m.workers.Done()
		defer func() { m.mu.Lock(); m.readers--; m.mu.Unlock() }()
		m.readLoop(ctx, key, entry)
	}()
	return localConn, nil
}

func (m *udpFlowManager) removeFlow(key udpFlowKey, entry *udpFlowEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flows[key] == entry {
		_ = entry.conn.Close()
		delete(m.flows, key)
	}
}

func (m *udpFlowManager) readLoop(ctx context.Context, key udpFlowKey, entry *udpFlowEntry) {
	defer m.removeFlow(key, entry)

	readerDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
		case <-key.leaseDone:
		case <-m.done:
		case <-readerDone:
			return
		}
		_ = entry.conn.Close()
	}()
	defer func() { close(readerDone); <-watcherDone }()
	buf := make([]byte, 65535)
	for {
		n, err := entry.conn.Read(buf)
		if err != nil {
			return
		}
		if n > types.MaxUDPPayloadSize {
			continue
		}
		if !m.readLoopForward(ctx, key, entry, buf[:n]) {
			return
		}
	}
}

func (m *udpFlowManager) readLoopForward(ctx context.Context, key udpFlowKey, entry *udpFlowEntry, payload []byte) bool {
	m.mu.Lock()
	if m.flows[key] != entry {
		m.mu.Unlock()
		return false
	}
	entry.lastSeen = time.Now()
	replyFrame := entry.frame
	replyFrame.Payload = bytes.Clone(payload)
	m.mu.Unlock()
	sendErr := m.exposure.SendDatagram(replyFrame)
	if sendErr != nil {
		select {
		case <-key.leaseDone:
			return false
		case <-m.done:
			return false
		default:
		}
	}
	return true
}
