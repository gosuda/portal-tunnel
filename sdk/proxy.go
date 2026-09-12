package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
		return errors.New("portal sdk: exposure is nil")
	}
	if ctx == nil {
		return errors.New("portal sdk: context is nil")
	}

	var err error
	if config.TCPTarget != "" {
		config.TCPTarget, err = utils.NormalizeLoopbackTarget(config.TCPTarget)
		if err != nil {
			return err
		}
	}
	if config.UDPTarget != "" {
		config.UDPTarget, err = utils.NormalizeLoopbackTarget(config.UDPTarget)
		if err != nil {
			return err
		}
	}
	workerCount := 0
	if config.TCPTarget != "" {
		workerCount++
	}
	if config.UDPTarget != "" {
		workerCount++
	}
	if workerCount == 0 {
		return errors.New("portal sdk: at least one proxy target is required")
	}

	cfg := exposure.config()
	identity := cfg.Identity
	tcpTarget := config.TCPTarget
	udpTarget := config.UDPTarget

	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("tcp_target", tcpTarget).
		Str("service_name", identity.Name).
		Strs("relays", exposure.activeRelayURLs()).
		Msg("starting portal tunnel; public URLs will be logged as relays become ready")
	if udpTarget != "" {
		log.Info().
			Str("udp_target", udpTarget).
			Str("service_name", identity.Name).
			Msg("udp relay enabled")
	}

	var connWG sync.WaitGroup
	var connCount atomic.Int64
	proxyCtx, cancel := context.WithCancel(ctx)
	results := make(chan error, workerCount)
	if tcpTarget != "" {
		go func() { results <- proxyRelayConnections(proxyCtx, exposure, tcpTarget, &connWG, &connCount) }()
	}
	if udpTarget != "" {
		go func() { results <- runUDPProxy(proxyCtx, exposure, udpTarget) }()
	}

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
	if closeErr != nil {
		log.Warn().Err(closeErr).Msg("relay shutdown completed with cleanup errors")
	}

	if ctx.Err() != nil {
		log.Info().Msg("tunnel shutting down")
	}

	done := make(chan struct{})
	go func() {
		connWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Warn().Msg("tunnel shutdown timeout; connections still active")
	}

	log.Info().Msg("tunnel shutdown complete")
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(primary, closeErr)
}

func proxyRelayConnections(ctx context.Context, exposure *Exposure, localAddr string, connWG *sync.WaitGroup, connCount *atomic.Int64) error {
	for {
		relayConn, err := exposure.Accept()
		if err != nil {
			switch {
			case errors.Is(err, ErrNoRelays):
				return err
			case errors.Is(err, context.Canceled):
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			case ctx.Err() != nil:
				return ctx.Err()
			case errors.Is(err, net.ErrClosed):
				return net.ErrClosed
			default:
				return err
			}
		}

		connID := connCount.Add(1)
		log.Debug().
			Int64("conn_id", connID).
			Str("remote_addr", relayConn.RemoteAddr().String()).
			Msg("accepted relay connection")

		connWG.Add(1)
		go func(connID int64, relayConn net.Conn) {
			defer connWG.Done()
			if err := proxyConnection(ctx, localAddr, relayConn); err != nil {
				log.Debug().Err(err).Int64("conn_id", connID).Msg("proxy connection closed with an I/O error")
			}
			log.Debug().Int64("conn_id", connID).Msg("proxy connection closed")
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

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		return writeEmptyHTTPResponse(relayConn)
	}
	defer localConn.Close()

	errCh := make(chan error, 2)
	stopCh := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = relayConn.Close()
			_ = localConn.Close()
		case <-stopCh:
		}
	}()

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(localConn, relayConn, *bufPtr)
		if tcpConn, ok := localConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- err
	}()

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(relayConn, localConn, *bufPtr)
		_ = relayConn.Close()
		errCh <- err
	}()

	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}

	close(stopCh)
	if errors.Is(firstErr, io.EOF) || errors.Is(firstErr, net.ErrClosed) {
		return nil
	}
	return firstErr
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

// runUDPProxy waits for the exposure datagram plane and proxies it to the
// configured local UDP target.
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
		return errors.New("relay did not expose any UDP listeners")
	}

	for _, relay := range udpRelays {
		log.Info().
			Str("udp_addr", relay.UDPAddr).
			Str("relay_url", relay.RelayURL).
			Msg("UDP tunnel ready")
	}

	return proxyExposureDatagrams(ctx, exposure, udpTarget)
}

// proxyExposureDatagrams receives datagrams from the exposure datagram plane
// and forwards them to the local UDP service, relaying responses back.
func proxyExposureDatagrams(ctx context.Context, exposure *Exposure, localAddr string) error {
	resolvedAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr %q: %w", localAddr, err)
	}

	mgr := newUDPFlowManager(resolvedAddr, exposure)
	go mgr.runCleanup(ctx)

	log.Info().Str("target", localAddr).Msg("udp proxy loop started, waiting for datagrams")
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
			log.Warn().
				Err(err).
				Uint32("flow_id", frame.FlowID).
				Str("address", frame.Address).
				Str("relay_url", frame.RelayURL).
				Msg("dial local udp failed")
			continue
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

	return nil
}

type udpFlowKey struct {
	flowID   uint32
	address  string
	relayURL string
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
}

func newUDPFlowManager(target *net.UDPAddr, exposure *Exposure) *udpFlowManager {
	return &udpFlowManager{
		target:   target,
		exposure: exposure,
		flows:    make(map[udpFlowKey]*udpFlowEntry),
	}
}

func (m *udpFlowManager) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
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

func (m *udpFlowManager) getOrCreate(ctx context.Context, frame types.DatagramFrame) (*net.UDPConn, error) {
	key := udpFlowKey{
		flowID:   frame.FlowID,
		address:  frame.Address,
		relayURL: frame.RelayURL,
	}

	m.mu.Lock()
	if f, ok := m.flows[key]; ok {
		f.lastSeen = time.Now()
		m.mu.Unlock()
		return f.conn, nil
	}
	m.mu.Unlock()

	localConn, err := net.DialUDP("udp", nil, m.target)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if f, ok := m.flows[key]; ok {
		m.mu.Unlock()
		_ = localConn.Close()
		f.lastSeen = time.Now()
		return f.conn, nil
	}
	m.flows[key] = &udpFlowEntry{
		conn:     localConn,
		lastSeen: time.Now(),
		frame: types.DatagramFrame{
			FlowID:   frame.FlowID,
			Address:  frame.Address,
			RelayURL: frame.RelayURL,
			UDPAddr:  frame.UDPAddr,
		},
	}
	m.mu.Unlock()

	go m.readLoop(ctx, key, localConn)
	return localConn, nil
}

func (m *udpFlowManager) removeFlow(key udpFlowKey) {
	m.mu.Lock()
	if f, ok := m.flows[key]; ok {
		_ = f.conn.Close()
		delete(m.flows, key)
	}
	m.mu.Unlock()
}

func (m *udpFlowManager) readLoop(ctx context.Context, key udpFlowKey, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Debug().
				Err(err).
				Uint32("flow_id", key.flowID).
				Str("address", key.address).
				Str("relay_url", key.relayURL).
				Msg("local read ended")
			m.removeFlow(key)
			return
		}

		m.mu.Lock()
		entry := m.flows[key]
		if entry == nil {
			m.mu.Unlock()
			return
		}
		entry.lastSeen = time.Now()
		replyFrame := entry.frame
		replyFrame.Payload = bytes.Clone(buf[:n])
		m.mu.Unlock()

		if sendErr := m.exposure.SendDatagram(replyFrame); sendErr != nil {
			log.Debug().
				Err(sendErr).
				Uint32("flow_id", key.flowID).
				Str("address", key.address).
				Str("relay_url", key.relayURL).
				Msg("send datagram to relay failed")
			m.removeFlow(key)
			return
		}
	}
}
