package overlay

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// HandleConnect verifies a gateway connect request, frames the upstream
// handshake, and returns the hijacked client connection paired with the
// gateway connection for the caller to bridge. It returns nil, nil after
// writing an API error.
func (r *Runtime) HandleConnect(w http.ResponseWriter, request *http.Request, capability string, source netip.Addr) (net.Conn, net.Conn) {
	claims, release, ok := r.admitHandleConnectRequest(w, source, capability)
	if !ok {
		return nil, nil
	}
	handoff := false
	defer func() {
		if !handoff {
			release()
		}
	}()
	downstream, buffered, upstream, ok := r.openHandleConnectBridge(w, request, capability, claims.Ingress.IVNPDestination)
	if !ok {
		return nil, nil
	}
	defer func() {
		if !handoff {
			closeNow(upstream)
		}
	}()
	_ = downstream.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	client := &bufferedConn{Conn: downstream, reader: buffered.Reader, release: release}
	client.stop = context.AfterFunc(r.ctx, func() { _ = client.Close() })
	handoff = true
	return client, upstream
}

func (r *Runtime) admitHandleConnectRequest(w http.ResponseWriter, source netip.Addr, capability string) (capabilityClaims, func(), bool) {
	if r == nil || !r.ready.Load() {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay is unavailable")
		return capabilityClaims{}, nil, false
	}
	if retry := r.sourceLimiter.Allow(source, 1); retry > 0 {
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay request rate exceeded")
		return capabilityClaims{}, nil, false
	}
	claims, err := verifyCapability(capability, time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.GatewayAddress, r.config.Authority.Identity().Address) || claims.GatewayDestination != r.Destination() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		return capabilityClaims{}, nil, false
	}
	r.admissionMu.Lock()
	if r.activeSources[source] >= sourceConnectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay source capacity exhausted")
		return capabilityClaims{}, nil, false
	}
	if r.outbound >= connectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		return capabilityClaims{}, nil, false
	}
	r.outbound++
	r.activeSources[source]++
	r.admissionMu.Unlock()
	release := func() {
		r.admissionMu.Lock()
		r.outbound--
		r.activeSources[source]--
		if r.activeSources[source] == 0 {
			delete(r.activeSources, source)
		}
		r.admissionMu.Unlock()
	}
	return claims, release, true
}

func (r *Runtime) exchangeHandleConnectUpstream(w http.ResponseWriter, request *http.Request, capability string, destination string) (net.Conn, bool) {
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	upstream, err := r.dial(ctx, destination)
	cancel()
	if err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return nil, false
	}
	response, ok := transactHandleConnectHandshake(upstream, capability, w)
	if !ok {
		return nil, false
	}
	switch response[0] {
	case types.OverlayStatusAccepted:
	case types.OverlayStatusCapacity:
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		closeNow(upstream)
		return nil, false
	case types.OverlayStatusPending:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeLeaseRejected, "lease is not approved for routing")
		closeNow(upstream)
		return nil, false
	case types.OverlayStatusDenied:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeLeaseDenied, "lease is denied by the relay")
		closeNow(upstream)
		return nil, false
	default:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		closeNow(upstream)
		return nil, false
	}
	return upstream, true
}

func transactHandleConnectHandshake(upstream net.Conn, capability string, w http.ResponseWriter) ([1]byte, bool) {
	var response [1]byte
	_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
	handshakeErr := binary.Write(upstream, binary.BigEndian, uint16(len(capability)))
	if handshakeErr == nil {
		_, handshakeErr = io.WriteString(upstream, capability)
	}
	if handshakeErr == nil {
		_, handshakeErr = io.ReadFull(upstream, response[:])
	}
	if handshakeErr != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		closeNow(upstream)
		return response, false
	}
	return response, true
}

func upgradeHandleConnectHijack(buffered *bufio.ReadWriter, downstream net.Conn) bool {
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge upgrade write failed")
		_ = downstream.Close()
		return false
	}
	if err := buffered.Flush(); err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge upgrade flush failed")
		_ = downstream.Close()
		return false
	}
	return true
}

type bufferedConn struct {
	net.Conn
	reader  *bufio.Reader
	stop    func() bool
	release func()
	close   sync.Once
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) Close() error {
	err := c.Conn.Close()
	c.close.Do(func() {
		if c.stop != nil {
			c.stop()
		}
		if c.release != nil {
			c.release()
		}
	})
	return err
}

func acceptHandleConnectHijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, bool) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackUnsupported, "hijacking is not supported")
		return nil, nil, false
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge hijack failed")
		return nil, nil, false
	}
	if !upgradeHandleConnectHijack(buffered, downstream) {
		return nil, nil, false
	}
	return downstream, buffered, true
}

func (r *Runtime) openHandleConnectBridge(w http.ResponseWriter, request *http.Request, capability string, destination string) (net.Conn, *bufio.ReadWriter, net.Conn, bool) {
	upstream, ok := r.exchangeHandleConnectUpstream(w, request, capability, destination)
	if !ok {
		return nil, nil, nil, false
	}
	downstream, buffered, ok := acceptHandleConnectHijack(w)
	if !ok {
		closeNow(upstream)
		return nil, nil, nil, false
	}
	return downstream, buffered, upstream, true
}
