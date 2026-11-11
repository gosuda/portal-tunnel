package overlay

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

func TestGatewayKeepsTheRefusalReason(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status byte
		code   int
		api    string
	}{
		{types.OverlayStatusPending, http.StatusForbidden, types.APIErrorCodeLeaseRejected},
		{types.OverlayStatusDenied, http.StatusForbidden, types.APIErrorCodeLeaseDenied},
		{types.OverlayStatusCapacity, http.StatusTooManyRequests, types.APIErrorCodeRateLimited},
		{types.OverlayStatusUnavailable, http.StatusForbidden, types.APIErrorCodeUnauthorized},
		{9, http.StatusForbidden, types.APIErrorCodeUnauthorized},
	} {
		checkRefusalReasonCase(t, tc.status, tc.code, tc.api)
	}
}

func newRefusalReasonEndpoint(t *testing.T, status byte) endpointStub {
	t.Helper()
	return endpointStub{
		destination: testDestination("gateway"),
		dial: func(context.Context, string, string) (net.Conn, error) {
			local, remote := net.Pipe()
			go func() {
				defer remote.Close()
				var size uint16
				if binary.Read(remote, binary.BigEndian, &size) != nil {
					return
				}
				if _, err := io.ReadFull(remote, make([]byte, size)); err != nil {
					return
				}
				_, _ = remote.Write([]byte{status})
			}()
			return peerConn{Conn: local, remote: ivnp.Addr{Hash: sha256.Sum256([]byte("ingress")), Port: 4017}}, nil
		},
	}
}

func checkRefusalReasonCase(t *testing.T, status byte, code int, api string) {
	t.Helper()
	gate, capability := testGateway(t)
	gate.sourceLimiter = newSourceLimiter(1000, 1000)
	gate.endpoint = newRefusalReasonEndpoint(t, status)
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr("192.0.2.1"))
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != code || body.Error.Code != api {
		t.Fatalf("status %d answered %d %q, want %d %q", status, response.Code, body.Error.Code, code, api)
	}
}

func TestGatewayTruncatedUpstreamResponseIsUnavailable(t *testing.T) {
	t.Parallel()
	gate, capability := testGateway(t)
	gate.sourceLimiter = newSourceLimiter(1000, 1000)
	gate.endpoint = endpointStub{
		destination: testDestination("gateway"),
		dial: func(context.Context, string, string) (net.Conn, error) {
			local, remote := net.Pipe()
			go func() {
				defer remote.Close()
				var size uint16
				if binary.Read(remote, binary.BigEndian, &size) != nil {
					return
				}
				_, _ = io.CopyN(io.Discard, remote, int64(size))
			}()
			return peerConn{Conn: local, remote: ivnp.Addr{Hash: sha256.Sum256([]byte("ingress")), Port: 4017}}, nil
		},
	}
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr("192.0.2.1"))
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || body.Error.Code != types.APIErrorCodeFeatureUnavailable {
		t.Fatalf("truncated upstream answered %d %q, want %d %q", response.Code, body.Error.Code, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable)
	}
}
