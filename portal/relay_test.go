package portal

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestOverlayConnectClaimsOnlyAuthorizedLocalBackhaul(t *testing.T) {
	registry := newTestRegistry(t)
	server := &Server{registry: registry, authority: registry.tokenAuthority}
	record, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "demo")}, "203.0.113.10", "")
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	// The transport's identity gate is covered by overlay tests. Here exercise
	// the actual receiving handler, lease authority, and reverse stream bridge.
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleOverlay))
	defer httpServer.Close()
	for _, token := range []string{"", "invalid"} {
		req := httptest.NewRequest(http.MethodConnect, types.PathRelayConnect, nil)
		req.Header.Set(types.HeaderAccessToken, token)
		response := httptest.NewRecorder()
		server.handleOverlay(response, req)
		if response.Code < 400 {
			t.Fatal("unauthorized reverse stream accepted")
		}
	}
	record.relayBinding.Store(&relayBinding{expiresAt: time.Now().Add(time.Minute)})
	req := httptest.NewRequest(http.MethodGet, types.PathRelayLease, nil)
	req.Header.Set(types.HeaderAccessToken, lease.AccessToken)
	response := httptest.NewRecorder()
	server.handleOverlay(response, req)
	if response.Code < 400 {
		t.Fatal("forwarding lease was accepted as another middle relay")
	}
	record.relayBinding.Store(nil)

	reverse, endpoint := net.Pipe()
	defer endpoint.Close()
	if err := record.stream.OfferConn(reverse); err != nil {
		t.Fatal(err)
	}
	backend := make(chan error, 1)
	go func() {
		_ = endpoint.SetDeadline(time.Now().Add(3 * time.Second))
		marker := make([]byte, 1)
		for {
			if _, err := io.ReadFull(endpoint, marker); err != nil {
				backend <- err
				return
			}
			if marker[0] == types.MarkerTLSStart {
				break
			}
		}
		ciphertext := make([]byte, 6)
		if _, err := io.ReadFull(endpoint, ciphertext); err != nil {
			backend <- err
			return
		}
		_, err := endpoint.Write(ciphertext)
		backend <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", httpServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, httpServer.URL+types.PathRelayConnect, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(types.HeaderAccessToken, lease.AccessToken)
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	accepted, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("connect: %s", accepted.Status)
	}
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0xff}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatal("tenant TLS bytes changed in relay bridge")
	}
	if err := <-backend; err != nil {
		t.Fatal(err)
	}
}

func TestRelayBindingRequiresLocalLeaseAuthority(t *testing.T) {
	registry := newTestRegistry(t)
	server := &Server{registry: registry, overlay: &overlay.Runtime{}}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, types.PathSDKRelay, nil)
		response := httptest.NewRecorder()
		server.handleRelayBinding(response, request)
		if response.Code < 400 {
			t.Fatal("binding changed without local lease authority")
		}
	}
}
