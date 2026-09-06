package sdk

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestIVNPReverseExecutesSelectedGateway(t *testing.T) {
	requests := make(chan *http.Request, 1)
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n")
		_ = buffered.WriteByte(types.MarkerTLSStart)
		_ = buffered.Flush()
	}))
	defer gateway.Close()
	ingress, _ := url.Parse("https://ingress.example")
	l := &listener{
		relayURL:  ingress,
		route:     discovery.Route{RelayURL: ingress.String(), GatewayURL: gateway.URL, IngressDestination: "selected.b32.i2p"},
		tlsConfig: &tls.Config{}, gatewayTLS: gateway.Client().Transport.(*http.Transport).TLSClientConfig,
		dialTimeout: time.Second,
		lease:       utils.NewSnapshot(listenerSnapshot{accessToken: "ingress-token"}, listenerSnapshot.snapshot),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := l.openReverseSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var marker [1]byte
	if _, err := conn.Read(marker[:]); err != nil || marker[0] != types.MarkerTLSStart {
		t.Fatalf("buffered claim marker = %v: %v", marker, err)
	}
	select {
	case r := <-requests:
		if r.URL.Path != types.PathSDKConnect || r.Header.Get(types.HeaderAccessToken) != "ingress-token" || r.Header.Get(types.HeaderIVNPDestination) != l.route.IngressDestination {
			t.Fatal("selected reverse endpoint not executed")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
