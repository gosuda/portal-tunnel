package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestIVNPReverseExecutesSelectedGateway(t *testing.T) {
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func TestIVNPReverseFailureKeepsHealthyRelaysEligible(t *testing.T) {
	for _, tc := range []struct {
		name          string
		response      string
		stopGateway   bool
		cancel        bool
		gatewayFailed bool
		terminal      bool
	}{
		{
			name:     "reverse response",
			response: "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:     "terminal reverse response",
			response: "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{\"ok\":false,\"error\":{\"code\":\"feature_unavailable\"}}",
			terminal: true,
		},
		{
			name:     "established stream EOF",
			response: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n",
		},
		{
			name:          "HTTPS exchange failure",
			gatewayFailed: true,
		},
		{
			name:          "HTTPS dial failure",
			stopGateway:   true,
			gatewayFailed: true,
		},
		{
			name:   "canceled dial",
			cancel: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprint(buffered, tc.response)
				_ = buffered.Flush()
			}))
			defer gateway.Close()
			ingress, _ := url.Parse("https://ingress.example")
			relaySet := mustRelaySet(t, ingress.String(), gateway.URL)
			relaySet.ConfirmRelayURL(ingress.String())
			relaySet.ConfirmRelayURL(gateway.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			l := &listener{
				relayURL:    ingress,
				route:       discovery.Route{RelayURL: ingress.String(), GatewayURL: gateway.URL, IngressDestination: "selected.b32.i2p"},
				relaySet:    relaySet,
				tlsConfig:   &tls.Config{},
				gatewayTLS:  gateway.Client().Transport.(*http.Transport).TLSClientConfig,
				dialTimeout: time.Second,
				retryCount:  10,
				stream:      transport.NewClientStream(1, time.Second),
				lease:       utils.NewSnapshot(listenerSnapshot{accessToken: "ingress-token"}, listenerSnapshot.snapshot),
				cancel:      cancel,
			}
			if tc.stopGateway {
				gateway.Close()
			}
			if tc.cancel {
				cancel()
			}
			err := l.runReverseSessionLoop(ctx, nil, 1)
			if tc.cancel {
				if err != nil {
					t.Fatalf("canceled reverse loop returned %v", err)
				}
			} else if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected retry exhaustion, got %v", err)
			}
			if got := l.closeForTerminalRelayError(err); got != tc.terminal {
				t.Fatalf("terminal closure = %v, want %v: %v", got, tc.terminal, err)
			}
			if tc.terminal && ctx.Err() == nil {
				t.Fatal("terminal route failure did not close the listener")
			}
			wantEligible := map[string]bool{ingress.String(): true, gateway.URL: !tc.gatewayFailed}
			selected := make(map[string]bool)
			for _, route := range relaySet.SelectRelays(discovery.RouteState{}) {
				selected[route.RelayURL] = true
			}
			confirmed := make(map[string]bool)
			for _, relay := range relaySet.ConfirmedRelays() {
				confirmed[relay.Descriptor.APIHTTPSAddr] = true
			}
			for relayURL, want := range wantEligible {
				if selected[relayURL] != want || confirmed[relayURL] != want {
					t.Errorf("relay %s: selected=%v confirmed=%v, want eligible=%v", relayURL, selected[relayURL], confirmed[relayURL], want)
				}
				if want {
					if _, _, failures := relaySet.RecordActiveFailure(relayURL, 1); failures != 1 {
						t.Errorf("healthy relay %s inherited %d active failures", relayURL, failures-1)
					}
				}
			}
		})
	}
}
