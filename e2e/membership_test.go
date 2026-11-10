package e2e_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestRelayMembershipRemoveAndAdd(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer service.Close()
	target, err := url.Parse(service.URL)
	if err != nil {
		t.Fatalf("parse local service URL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayA := startMembershipRelay(t, ctx)
	relayB := startMembershipRelay(t, ctx)

	clientIdentity, err := identity.Generate("membership")
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	exposure, err := sdk.Expose(ctx, clientIdentity, []string{relayA.relayURL, relayB.relayURL})
	if err != nil {
		t.Fatalf("expose local service: %v", err)
	}
	t.Cleanup(func() { _ = exposure.Close() })
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- sdk.Proxy(ctx, exposure, target.Host)
	}()
	t.Cleanup(func() {
		select {
		case err := <-proxyDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("proxy exposure: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("proxy exposure did not stop")
		}
	})

	readyDeadline := time.Now().Add(15 * time.Second)
	publicA := waitPublicURLOnPort(t, exposure, relayA.sniPort, readyDeadline)
	publicB := waitPublicURLOnPort(t, exposure, relayB.sniPort, readyDeadline)
	waitServesMarker(t, "relay A before removal", relayA, publicA, 15*time.Second)
	waitServesMarker(t, "relay B before removal", relayB, publicB, 15*time.Second)

	if err := exposure.RemoveRelay(relayA.relayURL); err != nil {
		t.Fatalf("remove relay A: %v", err)
	}
	removedDeadline := time.Now().Add(15 * time.Second)
	for {
		_, servedA := tenantGet(relayA.sniAddr, relayA.certPath, publicA)
		gotB, servedB := tenantGet(relayB.sniAddr, relayB.certPath, publicB)
		_, stillMember := relayStatusOnPort(exposure.Relays(), relayA.sniPort)
		if !servedA && servedB && gotB == marker && !stillMember {
			break
		}
		if !time.Now().Before(removedDeadline) {
			t.Fatalf("relay A removal did not converge: A served=%v, B served=%v body=%q, relays=%+v",
				servedA, servedB, gotB, exposure.Relays())
		}
		<-time.After(250 * time.Millisecond)
	}

	if err := exposure.AddRelay(relayA.relayURL); err != nil {
		t.Fatalf("add relay A back: %v", err)
	}
	publicAAfterAdd := waitPublicURLOnPort(t, exposure, relayA.sniPort, time.Now().Add(30*time.Second))
	waitServesMarker(t, "relay A after re-add", relayA, publicAAfterAdd, 30*time.Second)
	waitServesMarker(t, "relay B after re-add", relayB, publicB, 15*time.Second)
}

type membershipRelay struct {
	relayURL string
	sniAddr  string
	sniPort  int
	certPath string
	stateDir string
}

func startMembershipRelay(t *testing.T, ctx context.Context) membershipRelay {
	t.Helper()
	sniPort := harnessPort(t, "127.0.0.1")
	sniAddr := "127.0.0.1:" + strconv.Itoa(sniPort)
	relayURL := "https://" + sniAddr
	stateDir := t.TempDir()
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      stateDir,
		SNIListenAddr: sniAddr,
		SNIPort:       sniPort,
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		_ = relay.Shutdown(context.Background())
		_ = relay.Wait()
	})
	return membershipRelay{
		relayURL: relayURL,
		sniAddr:  sniAddr,
		sniPort:  sniPort,
		certPath: filepath.Join(stateDir, "fullchain.pem"),
		stateDir: stateDir,
	}
}

func relayStatusOnPort(relays []sdk.RelayStatus, sniPort int) (sdk.RelayStatus, bool) {
	suffix := ":" + strconv.Itoa(sniPort)
	for _, status := range relays {
		if strings.HasSuffix(status.RelayURL, suffix) {
			return status, true
		}
	}
	return sdk.RelayStatus{}, false
}

func waitPublicURLOnPort(t *testing.T, exposure *sdk.Exposure, sniPort int, deadline time.Time) string {
	t.Helper()
	for {
		if status, ok := relayStatusOnPort(exposure.Relays(), sniPort); ok && status.PublicURL != "" {
			return status.PublicURL
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("relay on port %d never reported a public URL; relays = %+v", sniPort, exposure.Relays())
		}
		<-time.After(250 * time.Millisecond)
	}
}

func waitServesMarker(t *testing.T, label string, relay membershipRelay, publicURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got, ok := tenantGet(relay.sniAddr, relay.certPath, publicURL); ok && got == marker {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: public URL %s never served the marker", label, publicURL)
		}
		<-time.After(250 * time.Millisecond)
	}
}
