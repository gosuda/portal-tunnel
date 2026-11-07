package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// A session lasts as long as the tunnel holds its host, on a real relay. Nobody
// but this identity can hold the address-bound URL, so a session there survives a
// restart. Another identity may have held an alias in between, so one there does not.
func TestSessionsFollowTheHostsATunnelHolds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	port := harnessPort(t, "localhost")
	sniAddr := net.JoinHostPort("localhost", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + sniAddr, StateDir: t.TempDir(), SNIListenAddr: sniAddr, SNIPort: port})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	var id types.Identity
	// start is one run of the tunnel, wired as portal expose wires it.
	start := func() (status sdk.RelayStatus, stop func()) {
		t.Helper()
		runtime, err := tunnel.Start(ctx, tunnel.Spec{
			Identity:  tunnel.IdentitySpec{Name: "held", Path: identityPath},
			Relays:    tunnel.RelaySpec{URLs: []string{"https://" + sniAddr}},
			Transport: tunnel.TransportSpec{Target: strings.TrimPrefix(upstream.URL, "http://")},
			HTTP:      &tunnel.HTTPConfig{Auth: &appauth.Config{Provider: appauth.ProviderCredential}},
		})
		if err != nil {
			t.Fatal(err)
		}
		id = runtime.Identity
		runDone := make(chan error, 1)
		go func() { runDone <- runtime.Run(ctx) }()
		waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
		defer waitCancel()
		ready, err := runtime.Exposure.WaitReady(waitCtx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].AliasURL == "" {
			t.Fatalf("relay status = %+v, want a public URL and an alias", ready)
		}
		return ready[0], func() {
			t.Helper()
			_ = runtime.Close()
			select {
			case err := <-runDone:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("run: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("the tunnel did not stop")
			}
		}
	}

	// Every host is on the relay, and each request names its own in the SNI.
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		},
	}
	send := func(req *http.Request) *http.Response {
		t.Helper()
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response
	}
	signIn := func(publicURL string) *http.Cookie {
		t.Helper()
		parsed, err := url.Parse(publicURL)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := appauth.IssueCredential(id, parsed.Host, "alice", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]string{"credential": credential})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicURL+appauth.ReservedPathPrefix+"redeem", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", "https://"+parsed.Host)
		response := send(req)
		if response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 {
			t.Fatalf("sign-in at %s = %d, cookies %v", publicURL, response.StatusCode, response.Cookies())
		}
		return response.Cookies()[0]
	}
	open := func(publicURL string, session *http.Cookie, host string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL+"/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.AddCookie(session)
		return send(req).StatusCode
	}

	status, stop := start()
	canonicalSession, aliasSession := signIn(status.PublicURL), signIn(status.AliasURL)
	if code := open(status.PublicURL, canonicalSession, ""); code != http.StatusNoContent {
		t.Fatalf("canonical session = %d; want 204", code)
	}
	if code := open(status.AliasURL, aliasSession, ""); code != http.StatusNoContent {
		t.Fatalf("alias session = %d; want 204", code)
	}
	if code := open(status.PublicURL, canonicalSession, "elsewhere.localhost:"+strconv.Itoa(port)); code != http.StatusMisdirectedRequest {
		t.Fatalf("a host the tunnel does not hold = %d; want 421", code)
	}

	stop()
	restarted, stop := start()
	t.Cleanup(stop)
	if code := open(restarted.PublicURL, canonicalSession, ""); code != http.StatusNoContent {
		t.Fatalf("canonical session after a restart = %d; want 204", code)
	}
	if code := open(restarted.AliasURL, aliasSession, ""); code != http.StatusSeeOther {
		t.Fatalf("alias session after a restart = %d; want the login redirect", code)
	}
	if code := open(restarted.AliasURL, signIn(restarted.AliasURL), ""); code != http.StatusNoContent {
		t.Fatalf("new alias session = %d; want 204", code)
	}
}
