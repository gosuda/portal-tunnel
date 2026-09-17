package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestStaticCacheOffloadAndOfflineTLS(t *testing.T) {
	const offlineTTL = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stateDir, siteDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(siteDir, "index.html"), []byte("cached site"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiPort, sniPort := harnessPort(t), harnessPort(t)
	sniAddr := "127.0.0.1:" + strconv.Itoa(sniPort)
	relayURL := "https://" + sniAddr
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL: relayURL, StateDir: stateDir,
		APIListenAddr: "127.0.0.1:" + strconv.Itoa(apiPort), SNIListenAddr: sniAddr,
		Cache: cache.Config{Enabled: true, MaxBytes: 1024, MaxTTL: offlineTTL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = relay.Shutdown(context.Background())
		_ = relay.Wait()
	})
	id, err := identity.Generate("cached")
	if err != nil {
		t.Fatal(err)
	}
	exposure, err := sdk.Expose(ctx, id, []string{relayURL}, sdk.WithStaticRelayCache(siteDir, 24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer exposure.Close()
	var originCalls atomic.Int32
	static := utils.NewStaticSiteHandler("/", siteDir, "index.html")
	go func() {
		_ = sdk.RunHTTP(ctx, exposure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originCalls.Add(1)
			w.Header().Set("X-Origin", "true")
			static.ServeHTTP(w, r)
		}), "")
	}()
	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	ready, err := exposure.WaitReady(readyCtx)
	if err != nil || len(ready) != 1 {
		t.Fatalf("ready: %v, %v", ready, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid relay certificate")
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	publicURL := ready[0].PublicURL
	for {
		response, err := client.Get(publicURL + "/app/route")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.Header.Get("ETag") != "" {
			if string(body) != "cached site" || response.Header.Get("X-Origin") != "" {
				t.Fatalf("cache response: %q, %v", body, response.Header)
			}
			break
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("cache did not populate")
		case <-time.After(50 * time.Millisecond):
		}
	}
	before := originCalls.Load()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, publicURL, nil)
	request.Header.Set("Range", "bytes=0-5")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusPartialContent || string(body) != "cached" || originCalls.Load() != before {
		t.Fatalf("cache hit crossed origin or lost Range support: %d, %q", response.StatusCode, body)
	}
	// A Host header that disagrees with the tenant TLS server name must never
	// reach cached content, even while the tenant is online.
	spoofed, _ := http.NewRequestWithContext(ctx, http.MethodGet, publicURL, nil)
	spoofed.Host = "spoofed.example.com"
	response, err = client.Do(spoofed)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("spoofed host status = %d, want %d", response.StatusCode, http.StatusMisdirectedRequest)
	}
	// A non-cacheable method on a terminated connection uses the existing
	// reverse tunnel, with authenticated tenant TLS on the upstream leg.
	response, err = client.Post(publicURL, "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.Header.Get("X-Origin") != "true" {
		t.Fatalf("cache fallback did not reach the origin: %d", response.StatusCode)
	}
	closeStartedAt := time.Now()
	if err := exposure.Close(); err != nil {
		t.Fatal(err)
	}
	// The relay processes unregister between the start and end of Close.
	// Before this lower bound, a failed request cannot be legitimate expiry.
	earliestExpiry := closeStartedAt.Add(offlineTTL)
	deadline := time.Now().Add(offlineTTL + 3*time.Second)
	response, err = client.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "cached site" {
		t.Fatalf("offline cache: %d, %q", response.StatusCode, body)
	}
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for time.Now().Before(deadline) {
		response, err = client.Get(publicURL)
		if err != nil {
			if time.Now().Before(earliestExpiry) {
				t.Fatalf("offline cache failed before its TTL: %v", err)
			}
			// An unknown tenant closes the TLS connection. A dial timeout or
			// certificate failure must not masquerade as successful expiry.
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("unexpected error while checking cache expiry: %v", err)
			}
			return // Cache TTL has expired and there is no live origin.
		}
		body, err = io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode == http.StatusServiceUnavailable {
			if time.Now().Before(earliestExpiry) {
				t.Fatal("offline cache returned 503 before its TTL")
			}
			return
		}
		if response.StatusCode != http.StatusOK || string(body) != "cached site" {
			t.Fatalf("unexpected offline cache response: %d, %q", response.StatusCode, body)
		}
		<-poll.C
	}
	t.Fatal("cache outlived the relay's offline TTL ceiling")
}
