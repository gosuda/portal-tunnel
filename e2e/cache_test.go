package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
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
	"github.com/gosuda/portal-tunnel/v2/sdk/staticsite"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func startCacheRelay(t *testing.T, ctx context.Context, cfg cache.Config) (*url.URL, string, *portal.Server) {
	t.Helper()
	stateDir := t.TempDir()
	base, _ := url.Parse("https://127.0.0.1:" + strconv.Itoa(harnessPort(t, "127.0.0.1")))
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL: base.String(), StateDir: stateDir, SNIListenAddr: base.Host,
		Cache: cfg, TenantCertificates: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	return base, stateDir, relay
}

func registerCacheLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, id types.Identity) types.RegisterResponse {
	t.Helper()
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge,
		types.RegisterChallengeRequest{Identity: id, Cache: true, TTL: 60}, nil, &challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := identity.NewLocalAuthority(id).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	var lease types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister,
		types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, nil, &lease); err != nil {
		t.Fatal(err)
	}
	return lease
}

func buildCacheUpload(t *testing.T) ([]byte, string) {
	t.Helper()
	const content = "site"
	digest := sha256.Sum256([]byte(content))
	manifest := fmt.Sprintf(`{"index":"index.html","files":[{"path":"index.html","size":4,"sha256":"%x"}]}`, digest)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, field := range []struct{ name, value string }{{"manifest", manifest}, {"object", content}} {
		part, err := writer.CreateFormField(field.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, field.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func stallCacheUpload(t *testing.T, base *url.URL, transport *http.Transport, lease types.RegisterResponse) ([]byte, string) {
	t.Helper()
	upload, formType := buildCacheUpload(t)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", base.Host,
		transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s: %s\r\n\r\n",
		types.PathSDKCache, base.Host, formType, len(upload), types.HeaderAccessToken, lease.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(upload[:8]); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPut})
	if err != nil {
		t.Fatalf("stalled upload did not receive an HTTP response: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("stalled upload = %d, want 400", response.StatusCode)
	}
	return upload, formType
}

func registerStalledCacheLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) types.RegisterResponse {
	t.Helper()
	id, err := identity.Generate("stalled-cache")
	if err != nil {
		t.Fatal(err)
	}
	return registerCacheLease(t, ctx, client, base, id)
}

func stallThenUploadCacheObject(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, lease types.RegisterResponse) {
	t.Helper()
	upload, formType := stallCacheUpload(t, base, client.Transport.(*http.Transport), lease)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, base.String()+types.PathSDKCache, bytes.NewReader(upload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", formType)
	request.Header.Set(types.HeaderAccessToken, lease.AccessToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upload after timeout = %d, want 200", response.StatusCode)
	}
}

func TestStalledMultipartUploadReleasesAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base, stateDir, relay := startCacheRelay(t, ctx, cache.Config{Enabled: true, MaxBytes: 1024, MaxTTL: time.Minute})
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := relay.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown relay: %v", err)
		}
		if err := relay.Wait(); err != nil {
			t.Errorf("wait for relay shutdown: %v", err)
		}
	})
	waitForRelayCertificateMaterial(t, stateDir)
	client := relayControlClient(t, stateDir)
	lease := registerStalledCacheLease(t, ctx, client, base)
	stallThenUploadCacheObject(t, ctx, client, base, lease)
}

func writeCacheSite(t *testing.T) string {
	t.Helper()
	siteDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(siteDir, "index.html"), []byte("cached site"), 0o600); err != nil {
		t.Fatal(err)
	}
	return siteDir
}

func exposeStaticCache(t *testing.T, ctx context.Context, relayURL, siteDir string, originCalls *atomic.Int32) *sdk.Exposure {
	t.Helper()
	id, err := identity.Generate("cached")
	if err != nil {
		t.Fatal(err)
	}
	exposure, err := sdk.Expose(ctx, id, []string{relayURL}, sdk.WithStaticRelayCache(siteDir, 24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	static := staticsite.NewHandler("/", siteDir, "index.html")
	go func() {
		_ = sdk.RunHTTP(ctx, exposure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originCalls.Add(1)
			w.Header().Set("X-Origin", "true")
			static.ServeHTTP(w, r)
		}), "")
	}()
	return exposure
}

func awaitCachePopulated(ctx context.Context, t *testing.T, client *http.Client, publicURL string) {
	t.Helper()
	for {
		response, err := client.Get(publicURL + "/app/route")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.Header.Get("ETag") == "" {
			select {
			case <-ctx.Done():
				t.Fatal("cache did not populate")
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if string(body) != "cached site" || response.Header.Get("X-Origin") != "" {
			t.Fatalf("cache response: %q, %v", body, response.Header)
		}
		break
	}
}

func assertFriendlyHostnameBypassed(t *testing.T, client *http.Client, publicURL string, relay *portal.Server) {
	t.Helper()
	leases := relay.PublicLeases()
	if len(leases) != 1 || leases[0].Hostname == "" {
		t.Fatalf("friendly lease unavailable: %+v", leases)
	}
	friendlyURL, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	if port := friendlyURL.Port(); port != "" {
		friendlyURL.Host = net.JoinHostPort(leases[0].Hostname, port)
	} else {
		friendlyURL.Host = leases[0].Hostname
	}
	response, err := client.Get(friendlyURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.Header.Get("X-Origin") != "true" || response.Header.Get("ETag") != "" {
		t.Fatalf("friendly hostname used relay cache: %v", response.Header)
	}
}

func assertCacheRangeHit(t *testing.T, ctx context.Context, client *http.Client, publicURL string, originCalls *atomic.Int32) {
	t.Helper()
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
}

func assertSpoofedHostMisdirected(t *testing.T, ctx context.Context, client *http.Client, publicURL string) {
	t.Helper()
	spoofed, _ := http.NewRequestWithContext(ctx, http.MethodGet, publicURL, nil)
	spoofed.Host = "spoofed.example.com"
	response, err := client.Do(spoofed)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("spoofed host status = %d, want %d", response.StatusCode, http.StatusMisdirectedRequest)
	}
}

func assertUncacheableFallsThrough(t *testing.T, ctx context.Context, client *http.Client, publicURL string) {
	t.Helper()
	response, err := client.Post(publicURL, "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.Header.Get("X-Origin") != "true" {
		t.Fatalf("cache fallback did not reach the origin: %d", response.StatusCode)
	}
}

func assertCacheSemantics(t *testing.T, ctx context.Context, client *http.Client, publicURL string, relay *portal.Server, originCalls *atomic.Int32) {
	t.Helper()
	assertFriendlyHostnameBypassed(t, client, publicURL, relay)
	assertCacheRangeHit(t, ctx, client, publicURL, originCalls)
	assertSpoofedHostMisdirected(t, ctx, client, publicURL)
	assertUncacheableFallsThrough(t, ctx, client, publicURL)
}

func assertOfflineCacheAvailable(t *testing.T, client *http.Client, publicURL string) {
	t.Helper()
	response, err := client.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "cached site" {
		t.Fatalf("offline cache: %d, %q", response.StatusCode, body)
	}
}

func noteOfflineFetchError(t *testing.T, err error, earliestExpiry time.Time) {
	t.Helper()
	if time.Now().Before(earliestExpiry) {
		t.Fatalf("offline cache failed before its TTL: %v", err)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("unexpected error while checking cache expiry: %v", err)
	}
}

func noteOfflinePollResponse(t *testing.T, response *http.Response, earliestExpiry time.Time) bool {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode == http.StatusServiceUnavailable {
		if time.Now().Before(earliestExpiry) {
			t.Fatal("offline cache returned 503 before its TTL")
		}
		return true
	}
	if response.StatusCode != http.StatusOK || string(body) != "cached site" {
		t.Fatalf("unexpected offline cache response: %d, %q", response.StatusCode, body)
	}
	return false
}

func awaitOfflineCacheExpiry(t *testing.T, client *http.Client, publicURL string, earliestExpiry, deadline time.Time) {
	t.Helper()
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for time.Now().Before(deadline) {
		response, err := client.Get(publicURL)
		if err != nil {
			noteOfflineFetchError(t, err, earliestExpiry)
			return
		}
		if noteOfflinePollResponse(t, response, earliestExpiry) {
			return
		}
		<-poll.C
	}
	t.Fatal("cache outlived the relay's offline TTL ceiling")
}

func assertOfflineCacheExpiry(t *testing.T, client *http.Client, publicURL string, exposure *sdk.Exposure, offlineTTL time.Duration) {
	t.Helper()
	closeStartedAt := time.Now()
	if err := exposure.Close(); err != nil {
		t.Fatal(err)
	}
	assertOfflineCacheAvailable(t, client, publicURL)
	awaitOfflineCacheExpiry(t, client, publicURL, closeStartedAt.Add(offlineTTL), time.Now().Add(offlineTTL+3*time.Second))
}

func TestStaticCacheOffloadAndOfflineTLS(t *testing.T) {
	const offlineTTL = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	siteDir := writeCacheSite(t)
	base, stateDir, relay := startCacheRelay(t, ctx, cache.Config{Enabled: true, MaxBytes: 1024, MaxTTL: offlineTTL})
	t.Cleanup(func() {
		cancel()
		_ = relay.Shutdown(context.Background())
		_ = relay.Wait()
	})
	relayURL := base.String()
	sniAddr := base.Host
	var originCalls atomic.Int32
	exposure := exposeStaticCache(t, ctx, relayURL, siteDir, &originCalls)
	defer exposure.Close()
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
	awaitCachePopulated(readyCtx, t, client, publicURL)
	assertCacheSemantics(t, ctx, client, publicURL, relay, &originCalls)
	assertOfflineCacheExpiry(t, client, publicURL, exposure, offlineTTL)
}

func TestNamespaceCanonicalNeverUsesLegacyCache(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base, stateDir, relay := startCacheRelay(t, ctx, cache.Config{Enabled: true, MaxBytes: 1024, MaxTTL: time.Minute})
	t.Cleanup(func() { _ = relay.Shutdown(context.Background()); _ = relay.Wait() })
	h := &harness{t: t, server: relay, sniAddr: base.Host, certificate: filepath.Join(stateDir, "fullchain.pem")}
	id, err := identity.Generate("namespace-cache")
	if err != nil {
		t.Fatal(err)
	}
	exposure, ready := namespaceService(t, h, id, "live origin", sdk.WithAutomaticTLS(t.TempDir(), true), sdk.WithStaticRelayCache(writeCacheSite(t), time.Minute))
	if ready.LegacyURL == "" || ready.LegacyURL == ready.PublicURL {
		t.Fatalf("cache migration URLs=%+v", ready)
	}
	client, transport, ok := tenantTLSClient(h.sniAddr, h.certificate)
	if !ok {
		t.Fatal("load trust")
	}
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	deadline, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	awaitCachePopulated(deadline, t, client, ready.LegacyURL)
	namespaceResponse(t, h, ready.PublicURL, "live origin", true)
	parsed, _ := url.Parse(ready.PublicURL)
	// Even when the relay terminates TLS for a legacy snapshot, a forged HTTP
	// authority must not make that snapshot available under a canonical name.
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, ready.LegacyURL, nil)
	request.Host = parsed.Host
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("legacy cache accepted canonical authority: %d", response.StatusCode)
	}
	if err := exposure.Close(); err != nil {
		t.Fatal(err)
	}
	assertOfflineCacheAvailable(t, client, ready.LegacyURL)
	transport.CloseIdleConnections()
	response, err = client.Get(ready.PublicURL)
	if err == nil {
		response.Body.Close()
		t.Fatalf("offline canonical completed TLS and returned %d", response.StatusCode)
	}
}
