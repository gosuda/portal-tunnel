package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestInspector(t *testing.T, next http.Handler, bodies bool) *httpInspector {
	t.Helper()
	i, err := startHTTPInspector(next, bodies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = i.Close() })
	return i
}

func inspectorRequest(t *testing.T, i *httpInspector, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, i.origin+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", i.origin)
		req.Header.Set("X-Portal-Inspector", "replay")
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func readInspection(t *testing.T, response *http.Response) inspectedTransaction {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("inspector status = %d", response.StatusCode)
	}
	var transaction inspectedTransaction
	if err := json.NewDecoder(response.Body).Decode(&transaction); err != nil {
		t.Fatal(err)
	}
	return transaction
}

func TestInspectorCaptureAndReplayStayOnConfiguredRoute(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Set-Cookie", "session=response-secret")
		w.Header().Set("X-Custom-Secret", "response-secret")
		_, _ = fmt.Fprintf(w, "%s %s %s %s", r.Method, r.URL.RequestURI(), body, r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)
	g, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/hooks", Upstream: upstream.URL + "/receiver"}}, X402Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	origin, err := g.StartInspector(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(origin, "http://127.0.0.1:") {
		t.Fatalf("inspector origin = %q", origin)
	}
	request := httptest.NewRequest(http.MethodPost, "https://preview.example/hooks/event?q=original", strings.NewReader("payload"))
	request.Header.Set("Authorization", "Bearer request-secret")
	request.Header.Set("Cookie", "session=request-secret")
	request.Header.Set("X-API-Key", "request-secret")
	request.Header.Set("X-Unrecognized", "request-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	forwarded := httptest.NewRecorder()
	g.ServeHTTP(forwarded, request)
	if forwarded.Code != http.StatusOK || forwarded.Body.String() != "POST /receiver/event?q=original payload Bearer request-secret" {
		t.Fatalf("forwarded = %d %q", forwarded.Code, forwarded.Body.String())
	}
	captured := readInspection(t, inspectorRequest(t, g.inspector, http.MethodGet, "/transactions/1"))
	if captured.Path != "/hooks/event?q=original" || captured.Method != http.MethodPost || captured.RequestBody != "payload" || !captured.Replayable {
		t.Fatalf("capture = %+v", captured)
	}
	for _, name := range []string{"Authorization", "Cookie", "X-API-Key", "X-Unrecognized"} {
		if captured.RequestHeaders.Get(name) != "[redacted]" {
			t.Fatalf("header %s was not redacted", name)
		}
	}
	if captured.ResponseHeaders.Get("Set-Cookie") != "[redacted]" || captured.ResponseHeaders.Get("X-Custom-Secret") != "[redacted]" {
		t.Fatalf("response headers = %v", captured.ResponseHeaders)
	}
	if captured.RequestHeaders.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("trusted public scheme was lost")
	}
	replayed := readInspection(t, inspectorRequest(t, g.inspector, http.MethodPost, "/transactions/1/replay"))
	if replayed.ID != 2 || replayed.ReplayedFrom != 1 || replayed.ResponseBody != "POST /receiver/event?q=original payload " {
		t.Fatalf("replay = %+v", replayed)
	}
}

func TestInspectorLocalOriginProtection(t *testing.T) {
	t.Parallel()
	i := newTestInspector(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), false)
	i.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://preview.example/", nil))
	for _, tc := range []struct{ name, method, origin, host, site, action string }{
		{"foreign origin", "POST", "https://evil.example", "", "", "replay"},
		{"missing origin", "POST", "", "", "", "replay"},
		{"rebinding host", "POST", i.origin, "evil.example", "", "replay"},
		{"missing explicit action", "POST", i.origin, "", "", ""},
		{"cross site", "POST", i.origin, "", "cross-site", "replay"},
		{"foreign read", "GET", "https://evil.example", "", "", ""},
		{"rebinding UI", "GET", "", "evil.example", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, i.origin+"/transactions/1/replay", nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			req.Header.Set("X-Portal-Inspector", tc.action)
			response := httptest.NewRecorder()
			i.serveLocal(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
	response := inspectorRequest(t, i, http.MethodGet, "/")
	page, _ := io.ReadAll(response.Body)
	if !bytes.Contains(page, []byte("non-idempotent")) || !bytes.Contains(page, []byte("confirm(")) {
		t.Fatal("UI must explain and confirm replay side effects")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("inspector must not allow caching or cross-origin reads")
	}
	navigation := httptest.NewRequest(http.MethodGet, i.origin+"/", nil)
	navigation.Header.Set("Sec-Fetch-Site", "same-site")
	pageResponse := httptest.NewRecorder()
	i.serveLocal(pageResponse, navigation)
	if pageResponse.Code != http.StatusOK {
		t.Fatal("a link from another local page must open the static UI")
	}
	req := httptest.NewRequest(http.MethodPost, i.origin+"/transactions/1/replay", strings.NewReader(`{"url":"http://evil.example"}`))
	req.Header.Set("Origin", i.origin)
	req.Header.Set("X-Portal-Inspector", "replay")
	denied := httptest.NewRecorder()
	i.serveLocal(denied, req)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("request override status = %d", denied.Code)
	}
}

func TestInspectorBoundsAndBodyOptIn(t *testing.T) {
	t.Parallel()
	for _, bodies := range []bool{false, true} {
		t.Run(fmt.Sprint(bodies), func(t *testing.T) {
			payload := strings.Repeat("x", 3*inspectBodyLimit)
			i := newTestInspector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(w, r.Body)
			}), bodies)
			for n := 0; n < inspectCapacity+1; n++ {
				req := httptest.NewRequest(http.MethodPost, "https://preview.example/", strings.NewReader(payload))
				req.ContentLength = -1
				response := httptest.NewRecorder()
				i.ServeHTTP(response, req)
				if response.Body.String() != payload {
					t.Fatal("capture changed forwarded payload")
				}
			}
			if response := inspectorRequest(t, i, http.MethodGet, "/transactions/1"); response.StatusCode != http.StatusNotFound {
				t.Fatal("oldest record was not evicted")
			}
			latest := readInspection(t, inspectorRequest(t, i, http.MethodGet, fmt.Sprintf("/transactions/%d", inspectCapacity+1)))
			if latest.Replayable {
				t.Fatal("oversized or uncaptured request body must not be replayable")
			}
			if bodies {
				if len(latest.RequestBody) != inspectBodyLimit || len(latest.ResponseBody) != inspectBodyLimit || !latest.RequestTruncated || !latest.ResponseTruncated {
					t.Fatal("body previews were not bounded")
				}
			} else if latest.RequestBody != "" || latest.ResponseBody != "" {
				t.Fatal("bodies captured without opt-in")
			}
			if response := inspectorRequest(t, i, http.MethodPost, fmt.Sprintf("/transactions/%d/replay", inspectCapacity+1)); response.StatusCode != http.StatusConflict {
				t.Fatal("ineligible replay accepted")
			}
		})
	}
}

func TestInspectorRedactsCredentialQueries(t *testing.T) {
	t.Parallel()
	i := newTestInspector(t, http.NotFoundHandler(), false)
	for n, path := range []string{
		"/hook?access_token=secret&q=ok",
		"/hook?access_token=secret&invalid=%xx",
		"/hook?access_token=secret&large=" + strings.Repeat("x", inspectPathLimit),
		"/callback?session=secret&q=ok",
		"/callback?session_id=secret&q=ok",
		"/callback?sig=secret&q=ok",
		"/callback?jwt=secret&q=ok",
		"/callback?sid=secret&q=ok",
		"/callback?X-Amz-Signature=secret&q=ok",
	} {
		i.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://preview.example"+path, nil))
		captured := readInspection(t, inspectorRequest(t, i, http.MethodGet, fmt.Sprintf("/transactions/%d", n+1)))
		if strings.Contains(captured.Path, "secret") || captured.Replayable {
			t.Fatalf("credential query capture = %+v", captured)
		}
		if n != 1 && n != 2 && !strings.Contains(captured.Path, "q=ok") {
			t.Fatal("non-sensitive query was lost")
		}
	}
	for _, name := range []string{"design", "signal", "q", "page"} {
		if sensitiveQuery(name) {
			t.Fatalf("%q must not be treated as a credential", name)
		}
	}
}

func TestInspectorUIShutdownDoesNotStopForwarding(t *testing.T) {
	t.Parallel()
	i := newTestInspector(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "local app still running")
	}), false)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	i.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example/", nil))
	if response.Code != http.StatusOK || response.Body.String() != "local app still running" {
		t.Fatal("stopping the inspector UI affected application forwarding")
	}
}

func TestInspectorPreservesStreamingAndUpgrades(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/upgrade" {
					conn, rw, err := http.NewResponseController(w).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nready\n")
					_ = rw.Flush()
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: ready\n\n")
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
				}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
			upstream := httptest.NewServer(handler)
			t.Cleanup(upstream.Close)
			gateway, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/", Upstream: upstream.URL}}, X402Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = gateway.Close() })
			if enabled {
				if _, err := gateway.StartInspector(true); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(gateway)
			t.Cleanup(server.Close)
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Get(server.URL + "/events")
			if err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(response.Body).ReadString('\n')
			_ = response.Body.Close()
			if err != nil || line != "data: ready\n" {
				t.Fatalf("stream = %q, %v", line, err)
			}
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = fmt.Fprintf(conn, "GET /upgrade HTTP/1.1\r\nHost: preview.example\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			rw := bufio.NewReader(conn)
			upgrade, err := http.ReadResponse(rw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if upgrade.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade status = %d", upgrade.StatusCode)
			}
			line, err = rw.ReadString('\n')
			if err != nil || line != "ready\n" {
				t.Fatalf("upgrade data = %q, %v", line, err)
			}
		})
	}
}

func BenchmarkInspectorForwarding(b *testing.B) {
	for _, mode := range []string{"disabled", "metadata", "bodies"} {
		b.Run(mode, func(b *testing.B) {
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) })
			if mode != "disabled" {
				inspector, err := startHTTPInspector(handler, mode == "bodies")
				if err != nil {
					b.Fatal(err)
				}
				defer inspector.Close()
				handler = inspector
			}
			payload := strings.Repeat("x", inspectBodyLimit)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for b.Loop() {
				request := httptest.NewRequest(http.MethodPost, "https://preview.example/hook", strings.NewReader(payload))
				handler.ServeHTTP(&inspectDiscard{header: make(http.Header)}, request)
			}
		})
	}
}
