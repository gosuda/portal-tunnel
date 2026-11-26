package gateway

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	inspectCapacity    = 100
	inspectBodyLimit   = 8 << 10
	inspectHeaderLimit = 8 << 10
	inspectPathLimit   = 4 << 10
)

//go:embed inspector.html
var inspectorPage []byte

// The inspector owns only local, ephemeral debugging data. The router remains
// the owner of upstream selection, including during replay.
type httpInspector struct {
	next      http.Handler
	bodies    bool
	server    *http.Server
	cancel    context.CancelFunc
	origin    string
	slots     chan struct{}
	replaying chan struct{}
	mu        sync.Mutex
	sequence  uint64
	records   [inspectCapacity]*inspectedTransaction
}

type inspectedTransaction struct {
	ID                uint64      `json:"id"`
	Time              time.Time   `json:"time"`
	Method            string      `json:"method"`
	Path              string      `json:"path"`
	Status            int         `json:"status"`
	DurationMS        float64     `json:"duration_ms"`
	ReplayedFrom      uint64      `json:"replayed_from,omitempty"`
	RequestHeaders    http.Header `json:"request_headers"`
	ResponseHeaders   http.Header `json:"response_headers"`
	RequestBody       string      `json:"request_body"`
	ResponseBody      string      `json:"response_body"`
	RequestTruncated  bool        `json:"request_truncated"`
	ResponseTruncated bool        `json:"response_truncated"`
	BodiesCaptured    bool        `json:"bodies_captured"`
	Replayable        bool        `json:"replayable"`
	ReplayDisabled    string      `json:"replay_disabled,omitempty"`
	host              string
	requestURL        url.URL
	replayHeaders     http.Header
	body              []byte
}

func startHTTPInspector(next http.Handler, bodies bool) (*httpInspector, error) {
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, err
	}
	i := &httpInspector{next: next, bodies: bodies, cancel: cancel,
		origin: "http://" + listener.Addr().String(), slots: make(chan struct{}, 16), replaying: make(chan struct{}, 1)}
	i.server = &http.Server{Handler: http.HandlerFunc(i.serveLocal),
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: inspectHeaderLimit, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = i.server.Serve(listener) }()
	return i, nil
}

func (i *httpInspector) Close() error {
	if i == nil {
		return nil
	}
	i.cancel()
	return i.server.Close()
}

func (i *httpInspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case i.slots <- struct{}{}:
		defer func() { <-i.slots }()
		i.capture(w, r, 0)
	default:
		// Inspection never queues or waits for capacity on the forwarding path.
		i.next.ServeHTTP(w, r)
	}
}

func (i *httpInspector) capture(w http.ResponseWriter, r *http.Request, replayedFrom uint64) *inspectedTransaction {
	started := time.Now()
	headers, replayHeaders := inspectHeaders(r.Header)
	t := &inspectedTransaction{Time: started, Method: r.Method, host: r.Host,
		RequestHeaders: headers, replayHeaders: replayHeaders, BodiesCaptured: i.bodies,
		ReplayedFrom: replayedFrom, Replayable: true}
	t.requestURL = url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	// Bound work before escaping/building a potentially oversized request URI.
	if len(r.URL.Path) <= inspectPathLimit && len(r.URL.RawPath) <= inspectPathLimit && len(r.URL.RawQuery) <= inspectPathLimit {
		t.Path = t.requestURL.RequestURI()
	}
	if t.Path == "" || len(t.Path) > inspectPathLimit || len(t.host) > 512 || len(t.Method) > 32 {
		t.Path = "[request metadata exceeds the capture limit]"
		t.host, t.Method, t.requestURL = "", "", url.URL{}
		t.ReplayDisabled = "Request metadata exceeds the capture limit."
	} else {
		t.Path = strings.Clone(t.Path)
		t.host, t.Method = strings.Clone(t.host), strings.Clone(t.Method)
		t.requestURL.Path = strings.Clone(t.requestURL.Path)
		t.requestURL.RawPath = strings.Clone(t.requestURL.RawPath)
		t.requestURL.RawQuery = strings.Clone(t.requestURL.RawQuery)
		query, queryErr := url.ParseQuery(t.requestURL.RawQuery)
		if queryErr != nil {
			t.ReplayDisabled = "The query could not be safely parsed."
			query = url.Values{"redacted": {"invalid query"}}
		}
		for key := range query {
			if sensitiveQuery(key) {
				query.Set(key, "[redacted]")
				t.ReplayDisabled = "The query contains redacted credentials."
			}
		}
		if t.ReplayDisabled != "" {
			t.requestURL.RawQuery = query.Encode()
			t.Path = t.requestURL.RequestURI()
		}
	}
	upgrade := r.Header.Get("Upgrade") != "" || r.Method == http.MethodConnect
	var body *inspectBody
	if r.Body != nil && r.Body != http.NoBody {
		if i.bodies && !upgrade {
			body = &inspectBody{ReadCloser: r.Body, length: r.ContentLength}
			r.Body = body
		} else {
			t.ReplayDisabled = "Request body was not captured."
		}
	}
	if upgrade {
		t.ReplayDisabled = "Upgraded and CONNECT requests cannot be replayed."
	}
	response := &inspectResponse{ResponseWriter: w, bodies: i.bodies && !upgrade}
	i.next.ServeHTTP(response, r)
	t.Status = response.status
	if t.Status == 0 {
		t.Status = http.StatusOK
	}
	t.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	t.ResponseHeaders = response.headers
	contentType := response.contentType
	if t.ResponseHeaders == nil {
		// No final WriteHeader ran, so net/http sends the map as it is now.
		t.ResponseHeaders, _ = inspectHeaders(response.Header())
		contentType = response.Header().Get("Content-Type")
	}
	t.ResponseBody, t.ResponseTruncated = string(response.body), response.truncated
	if body != nil {
		var complete bool
		t.body, t.RequestTruncated, complete = body.snapshot()
		t.RequestBody = string(t.body)
		if !complete || t.RequestTruncated {
			t.ReplayDisabled = "Request body is incomplete or exceeds 8 KiB."
		}
	}
	if strings.HasPrefix(contentType, "text/event-stream") {
		t.ReplayDisabled = "Event streams cannot be replayed."
	}
	t.Replayable = t.ReplayDisabled == ""
	i.mu.Lock()
	i.sequence++
	t.ID = i.sequence
	i.records[(t.ID-1)%inspectCapacity] = t
	i.mu.Unlock()
	return t
}

// inspectAllowedHeaders lists the only headers whose values are stored and
// replayed. The list is far below the 32-name and 8 KiB limits, so these
// headers always fit before any redacted name uses the budget.
var inspectAllowedHeaders = []string{"Content-Type", "Content-Encoding", "Content-Length", "Accept",
	"Accept-Encoding", "Accept-Language", "User-Agent", "X-Request-Id", "X-Forwarded-Proto"}

// Capture selected headers only. Unrecognized values, including custom API
// keys, signatures, cookies and Portal identity proofs, never enter storage.
// Allowed headers are kept first, so many custom headers cannot push out a
// header that replay needs. Other names follow in sorted order as redacted
// metadata, so the kept set does not depend on map iteration order.
func inspectHeaders(source http.Header) (http.Header, http.Header) {
	visible, eligible := make(http.Header), make(http.Header)
	remaining := inspectHeaderLimit
	allowed := make(map[string]bool, len(inspectAllowedHeaders))
	for _, name := range inspectAllowedHeaders {
		allowed[name] = true
		values := source.Values(name)
		if len(values) == 0 {
			continue
		}
		remaining -= len(name)
		for index, value := range values {
			if index >= 16 || len(value) > remaining {
				break
			}
			value = strings.Clone(value)
			visible.Add(name, value)
			eligible.Add(name, value)
			remaining -= len(value) + 1
		}
	}
	others := make([]string, 0, len(source))
	for name := range source {
		if !allowed[http.CanonicalHeaderKey(name)] && len(name) <= 128 {
			others = append(others, name)
		}
	}
	slices.Sort(others)
	for _, name := range others {
		if len(visible) >= 32 || remaining < len(name)+16 {
			break
		}
		visible.Set(strings.Clone(name), "[redacted]")
		remaining -= len(name) + 10
	}
	return visible, eligible
}

// Long credential words match anywhere in the name. Short ones (sig, sid)
// match only as a whole separator-delimited part, so "design" stays visible.
func sensitiveQuery(name string) bool {
	name = strings.ToLower(name)
	if name == "code" {
		return true
	}
	for _, word := range []string{"auth", "token", "key", "secret", "password", "credential", "signature", "session", "jwt"} {
		if strings.Contains(name, word) {
			return true
		}
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if part == "sig" || part == "sid" {
			return true
		}
	}
	return false
}

type inspectBody struct {
	io.ReadCloser
	mu       sync.Mutex
	data     []byte
	read     int64
	length   int64
	complete bool
	failed   bool
}

func (b *inspectBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.read += int64(n)
	b.data = append(b.data, p[:min(n, inspectBodyLimit-len(b.data))]...)
	b.complete = errors.Is(err, io.EOF) || (b.length >= 0 && b.read == b.length)
	if err != nil && !errors.Is(err, io.EOF) {
		b.failed = true
	}
	return n, err
}

func (b *inspectBody) snapshot() ([]byte, bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data), b.read > inspectBodyLimit, b.complete && !b.failed
}

// Unwrap preserves ResponseController support; explicit Flush and Hijack also
// preserve handlers using the traditional streaming/upgrade interfaces.
type inspectResponse struct {
	http.ResponseWriter
	status      int
	headers     http.Header
	contentType string
	bodies      bool
	body        []byte
	truncated   bool
}

func (w *inspectResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *inspectResponse) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		// Snapshot what this call sends; later map changes are not sent.
		w.status = status
		w.headers, _ = inspectHeaders(w.Header())
		w.contentType = w.Header().Get("Content-Type")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *inspectResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if w.bodies && !strings.HasPrefix(w.contentType, "text/event-stream") {
		kept := min(n, inspectBodyLimit-len(w.body))
		w.body = append(w.body, p[:kept]...)
		w.truncated = w.truncated || kept < n
	}
	return n, err
}

func (w *inspectResponse) Flush() { _ = w.FlushError() }
func (w *inspectResponse) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *inspectResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (i *httpInspector) serveLocal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.Host != strings.TrimPrefix(i.origin, "http://") ||
		(r.Header.Get("Origin") != "" && r.Header.Get("Origin") != i.origin) {
		http.Error(w, "local same-origin access required", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(inspectorPage)
		return
	}
	// A normal link may navigate to the static UI from another local page.
	// Transaction reads and replay still require same-origin browser requests.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "local same-origin access required", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/transactions" {
		// List summaries only; body/header details are fetched on selection.
		i.mu.Lock()
		list := make([]map[string]any, 0, inspectCapacity)
		for id := i.sequence; id > 0 && i.sequence-id < inspectCapacity; id-- {
			t := i.records[(id-1)%inspectCapacity]
			list = append(list, map[string]any{"id": t.ID, "time": t.Time, "method": t.Method, "path": t.Path,
				"status": t.Status, "duration_ms": t.DurationMS, "replayed_from": t.ReplayedFrom})
		}
		i.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	idPath, ok := strings.CutPrefix(r.URL.Path, "/transactions/")
	idText, action, _ := strings.Cut(idPath, "/")
	id, err := strconv.ParseUint(idText, 10, 64)
	if !ok || err != nil || id == 0 {
		http.NotFound(w, r)
		return
	}
	i.mu.Lock()
	t := i.records[(id-1)%inspectCapacity]
	i.mu.Unlock()
	if t == nil || t.ID != id {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet && action == "" {
		_ = json.NewEncoder(w).Encode(t)
		return
	}
	if r.Method != http.MethodPost || action != "replay" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Origin") != i.origin || r.Header.Get("X-Portal-Inspector") != "replay" || r.ContentLength != 0 {
		http.Error(w, "same-origin explicit replay required; no request overrides accepted", http.StatusForbidden)
		return
	}
	if !t.Replayable {
		http.Error(w, t.ReplayDisabled, http.StatusConflict)
		return
	}
	select {
	case i.replaying <- struct{}{}:
		defer func() { <-i.replaying }()
	default:
		http.Error(w, "a replay is already running", http.StatusTooManyRequests)
		return
	}
	select {
	case i.slots <- struct{}{}:
		defer func() { <-i.slots }()
	default:
		http.Error(w, "capture capacity is busy", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	requestURL := t.requestURL
	req := (&http.Request{Method: t.Method, URL: &requestURL, Host: t.host,
		Header: t.replayHeaders.Clone(), Body: io.NopCloser(bytes.NewReader(t.body)), ContentLength: int64(len(t.body)),
		RemoteAddr: "127.0.0.1:0"}).WithContext(ctx)
	req.Header.Del("Content-Length")
	if len(t.body) == 0 {
		req.Body = http.NoBody
	}
	result := i.capture(&inspectDiscard{header: make(http.Header)}, req, t.ID)
	_ = json.NewEncoder(w).Encode(result)
}

type inspectDiscard struct{ header http.Header }

func (w *inspectDiscard) Header() http.Header       { return w.header }
func (*inspectDiscard) WriteHeader(int)             {}
func (*inspectDiscard) Write(p []byte) (int, error) { return len(p), nil }
func (*inspectDiscard) Flush()                      {}

// StartInspector attaches capture after the public auth/payment gates, and
// serves debugging/replay on a separate IPv4 loopback listener.
func (g *HTTPGateway) StartInspector(bodies bool) (string, error) {
	if g.inspector != nil {
		return "", errors.New("HTTP inspector is already running")
	}
	i, err := startHTTPInspector(g.routed, bodies)
	if err != nil {
		return "", fmt.Errorf("start HTTP inspector: %w", err)
	}
	g.inspector = i
	g.handler = g.payment.Wrap(i)
	return i.origin, nil
}
