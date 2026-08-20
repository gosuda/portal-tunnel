package thumbnail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// targetServing returns the address of a target that answers "/" with doc.
func targetServing(t *testing.T, doc string) (addr string, requests *atomic.Int64) {
	t.Helper()
	requests = &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://"), requests
}

const declaringDoc = `<html><head>
	<meta property="og:image" content="https://cdn.example.com/card.png">
</head></html>`

func TestParseDeclaredImageRefsPrefersOpenGraph(t *testing.T) {
	doc := `<html><head>
		<link rel="apple-touch-icon" href="/icon.png">
		<meta name="twitter:image" content="/twitter.png">
		<meta property="og:image" content="/og.png">
	</head><body></body></html>`

	refs := parseDeclaredImageRefs(strings.NewReader(doc))

	want := []string{"/og.png", "/twitter.png", "/icon.png"}
	if len(refs) != len(want) {
		t.Fatalf("refs = %v, want %v", refs, want)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("refs = %v, want %v", refs, want)
		}
	}
}

func TestParseDeclaredImageRefsStopsAtBody(t *testing.T) {
	doc := `<html><head><meta property="og:image" content="/og.png"></head>
		<body><meta property="og:image" content="/injected.png"></body></html>`

	refs := parseDeclaredImageRefs(strings.NewReader(doc))

	if len(refs) != 1 || refs[0] != "/og.png" {
		t.Fatalf("refs = %v, want only the head image", refs)
	}
}

func TestFromTargetKeepsAbsoluteURL(t *testing.T) {
	addr, _ := targetServing(t, declaringDoc)

	got, err := FromTarget(context.Background(), addr)
	if err != nil {
		t.Fatalf("from target: %v", err)
	}
	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the declared absolute URL", got)
	}
}

// Open Graph calls for an absolute URL. Resolving a relative one would mean
// picking a relay and a lease hostname, which couples a card image to relay
// selection for a value the app was supposed to state outright.
func TestFromTargetSkipsRelativeReferences(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="/og.png">
	</head></html>`)

	got, err := FromTarget(context.Background(), addr)
	if err != nil {
		t.Fatalf("from target: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty for a relative reference", got)
	}
}

func TestFromTargetFallsBackThroughPreferenceOrder(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="/relative-and-skipped.png">
		<meta name="twitter:image" content="https://cdn.example.com/twitter.png">
		<link rel="apple-touch-icon" href="https://cdn.example.com/icon.png">
	</head></html>`)

	got, err := FromTarget(context.Background(), addr)
	if err != nil {
		t.Fatalf("from target: %v", err)
	}
	if got != "https://cdn.example.com/twitter.png" {
		t.Fatalf("thumbnail = %q, want the twitter image ahead of the icon", got)
	}
}

// The value goes straight into an <img src> on the dashboard. data: and
// javascript: parse as absolute URLs and would otherwise pass an "is it
// absolute" test.
func TestFromTargetRejectsNonHTTPSchemes(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="data:image/png;base64,iVBORw0KGgo=">
		<meta property="og:image" content="javascript:alert(1)">
	</head></html>`)

	got, err := FromTarget(context.Background(), addr)
	if err != nil {
		t.Fatalf("from target: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

func TestFromTargetAcceptsAPageThatAdvertisesNothing(t *testing.T) {
	addr, _ := targetServing(t, `<html><head><title>plain</title></head><body>hi</body></html>`)

	got, err := FromTarget(context.Background(), addr)
	if err != nil {
		t.Fatalf("advertising no image is not an error: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

func TestFromTargetReportsAnUnreachableTarget(t *testing.T) {
	if _, err := FromTarget(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("an unreachable target returned no error")
	}
}

// The address must be the bare host:port the tunnel dials. Accepting a URL
// would turn this into "fetch any path on any host".
func TestFromTargetRejectsNonHostPortTargets(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8080/admin",
		"127.0.0.1",
		"user:pass@127.0.0.1:8080",
		"127.0.0.1:http",
		"",
	} {
		if _, err := FromTarget(context.Background(), target); err == nil {
			t.Errorf("target %q was accepted", target)
		}
	}
}

// A redirect would send this somewhere the operator did not name, so it is
// rejected rather than followed.
func TestFromTargetDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(declaringDoc))
	}))
	t.Cleanup(other.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	_, err := FromTarget(context.Background(), strings.TrimPrefix(redirector.URL, "http://"))
	if err == nil {
		t.Fatal("a redirect was followed instead of rejected")
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("redirect target received %d requests, want 0", n)
	}
}

// The opt-in is the whole contract with the operator: without it the target is
// not touched at all.
func TestResolveWithoutOptInMakesNoRequest(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	if got := Resolve(context.Background(), "", addr, false); got != "" {
		t.Fatalf("thumbnail = %q, want empty without the opt-in", got)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("target received %d requests without the opt-in, want 0", n)
	}
}

// An explicit --thumbnail is the operator's answer; discovery must not second
// guess it, and must not spend a request finding that out.
func TestResolveKeepsAnExplicitValue(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	got := Resolve(context.Background(), "https://example.com/chosen.png", addr, true)
	if got != "https://example.com/chosen.png" {
		t.Fatalf("thumbnail = %q, want the explicitly configured value", got)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("target received %d requests despite an explicit thumbnail, want 0", n)
	}
}

func TestResolveUsesTheTargetWhenAsked(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	got := Resolve(context.Background(), "", addr, true)
	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the image the target advertises", got)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("target received %d requests, want exactly 1", n)
	}
}

// A missing card image is not a reason to refuse to serve.
func TestResolveSurvivesAnUnreachableTarget(t *testing.T) {
	if got := Resolve(context.Background(), "", "127.0.0.1:1", true); got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}
