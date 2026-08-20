package sdk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
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

// Open Graph asks for an absolute URL, and an app that follows that needs no
// resolution: the value is already reachable from anywhere.
func TestDiscoverThumbnailKeepsAbsoluteURL(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="https://cdn.example.com/card.png">
	</head></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "app.portal.example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the declared absolute URL", got)
	}
}

// A relative reference is common despite the spec, and the file is served
// through the tunnel like any other path, so it resolves against the hostname
// the lease will answer at -- not the loopback address of the target.
func TestDiscoverThumbnailResolvesRelativeAgainstLeaseHostname(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="/og.png">
	</head></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "app.portal.example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "https://app.portal.example.com/og.png" {
		t.Fatalf("thumbnail = %q, want it resolved against the lease hostname", got)
	}
}

// Without a hostname there is nothing to resolve against, and storing the
// target's loopback address would render as a broken image for every visitor.
func TestDiscoverThumbnailSkipsRelativeWithoutHostname(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="/og.png">
	</head></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

func TestDiscoverThumbnailFallsBackThroughPreferenceOrder(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta name="twitter:image" content="https://cdn.example.com/twitter.png">
		<link rel="apple-touch-icon" href="https://cdn.example.com/icon.png">
	</head></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "app.portal.example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "https://cdn.example.com/twitter.png" {
		t.Fatalf("thumbnail = %q, want the twitter image ahead of the icon", got)
	}
}

// metadata.thumbnail goes straight into an <img src> on the dashboard, so only
// http(s) is adopted. data: and javascript: parse as absolute URLs and would
// otherwise pass an "is it absolute" test.
func TestDiscoverThumbnailRejectsNonHTTPSchemes(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="data:image/png;base64,iVBORw0KGgo=">
		<meta property="og:image" content="javascript:alert(1)">
	</head></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "app.portal.example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

func TestDiscoverThumbnailAcceptsAPageThatAdvertisesNothing(t *testing.T) {
	addr, _ := targetServing(t, `<html><head><title>plain</title></head><body>hi</body></html>`)

	got, err := DiscoverThumbnail(context.Background(), addr, "app.portal.example.com")
	if err != nil {
		t.Fatalf("advertising no image is not an error: %v", err)
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

// A target that is not listening yet must not be reported as a thumbnail, and
// must not be mistaken for one either.
func TestDiscoverThumbnailReportsAnUnreachableTarget(t *testing.T) {
	got, err := DiscoverThumbnail(context.Background(), "127.0.0.1:1", "app.portal.example.com")
	if err == nil {
		t.Fatal("an unreachable target returned no error")
	}
	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

const declaringDoc = `<html><head>
	<meta property="og:image" content="https://cdn.example.com/card.png">
</head></html>`

// The opt-in is the whole contract with the operator: without it the target is
// not touched at all.
func TestResolveMetadataThumbnailWithoutOptInMakesNoRequest(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	got := resolveMetadataThumbnail(context.Background(),
		ExposeConfig{}, addr, "app", []string{"https://portal.example.com"})

	if got != "" {
		t.Fatalf("thumbnail = %q, want empty without the opt-in", got)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("target received %d requests without the opt-in, want 0", n)
	}
}

// An explicit --thumbnail is the operator's answer; discovery must not second
// guess it, and must not spend a request finding that out.
func TestResolveMetadataThumbnailKeepsAnExplicitValue(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	cfg := ExposeConfig{
		ThumbnailFromTarget: true,
		Metadata:            types.LeaseMetadata{Thumbnail: "https://example.com/chosen.png"},
	}
	got := resolveMetadataThumbnail(context.Background(), cfg, addr, "app",
		[]string{"https://portal.example.com"})

	if got != "https://example.com/chosen.png" {
		t.Fatalf("thumbnail = %q, want the explicitly configured value", got)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("target received %d requests despite an explicit thumbnail, want 0", n)
	}
}

func TestResolveMetadataThumbnailUsesTheTargetWhenAsked(t *testing.T) {
	addr, requests := targetServing(t, declaringDoc)

	got := resolveMetadataThumbnail(context.Background(),
		ExposeConfig{ThumbnailFromTarget: true}, addr, "app",
		[]string{"https://portal.example.com"})

	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the image the target advertises", got)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("target received %d requests, want exactly 1", n)
	}
}

// A target that is not answering leaves the thumbnail empty rather than failing
// the exposure: a missing card image is not a reason to refuse to serve.
func TestResolveMetadataThumbnailSurvivesAnUnreachableTarget(t *testing.T) {
	got := resolveMetadataThumbnail(context.Background(),
		ExposeConfig{ThumbnailFromTarget: true}, "127.0.0.1:1", "app",
		[]string{"https://portal.example.com"})

	if got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}

// The lease hostname comes from the relay URL, so a relative reference resolves
// without the caller having to know it.
func TestResolveMetadataThumbnailResolvesRelativeFromTheRelayURL(t *testing.T) {
	addr, _ := targetServing(t, `<html><head>
		<meta property="og:image" content="/og.png">
	</head></html>`)

	got := resolveMetadataThumbnail(context.Background(),
		ExposeConfig{ThumbnailFromTarget: true}, addr, "app",
		[]string{"https://portal.example.com"})

	if got != "https://app.portal.example.com/og.png" {
		t.Fatalf("thumbnail = %q, want it resolved against the lease hostname", got)
	}
}

// The address must be the bare host:port the tunnel dials. Accepting a URL
// would turn this into "fetch any path on any host".
func TestDiscoverThumbnailRejectsNonHostPortTargets(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8080/admin",
		"127.0.0.1",
		"user:pass@127.0.0.1:8080",
		"127.0.0.1:http",
		"",
	} {
		if _, err := DiscoverThumbnail(context.Background(), target, "app.example.com"); err == nil {
			t.Errorf("target %q was accepted", target)
		}
	}
}
