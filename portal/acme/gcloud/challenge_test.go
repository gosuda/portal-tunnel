package gcloud

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/go-acme/lego/v4/challenge"
	lego "github.com/go-acme/lego/v4/providers/dns/gcloud"
	"golang.org/x/oauth2"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

type challengeTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t challengeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = t.target.Scheme, t.target.Host
	return t.base.RoundTrip(req)
}

func challengeContext(t *testing.T, handler http.HandlerFunc) context.Context {
	t.Helper()
	file := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(file, []byte(`{"type":"authorized_user","client_id":"test","client_secret":"test","refresh_token":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: challengeTransport{target: target, base: server.Client().Transport}})
}

func TestChallengePreservesTXTAndFreshCleanupCredentials(t *testing.T) {
	var mu sync.Mutex
	rr := &dns.ResourceRecordSet{Name: "_acme-challenge.example.com.", Type: "TXT", Ttl: 321, Rrdatas: []string{`"keep"`, `"challenge-other"`}}
	tokens := 0
	ctx := challengeContext(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token":
			tokens++
			io.WriteString(w, `{"access_token":"test","token_type":"Bearer","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/managedZones/zone"):
			json.NewEncoder(w).Encode(&dns.ManagedZone{Name: "zone", DnsName: "example.com.", Visibility: "public"})
		case strings.HasSuffix(r.URL.Path, "/rrsets"):
			json.NewEncoder(w).Encode(&dns.ResourceRecordSetsListResponse{Rrsets: []*dns.ResourceRecordSet{rr}})
		case strings.HasSuffix(r.URL.Path, "/changes"):
			var change dns.Change
			if err := json.NewDecoder(r.Body).Decode(&change); err != nil {
				t.Error(err)
			}
			if len(change.Additions) != 1 {
				t.Errorf("expected preserved TXT rrset, got %#v", change)
				return
			}
			rr = change.Additions[0]
			json.NewEncoder(w).Encode(&dns.Change{Status: "done"})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	orderCtx, cancel := context.WithCancel(ctx)
	p := New(Config{ProjectID: "project", ManagedZone: "zone"})
	cleanup, err := p.presentChallenge(orderCtx, lego.NewDefaultConfig(), rr.Name, "challenge")
	if err != nil || cleanup == nil {
		t.Fatalf("present: cleanup=%v err=%v", cleanup != nil, err)
	}
	cancel()
	if err := cleanup(context.WithoutCancel(ctx)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if rr.Ttl != 321 || !slices.Equal(rr.Rrdatas, []string{`"keep"`, `"challenge-other"`}) {
		t.Fatalf("cleanup changed unrelated TXT: %#v", rr)
	}
	if tokens != 2 {
		t.Fatalf("cleanup did not refresh credentials independently: %d", tokens)
	}
}

func TestChallengePreexistingValueHasNoCleanup(t *testing.T) {
	ctx := challengeContext(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token":
			io.WriteString(w, `{"access_token":"test","token_type":"Bearer","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/managedZones/zone"):
			io.WriteString(w, `{"name":"zone","dnsName":"example.com.","visibility":"private"}`)
		case strings.HasSuffix(r.URL.Path, "/rrsets"):
			io.WriteString(w, `{"rrsets":[{"name":"_acme-challenge.example.com.","type":"TXT","ttl":123,"rrdatas":["\"existing\""]}]}`)
		default:
			t.Errorf("unexpected mutation %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	cfg := lego.NewDefaultConfig()
	cfg.AllowPrivateZone = true
	cleanup, err := New(Config{ProjectID: "project", ManagedZone: "zone"}).presentChallenge(ctx, cfg, "_acme-challenge.example.com.", "existing")
	if err != nil || cleanup != nil {
		t.Fatalf("preexisting record: cleanup=%v err=%v", cleanup != nil, err)
	}
}

func TestChallengeCancellation(t *testing.T) {
	for _, stage := range []string{"auth", "lookup", "write", "poll"} {
		t.Run(stage, func(t *testing.T) {
			t.Setenv(lego.EnvTTL, "77")
			started := make(chan struct{})
			ctx := challengeContext(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				block := (stage == "auth" && r.URL.Path == "/token") || (stage == "lookup" && strings.HasSuffix(r.URL.Path, "/managedZones/zone")) || (stage == "write" && strings.HasSuffix(r.URL.Path, "/changes"))
				if block {
					io.Copy(io.Discard, r.Body)
					close(started)
					<-r.Context().Done()
					return
				}
				switch {
				case r.URL.Path == "/token":
					io.WriteString(w, `{"access_token":"test","token_type":"Bearer","expires_in":3600}`)
				case strings.HasSuffix(r.URL.Path, "/managedZones/zone"):
					io.WriteString(w, `{"name":"zone","dnsName":"example.com."}`)
				case strings.HasSuffix(r.URL.Path, "/rrsets"):
					io.WriteString(w, `{}`)
				case strings.HasSuffix(r.URL.Path, "/changes"):
					var change dns.Change
					if err := json.NewDecoder(r.Body).Decode(&change); err != nil {
						t.Error(err)
					}
					if len(change.Additions) != 1 || change.Additions[0].Ttl != 77 {
						t.Errorf("environment TTL not applied: %#v", change.Additions)
					}
					io.WriteString(w, `{"id":"pending","status":"pending"}`)
					close(started)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				cleanup, err := New(Config{ProjectID: "project", ManagedZone: "zone"}).presentChallenge(ctx, lego.NewDefaultConfig(), "_acme-challenge.example.com.", "value")
				if (stage == "write" || stage == "poll") && cleanup == nil {
					t.Error("uncertain write lost cleanup")
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not stop provider")
			}
		})
	}
}

func TestChallengeEnvironmentTimeout(t *testing.T) {
	t.Setenv(lego.EnvPropagationTimeout, "41")
	t.Setenv(lego.EnvPollingInterval, "7")
	p, err := New(Config{}).ChallengeProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	timeout, interval := p.(challenge.ProviderTimeout).Timeout()
	if timeout != 41*time.Second || interval != 7*time.Second {
		t.Fatalf("timeouts=%v,%v", timeout, interval)
	}
}

func TestMetadataTokenCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(server.URL, "http://"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := (metadataTokenSource{ctx: ctx}).Token(); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("metadata token ignored cancellation")
	}
}

func TestRemoveChallengeNoMatchingValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("unexpected mutation")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"rrsets":[{"name":"_acme-challenge.example.com.","type":"TXT","ttl":123,"rrdatas":["\"value-prefix\""]}]}`)
	}))
	defer server.Close()
	service, err := dns.NewService(context.Background(), option.WithHTTPClient(server.Client()), option.WithEndpoint(server.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	if err := removeChallenge(context.Background(), service, "project", "zone", "_acme-challenge.example.com.", "value"); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledMetadataDiscoveryDoesNotPoisonNextOrder(t *testing.T) {
	// Reproduce the upstream package-level cache being initialized by an
	// interrupted discovery. Provider discovery must not depend on that cache.
	t.Setenv("GCE_METADATA_HOST", "")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	metadata.OnGCEWithContext(canceled)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			io.WriteString(w, "project")
		case "/computeMetadata/v1/instance/service-accounts/default/token":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"test","token_type":"Bearer","expires_in":3600}`)
		default:
			t.Errorf("unexpected metadata request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	home := t.TempDir()
	t.Setenv("APPDATA", home)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	cfg, err := newRuntimeConfig(ctx, Config{})
	if err != nil {
		t.Fatalf("fresh order after interrupted discovery: %v", err)
	}
	if cfg.ProjectID != "project" {
		t.Fatalf("project = %q", cfg.ProjectID)
	}
	source := cfg.HTTPClient.Transport.(*oauth2.Transport).Source
	if _, err := source.Token(); err != nil {
		t.Fatalf("fresh metadata authentication: %v", err)
	}
}

func TestChallengeZonePrefersDelegatedChildOverCachedParent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/managedZones/explicit"):
			io.WriteString(w, `{"name":"explicit","dnsName":"example.com."}`)
		case r.URL.Query().Get("dnsName") == "acme.example.com.":
			io.WriteString(w, `{"managedZones":[{"name":"child","dnsName":"acme.example.com."}]}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer server.Close()
	service, err := dns.NewService(context.Background(), option.WithHTTPClient(server.Client()), option.WithEndpoint(server.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	p := New(Config{})
	p.zones.UpdateCopy(func(zones *map[string]string) { (*zones)["example.com"] = "parent" })
	zone, err := p.findManagedZone(context.Background(), service, "project", "token.acme.example.com.", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "child" {
		t.Fatalf("selected %q, want delegated child", zone.Name)
	}
	zone, err = p.findManagedZone(context.Background(), service, "project", "token.acme.example.com.", "explicit", false)
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "explicit" {
		t.Fatalf("selected %q, want explicit zone", zone.Name)
	}
}
