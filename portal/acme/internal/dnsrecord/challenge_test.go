package dnsrecord

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/resolver"
	"github.com/miekg/dns"
)

var errCleanupUnavailable = errors.New("cleanup unavailable")

func TestChallengeLegoCleansFailedPublicationBeforeReturning(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The real lego prober needs a directory and account key even when a failed
	// publication prevents it from contacting any validation endpoint.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"newAccount":"/account","newOrder":"/order"}`)
	}))
	defer server.Close()
	core, err := api.New(server.Client(), "test", server.URL, "account", key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cleaned := false
	provider := NewChallengeProvider(ctx, time.Minute, time.Second, func(context.Context, string, string) (Cleanup, error) {
		cancel()
		return func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			cleaned = true
			return nil
		}, context.Canceled
	})
	solvers := resolver.NewSolversManager(core)
	if err := solvers.SetDNS01Provider(provider); err != nil {
		t.Fatal(err)
	}
	err = resolver.NewProber(solvers).Solve([]acme.Authorization{{
		Status: acme.StatusPending, Identifier: acme.Identifier{Type: "dns", Value: "example.test"},
		Challenges: []acme.Challenge{{Type: "dns-01", Token: "token"}},
	}})
	if err == nil || !cleaned {
		t.Fatalf("lego returned error %v, cleanup completed %v", err, cleaned)
	}
}

func TestChallengeCancellationWaitsForPublicationAndRetainsCleanup(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	cleaned := false
	provider := NewChallengeProvider(ctx, time.Minute, time.Second, func(ctx context.Context, name, value string) (Cleanup, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		// The server may have accepted the write before the response was lost.
		return func(ctx context.Context) error {
			if ctx.Err() != nil {
				t.Fatalf("cleanup inherited canceled publication: %v", ctx.Err())
			}
			if name != "_acme-challenge.example.test." || value == "" {
				t.Fatalf("invalid pinned challenge: %q %q", name, value)
			}
			cleaned = true
			return nil
		}, ctx.Err()
	})
	finished := make(chan error, 1)
	go func() { finished <- provider.Present("example.test", "token", "key") }()
	<-started
	cancel()
	<-canceled
	select {
	case err := <-finished:
		t.Fatalf("publication returned while its backend was still working: %v", err)
	default:
	}
	close(release)
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("Present() = %v, want cancellation", err)
	}
	if err := provider.CleanUp("example.test", "token", "key"); err != nil {
		t.Fatal(err)
	}
	if !cleaned {
		t.Fatal("uncertain publication lost its cleanup")
	}
}

func TestChallengeCleanupSharesOneBudgetAfterOrderCancellation(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		provider := NewChallengeProvider(ctx, time.Minute, time.Second, func(context.Context, string, string) (Cleanup, error) {
			return func(ctx context.Context) error {
				select {
				case <-time.After(20 * time.Second):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}, nil
		})
		for _, key := range []string{"first", "second"} {
			if err := provider.Present("example.test", "token", key); err != nil {
				t.Fatal(err)
			}
		}
		// The budget starts during cleanup, even after a long-running order.
		<-time.After(time.Hour)
		cancel()
		started := time.Now()
		if err := provider.CleanUp("example.test", "token", "first"); err != nil {
			t.Fatalf("first cleanup: %v", err)
		}
		if err := provider.CleanUp("example.test", "token", "second"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second cleanup = %v, want shared deadline", err)
		}
		if elapsed := time.Since(started); elapsed != challengeCleanupTimeout {
			t.Fatalf("cleanup took %s, want one %s budget", elapsed, challengeCleanupTimeout)
		}
	})
}

func TestChallengeCleanupCanRetryWithinItsBudget(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	failed := false
	removed := false
	provider := NewChallengeProvider(t.Context(), time.Minute, time.Second, func(context.Context, string, string) (Cleanup, error) {
		return func(context.Context) error {
			if !failed {
				failed = true
				return errCleanupUnavailable
			}
			removed = true
			return nil
		}, nil
	})
	if err := provider.Present("example.test", "token", "key"); err != nil {
		t.Fatal(err)
	}
	if err := provider.CleanUp("example.test", "token", "key"); !errors.Is(err, errCleanupUnavailable) {
		t.Fatalf("first cleanup = %v", err)
	}
	if err := provider.CleanUp("example.test", "token", "key"); err != nil || !removed {
		t.Fatalf("cleanup retry = %v, removed %v", err, removed)
	}
	if err := provider.CleanUp("example.test", "token", "key"); err != nil {
		t.Fatalf("repeated cleanup = %v", err)
	}
}

func TestChallengeCleanupPinsDelegatedCNAME(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "false")
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var changed atomic.Bool
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if req.Question[0].Name == "_acme-challenge.example.test." {
			target := "original.example.test."
			if changed.Load() {
				target = "replacement.example.test."
			}
			resp.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: target}}
		}
		_ = w.WriteMsg(resp)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	finished := make(chan error, 1)
	go func() { finished <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-finished; err != nil {
			t.Error(err)
		}
	})
	// Lego exposes a resolver setter but no getter. All other challenge tests in
	// this package disable CNAME lookup, and no test runs in parallel.
	if err := dns01.AddRecursiveNameservers([]string{conn.LocalAddr().String()})(nil); err != nil {
		t.Fatal(err)
	}
	var cleanedName string
	provider := NewChallengeProvider(t.Context(), time.Minute, time.Second, func(_ context.Context, name, _ string) (Cleanup, error) {
		return func(context.Context) error {
			cleanedName = name
			return nil
		}, nil
	})
	if err := provider.Present("example.test", "token", "key"); err != nil {
		t.Fatal(err)
	}
	changed.Store(true)
	if info := dns01.GetChallengeInfo("example.test", "key"); info.EffectiveFQDN != "replacement.example.test." {
		t.Fatalf("fixture did not change delegation: %q", info.EffectiveFQDN)
	}
	if err := provider.CleanUp("example.test", "token", "key"); err != nil {
		t.Fatal(err)
	}
	if cleanedName != "original.example.test." {
		t.Fatalf("cleanup followed changed CNAME: %q", cleanedName)
	}
}
