package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestHTTPReplicasShareURLAndSurviveOneClientStopping(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL()
	serviceIdentity, err := identity.Generate("replicas")
	if err != nil {
		t.Fatal(err)
	}
	relayURL := fmt.Sprintf("https://127.0.0.1:%d", h.sniPort)
	var replicas []*sdk.Exposure
	var publicURL string
	for _, marker := range []string{"replica-one", "replica-two"} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, marker)
		}))
		t.Cleanup(origin.Close)
		target, err := url.Parse(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		exposure, err := sdk.Expose(t.Context(), serviceIdentity, []string{relayURL}, sdk.WithReplicas())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = exposure.Close() })
		go func() { _ = sdk.Proxy(t.Context(), exposure, target.Host) }()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		statuses, err := exposure.WaitReady(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(statuses) != 1 || statuses[0].PublicURL == "" {
			t.Fatalf("replica has no public URL: %+v", statuses)
		}
		if publicURL != "" && publicURL != statuses[0].PublicURL {
			t.Fatal("replicas received different public URLs")
		}
		publicURL = statuses[0].PublicURL
		replicas = append(replicas, exposure)
	}
	seen := make(map[string]bool)
	for range 16 {
		seen[h.get(publicURL)] = true
	}
	if !seen["replica-one"] || !seen["replica-two"] {
		t.Fatalf("new connections did not reach both origins: %v", seen)
	}
	listed := 0
	for _, lease := range h.server.PublicLeases() {
		if lease.Address == serviceIdentity.Address {
			listed++
		}
	}
	if listed != 1 {
		t.Fatalf("directory contains %d entries for one service", listed)
	}
	if err := replicas[0].Close(); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if body := h.get(publicURL); body != "replica-two" {
			t.Fatalf("surviving replica returned %q", body)
		}
	}
}
