package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
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

func TestHTTPReplicaAliasSessionSurvivesJoiningAndRestarting(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL()
	id, err := identity.Generate("authenticated-replicas")
	if err != nil {
		t.Fatal(err)
	}
	start := func(marker string) (*sdk.Exposure, sdk.RelayStatus) {
		t.Helper()
		exposure, err := sdk.Expose(t.Context(), id, []string{"https://" + h.sniAddr}, sdk.WithReplicas())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = exposure.Close() })
		gate, err := appauth.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, marker)
		}), id, appauth.Config{Provider: appauth.ProviderCredential, PublicHosts: func() []appauth.PublicHost {
			var hosts []appauth.PublicHost
			for _, relay := range exposure.Relays() {
				hosts = append(hosts, appauth.PublicHost{URL: relay.PublicURL}, appauth.PublicHost{URL: relay.AliasURL, Epoch: relay.AliasEpoch, Since: relay.AliasSince})
			}
			return hosts
		}})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = sdk.RunHTTP(t.Context(), exposure, gate, "") }()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		ready, err := exposure.WaitReady(ctx)
		if err != nil || len(ready) != 1 || ready[0].AliasURL == "" || ready[0].AliasEpoch == "" {
			t.Fatalf("alias readiness: %+v, %v", ready, err)
		}
		return exposure, ready[0]
	}
	first, initial := start("first")
	client := relayTenantClient(t, relayControlClient(t, h.stateDir), &url.URL{Host: h.sniAddr})
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	credential, err := appauth.IssueCredential(id, initial.AliasURL, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, initial.AliasURL+types.PathApplicationAuthRedeem, strings.NewReader(fmt.Sprintf(`{"credential":%q}`, credential)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", initial.AliasURL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("alias sign-in: status %d, cookies %v", resp.StatusCode, cookies)
	}
	second, joined := start("second")
	if joined.AliasEpoch != initial.AliasEpoch {
		t.Fatal("joining a replica changed alias ownership")
	}
	seen := make(map[string]bool)
	for range 16 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, initial.AliasURL+"/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookies[0])
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("alias session across replicas: status %d, %s, %v", resp.StatusCode, body, err)
		}
		seen[string(body)] = true
	}
	if !seen["first"] || !seen["second"] {
		t.Fatalf("authenticated requests did not reach both replicas: %v", seen)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_, restarted := start("restarted")
	if restarted.AliasEpoch != initial.AliasEpoch {
		t.Fatal("restarting one replica changed alias ownership")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, initial.AliasURL+"/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookies[0])
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "restarted" {
		t.Fatalf("session on restarted replica: status %d, %s, %v", resp.StatusCode, body, err)
	}
}
