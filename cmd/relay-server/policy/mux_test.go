package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const testFromHeader = "X-Test-From"

func marshalMuxRequest(t *testing.T, body any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readMuxAnswer(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

func postMuxRaw(t *testing.T, relay *httptest.Server, path, from string, raw []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, relay.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(testFromHeader, from)
	response, err := relay.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response, readMuxAnswer(t, response)
}

func postMuxJSON(t *testing.T, relay *httptest.Server, path, from string, body any) (*http.Response, []byte) {
	t.Helper()
	return postMuxRaw(t, relay, path, from, marshalMuxRequest(t, body))
}

func generateLeaseIdentity(t *testing.T, name string) types.Identity {
	t.Helper()
	leaseIdentity, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return leaseIdentity
}

func startMuxRelay(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = r.Header.Get(testFromHeader) + ":1234"
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)
	return relay
}

func completeBudgetRegistration(t *testing.T, relay *httptest.Server, asking, signing, name string) {
	t.Helper()
	leaseIdentity := generateLeaseIdentity(t, name)
	asked, answer := postMuxJSON(t, relay, types.PathSDKRegisterChallenge, asking, types.RegisterChallengeRequest{Identity: leaseIdentity})
	var challenge types.APIEnvelope[types.RegisterChallengeResponse]
	if err := json.Unmarshal(answer, &challenge); err != nil || asked.StatusCode != http.StatusCreated {
		t.Fatalf("%s challenge = %d, %v: %s", name, asked.StatusCode, err, answer)
	}
	signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.Data.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	request := types.RegisterRequest{ChallengeID: challenge.Data.ChallengeID, SIWEMessage: challenge.Data.SIWEMessage, SIWESignature: signature}
	if registered, answer := postMuxJSON(t, relay, types.PathSDKRegister, signing, request); registered.StatusCode != http.StatusCreated {
		t.Fatalf("%s register = %d: %s", name, registered.StatusCode, answer)
	}
}

func checkApprovedSpelledIdentity(t *testing.T, relay *httptest.Server, server *portal.Server, access *Store, asking string) {
	t.Helper()
	approved := generateLeaseIdentity(t, "budget-approved")
	decision := access.Snapshot()
	decision.Approve(approved.ServiceKey())
	if committed := access.Commit(decision); !server.SetServiceIdentityAccess(approved.ServiceKey(), committed.Access(approved.ServiceKey()), committed.Revision()) {
		t.Fatal("the approval was not applied")
	}
	spelled := approved
	spelled.Name = "budget_approved"
	if asked, answer := postMuxJSON(t, relay, types.PathSDKRegisterChallenge, asking, types.RegisterChallengeRequest{Identity: spelled}); asked.StatusCode != http.StatusCreated {
		t.Fatalf("approved identity, spelled another way = %d: %s", asked.StatusCode, answer)
	}
}

func TestMuxRejectsMethodBeforeAdmission(t *testing.T) {
	for _, path := range []string{types.PathSDKRegisterChallenge, types.PathSDKRegister, types.PathDiscoveryAnnounce} {
		t.Run(path, func(t *testing.T) {
			limiter := NewSourceLimiter(60, 1, 0, 0)
			handler := Mux(nil, http.NotFoundHandler(), nil, limiter, nil, PreAuthConfig{
				ChallengeCost: 1,
				RegisterCost:  1,
				AnnounceCost:  1,
			})
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("GET status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
			}
			if retry, _ := limiter.Allow(netip.MustParseAddr("192.0.2.1"), 1); retry != 0 {
				t.Fatal("unsupported method consumed the pre-auth budget")
			}
		})
	}
}

func openAllowedTunnelIngress(t *testing.T) (*portal.Server, *Ingress) {
	t.Helper()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(false, "", "192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return server, ingress
}

func TestMuxRefusesTunnelsFromOutsideAllowedNetworks(t *testing.T) {
	server, ingress := openAllowedTunnelIngress(t)
	limiter := NewSourceLimiter(1, 1, 1, 1)
	handler := Mux(server, http.NotFoundHandler(), ingress, limiter, NewStore(), PreAuthConfig{ChallengeCost: 1, RegisterCost: 1, AnnounceCost: 1})
	leaseIdentity := generateLeaseIdentity(t, "source-allowed")
	body := marshalMuxRequest(t, types.RegisterChallengeRequest{Identity: leaseIdentity})
	relay := startMuxRelay(t, handler)
	post := func(path, from string) (int, []byte) {
		t.Helper()
		response, answer := postMuxRaw(t, relay, path, from, body)
		return response.StatusCode, answer
	}

	for _, path := range []string{types.PathSDKRegisterChallenge, types.PathSDKRegister, types.PathSDKRenew} {
		status, answer := post(path, "198.51.100.7")
		var envelope types.APIEnvelope[json.RawMessage]
		if err := json.Unmarshal(answer, &envelope); err != nil || status != http.StatusForbidden ||
			envelope.Error == nil || envelope.Error.Code != types.APIErrorCodeSourceNotAllowed {
			t.Fatalf("%s from outside the allowed networks = %d: %s", path, status, answer)
		}
	}
	if status, answer := post(types.PathSDKRegisterChallenge, "192.0.2.7"); status != http.StatusCreated {
		t.Fatalf("challenge from an allowed network = %d: %s", status, answer)
	}
}

func TestMuxLeavesFallbackBodyLimitsToOwner(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := Mux(nil, fallback, nil, nil, nil, PreAuthConfig{})
	request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("upload"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("fallback status = %d, want 201", response.Code)
	}
}

func TestMuxUnapprovedLeaseBudget(t *testing.T) {
	const asking, signing = "198.51.100.1", "198.51.100.2"
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir(), UnapprovedLeasesPerSource: 2})
	if err != nil {
		t.Fatal(err)
	}
	access := NewStore()
	manual := access.Snapshot()
	manual.SetMode(ModeManual)
	access.Commit(manual)
	handler := Mux(server, http.NotFoundHandler(), nil, nil, access, PreAuthConfig{})
	relay := startMuxRelay(t, handler)
	post := func(path, from string, body any) (*http.Response, []byte) {
		t.Helper()
		return postMuxJSON(t, relay, path, from, body)
	}
	ask := func(leaseIdentity types.Identity) (*http.Response, []byte) {
		t.Helper()
		return post(types.PathSDKRegisterChallenge, asking, types.RegisterChallengeRequest{Identity: leaseIdentity})
	}

	for _, name := range []string{"budget-first", "budget-second"} {
		completeBudgetRegistration(t, relay, asking, signing, name)
	}
	if refused, answer := ask(generateLeaseIdentity(t, "budget-third")); refused.StatusCode != http.StatusTooManyRequests || refused.Header.Get("Retry-After") == "" {
		t.Fatalf("third unapproved lease = %d, Retry-After %q: %s", refused.StatusCode, refused.Header.Get("Retry-After"), answer)
	}

	checkApprovedSpelledIdentity(t, relay, server, access, asking)
}

func TestMuxPreAuthBudgetExhaustionRefusesWithRetryAfter(t *testing.T) {
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	limiter := NewSourceLimiter(1, 1, 0, 0)
	handler := Mux(server, http.NotFoundHandler(), nil, limiter, NewStore(), PreAuthConfig{ChallengeCost: 1})
	leaseIdentity := generateLeaseIdentity(t, "pre-auth-budget")
	body := marshalMuxRequest(t, types.RegisterChallengeRequest{Identity: leaseIdentity})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "198.51.100.1:1234"
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)
	challenge := func() (int, http.Header, string) {
		response, err := relay.Client().Post(relay.URL+types.PathSDKRegisterChallenge, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, string(readMuxAnswer(t, response))
	}
	if status, _, answer := challenge(); status != http.StatusCreated {
		t.Fatalf("first challenge = %d, want 201: %s", status, answer)
	}
	status, header, answer := challenge()
	if status != http.StatusTooManyRequests || header.Get("Retry-After") == "" {
		t.Fatalf("exhausted pre-auth budget = %d, Retry-After %q, want 429 with guidance: %s", status, header.Get("Retry-After"), answer)
	}
}
