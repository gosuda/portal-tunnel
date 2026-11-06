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

func TestMuxRejectsMethodBeforeAdmission(t *testing.T) {
	for _, path := range []string{types.PathSDKRegisterChallenge, types.PathSDKRegister, types.PathDiscoveryAnnounce} {
		t.Run(path, func(t *testing.T) {
			limiter := NewSourceLimiter(60, 1, 0, 0)
			handler := Mux(nil, http.NotFoundHandler(), nil, limiter, nil, types.PreAuthConfig{
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

func TestMuxLeavesFallbackBodyLimitsToOwner(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := Mux(nil, fallback, nil, nil, nil, types.PreAuthConfig{})
	request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("upload"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("fallback status = %d, want 201", response.Code)
	}
}

// A client that signs from a second address still spends the budget of the one
// that asked, where a refusal lands. The budget also reads an identity as its
// lease will hold it, not as a request spells it.
func TestMuxUnapprovedLeaseBudget(t *testing.T) {
	const asking, signing, fromHeader = "198.51.100.1", "198.51.100.2", "X-Test-From"
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir(), UnapprovedLeasesPerSource: 2})
	if err != nil {
		t.Fatal(err)
	}
	access := NewAccess()
	manual := access.Snapshot()
	manual.SetMode(ModeManual)
	access.Commit(manual)
	handler := Mux(server, http.NotFoundHandler(), nil, nil, access, types.PreAuthConfig{})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = r.Header.Get(fromHeader) + ":1234"
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)
	post := func(path, from string, body any) (*http.Response, []byte) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, relay.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(fromHeader, from)
		response, err := relay.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		answer, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, answer
	}
	ask := func(leaseIdentity types.Identity) (*http.Response, []byte) {
		t.Helper()
		return post(types.PathSDKRegisterChallenge, asking, types.RegisterChallengeRequest{Identity: leaseIdentity})
	}
	generate := func(name string) types.Identity {
		t.Helper()
		leaseIdentity, err := identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		return leaseIdentity
	}

	for _, name := range []string{"budget-first", "budget-second"} {
		leaseIdentity := generate(name)
		asked, answer := ask(leaseIdentity)
		var challenge types.APIEnvelope[types.RegisterChallengeResponse]
		if err := json.Unmarshal(answer, &challenge); err != nil || asked.StatusCode != http.StatusCreated {
			t.Fatalf("%s challenge = %d, %v: %s", name, asked.StatusCode, err, answer)
		}
		signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.Data.SIWEMessage)
		if err != nil {
			t.Fatal(err)
		}
		request := types.RegisterRequest{ChallengeID: challenge.Data.ChallengeID, SIWEMessage: challenge.Data.SIWEMessage, SIWESignature: signature}
		if registered, answer := post(types.PathSDKRegister, signing, request); registered.StatusCode != http.StatusCreated {
			t.Fatalf("%s register = %d: %s", name, registered.StatusCode, answer)
		}
	}
	if refused, answer := ask(generate("budget-third")); refused.StatusCode != http.StatusTooManyRequests || refused.Header.Get("Retry-After") == "" {
		t.Fatalf("third unapproved lease = %d, Retry-After %q: %s", refused.StatusCode, refused.Header.Get("Retry-After"), answer)
	}

	approved := generate("budget-approved")
	decision := access.Snapshot()
	decision.Approve(approved.ServiceKey())
	if committed := access.Commit(decision); !server.SetServiceIdentityAccess(approved.ServiceKey(), committed.Access(approved.ServiceKey()), committed.Revision()) {
		t.Fatal("the approval was not applied")
	}
	spelled := approved
	spelled.Name = "budget_approved"
	if asked, answer := ask(spelled); asked.StatusCode != http.StatusCreated {
		t.Fatalf("approved identity, spelled another way = %d: %s", asked.StatusCode, answer)
	}
}
