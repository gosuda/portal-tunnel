package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spruceid/siwe-go"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestExposeNoRelayInputs(t *testing.T) {
	exposure, err := Expose(context.Background(), ExposeConfig{Name: "demo"})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	if exposure == nil {
		t.Fatal("Expose() exposure = nil, want non-nil")
	}
	defer exposure.Close()
	if got := exposure.ActiveRelayURLs(); len(got) != 0 {
		t.Fatalf("Expose() relay urls = %v, want empty", got)
	}
}

func TestExposeLoadsPrivateKeyFromIdentityPath(t *testing.T) {
	privateKey := strings.Repeat("11", 32)
	identity, err := utils.ResolveSecp256k1Identity(privateKey)
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	identity.Name = "demo"
	identityPath := t.TempDir() + "/identity.json"
	if err := utils.SaveIdentity(identityPath, identity); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	challengeReqCh := make(chan types.RegisterChallengeRequest, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathSDKDomain:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.DomainResponse]{
				OK: true,
				Data: types.DomainResponse{
					ProtocolVersion: types.ProtocolVersion,
				},
			})
		case types.PathSDKRegisterChallenge:
			var challengeReq types.RegisterChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&challengeReq); err != nil {
				t.Fatalf("decode register challenge request: %v", err)
			}
			select {
			case challengeReqCh <- challengeReq:
			default:
			}
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterChallengeResponse]{
				OK: true,
				Data: types.RegisterChallengeResponse{
					ChallengeID: "challenge-1",
					ExpiresAt:   time.Now().Add(time.Minute).UTC(),
					SIWEMessage: mustSDKTestSIWEMessage(t, r, challengeReq.Identity.Address, "challenge-1"),
				},
			})
		case types.PathSDKRegister:
			var registerReq types.RegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&registerReq); err != nil {
				t.Fatalf("decode register request: %v", err)
			}
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterResponse]{
				OK: true,
				Data: types.RegisterResponse{
					Identity:    types.Identity{Name: identity.Name, Address: identity.Address},
					Hostname:    "127.0.0.1",
					AccessToken: "jwt-register-2",
				},
			})
		case types.PathSDKConnect:
			writeSDKTestEnvelope(w, http.StatusForbidden, types.APIEnvelope[any]{
				OK:    false,
				Error: &types.APIError{Code: types.APIErrorCodeUnauthorized, Message: "not used in test"},
			})
		case types.PathSDKRenew:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.RenewResponse]{
				OK:   true,
				Data: types.RenewResponse{AccessToken: "jwt-renew-2"},
			})
		case types.PathSDKUnregister:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[any]{OK: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	exposure, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:    []string{server.URL},
		IdentityPath: identityPath,
	})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer exposure.Close()

	var challengeReq types.RegisterChallengeRequest
	waitForSDKTest(t, func() bool {
		select {
		case challengeReq = <-challengeReqCh:
			return true
		default:
			return false
		}
	})

	if challengeReq.Identity.Address != identity.Address {
		t.Fatalf("register challenge Identity.Address = %q, want %q", challengeReq.Identity.Address, identity.Address)
	}
	if challengeReq.Identity.Name != identity.Name {
		t.Fatalf("register challenge Identity.Name = %q, want %q", challengeReq.Identity.Name, identity.Name)
	}
}

func TestExposeLoadsIdentityFromJSON(t *testing.T) {
	privateKey := strings.Repeat("22", 32)
	identity, err := utils.ResolveSecp256k1Identity(privateKey)
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	identity.Name = "demo-json"

	payload, err := json.Marshal(map[string]string{
		"name":        identity.Name,
		"address":     identity.Address,
		"public_key":  identity.PublicKey,
		"private_key": identity.PrivateKey,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	challengeReqCh := make(chan types.RegisterChallengeRequest, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathSDKDomain:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.DomainResponse]{
				OK: true,
				Data: types.DomainResponse{
					ProtocolVersion: types.ProtocolVersion,
				},
			})
		case types.PathSDKRegisterChallenge:
			var challengeReq types.RegisterChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&challengeReq); err != nil {
				t.Fatalf("decode register challenge request: %v", err)
			}
			select {
			case challengeReqCh <- challengeReq:
			default:
			}
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterChallengeResponse]{
				OK: true,
				Data: types.RegisterChallengeResponse{
					ChallengeID: "challenge-1",
					ExpiresAt:   time.Now().Add(time.Minute).UTC(),
					SIWEMessage: mustSDKTestSIWEMessage(t, r, challengeReq.Identity.Address, "challenge-1"),
				},
			})
		case types.PathSDKRegister:
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterResponse]{
				OK: true,
				Data: types.RegisterResponse{
					Identity:    types.Identity{Name: identity.Name, Address: identity.Address},
					Hostname:    "127.0.0.1",
					AccessToken: "jwt-register-json",
				},
			})
		case types.PathSDKConnect:
			writeSDKTestEnvelope(w, http.StatusForbidden, types.APIEnvelope[any]{
				OK:    false,
				Error: &types.APIError{Code: types.APIErrorCodeUnauthorized, Message: "not used in test"},
			})
		case types.PathSDKRenew:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.RenewResponse]{
				OK:   true,
				Data: types.RenewResponse{AccessToken: "jwt-renew-json"},
			})
		case types.PathSDKUnregister:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[any]{OK: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	exposure, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:    []string{server.URL},
		IdentityJSON: string(payload),
	})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer exposure.Close()

	var challengeReq types.RegisterChallengeRequest
	waitForSDKTest(t, func() bool {
		select {
		case challengeReq = <-challengeReqCh:
			return true
		default:
			return false
		}
	})

	if challengeReq.Identity.Name != identity.Name {
		t.Fatalf("register challenge Identity.Name = %q, want %q", challengeReq.Identity.Name, identity.Name)
	}
	if challengeReq.Identity.Address != identity.Address {
		t.Fatalf("register challenge Identity.Address = %q, want %q", challengeReq.Identity.Address, identity.Address)
	}
}

func TestExposeGeneratesAddressWithoutPrivateKey(t *testing.T) {
	challengeReqCh := make(chan types.RegisterChallengeRequest, 1)
	var mu sync.RWMutex
	var registeredIdentity types.Identity
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathSDKDomain:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.DomainResponse]{
				OK: true,
				Data: types.DomainResponse{
					ProtocolVersion: types.ProtocolVersion,
				},
			})
		case types.PathSDKRegisterChallenge:
			var challengeReq types.RegisterChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&challengeReq); err != nil {
				t.Fatalf("decode register challenge request: %v", err)
			}
			mu.Lock()
			registeredIdentity = challengeReq.Identity.Copy()
			mu.Unlock()
			select {
			case challengeReqCh <- challengeReq:
			default:
			}
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterChallengeResponse]{
				OK: true,
				Data: types.RegisterChallengeResponse{
					ChallengeID: "challenge-1",
					ExpiresAt:   time.Now().Add(time.Minute).UTC(),
					SIWEMessage: mustSDKTestSIWEMessage(t, r, challengeReq.Identity.Address, "challenge-1"),
				},
			})
		case types.PathSDKRegister:
			var registerReq types.RegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&registerReq); err != nil {
				t.Fatalf("decode register request: %v", err)
			}
			mu.RLock()
			identity := registeredIdentity.Copy()
			mu.RUnlock()
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterResponse]{
				OK: true,
				Data: types.RegisterResponse{
					Identity:    identity,
					Hostname:    "127.0.0.1",
					AccessToken: "jwt-register-3",
				},
			})
		case types.PathSDKConnect:
			writeSDKTestEnvelope(w, http.StatusForbidden, types.APIEnvelope[any]{
				OK:    false,
				Error: &types.APIError{Code: types.APIErrorCodeUnauthorized, Message: "not used in test"},
			})
		case types.PathSDKRenew:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.RenewResponse]{
				OK:   true,
				Data: types.RenewResponse{AccessToken: "jwt-renew-3"},
			})
		case types.PathSDKUnregister:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[any]{OK: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	exposure, err := Expose(context.Background(), ExposeConfig{
		RelayURLs: []string{server.URL},
		Name:      "demo",
	})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer exposure.Close()

	var challengeReq types.RegisterChallengeRequest
	waitForSDKTest(t, func() bool {
		select {
		case challengeReq = <-challengeReqCh:
			return true
		default:
			return false
		}
	})

	if challengeReq.Identity.Address == "" {
		t.Fatal("register challenge Identity.Address = empty, want generated address")
	}
	if _, err := utils.NormalizeEVMAddress(challengeReq.Identity.Address); err != nil {
		t.Fatalf("register challenge Identity.Address = %q, want valid EVM address: %v", challengeReq.Identity.Address, err)
	}
}

func TestAPIClientRegisterLeaseRequiresSNIPortForUDP(t *testing.T) {
	privateKey := strings.Repeat("33", 32)
	identity, err := utils.ResolveSecp256k1Identity(privateKey)
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	identity.Name = "demo-udp"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathSDKDomain:
			writeSDKTestEnvelope(w, http.StatusOK, types.APIEnvelope[types.DomainResponse]{
				OK: true,
				Data: types.DomainResponse{
					ProtocolVersion: types.ProtocolVersion,
				},
			})
		case types.PathSDKRegisterChallenge:
			var challengeReq types.RegisterChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&challengeReq); err != nil {
				t.Fatalf("decode register challenge request: %v", err)
			}
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterChallengeResponse]{
				OK: true,
				Data: types.RegisterChallengeResponse{
					ChallengeID: "challenge-udp",
					ExpiresAt:   time.Now().Add(time.Minute).UTC(),
					SIWEMessage: mustSDKTestSIWEMessage(t, r, challengeReq.Identity.Address, "challenge-udp"),
				},
			})
		case types.PathSDKRegister:
			writeSDKTestEnvelope(w, http.StatusCreated, types.APIEnvelope[types.RegisterResponse]{
				OK: true,
				Data: types.RegisterResponse{
					Identity:    types.Identity{Name: identity.Name, Address: identity.Address},
					Hostname:    "127.0.0.1",
					AccessToken: "jwt-register-udp",
					UDPEnabled:  true,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	api, err := newApiClient(server.URL, ListenerConfig{Identity: identity})
	if err != nil {
		t.Fatalf("newApiClient() error = %v", err)
	}

	_, err = api.registerLease(context.Background(), 30*time.Second, true, false)
	if err == nil {
		t.Fatal("registerLease() error = nil, want missing sni port error")
	}
	if !strings.Contains(err.Error(), "sni port") {
		t.Fatalf("registerLease() error = %v, want missing sni port error", err)
	}
}

func mustSDKTestSIWEMessage(t *testing.T, r *http.Request, address, challengeID string) string {
	t.Helper()

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	message, err := siwe.InitMessage(r.Host, address, scheme+"://"+r.Host+types.PathSDKRegister, "testnonce123", map[string]interface{}{
		"statement":      "Register a portal lease",
		"chainId":        1,
		"issuedAt":       time.Now().UTC().Format(time.RFC3339),
		"expirationTime": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"requestId":      challengeID,
	})
	if err != nil {
		t.Fatalf("siwe.InitMessage() error = %v", err)
	}
	return message.String()
}

func writeSDKTestEnvelope[T any](w http.ResponseWriter, status int, envelope types.APIEnvelope[T]) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if envelope.OK {
		_ = json.NewEncoder(w).Encode(envelope.Data)
		return
	}
	if envelope.Error != nil {
		_ = json.NewEncoder(w).Encode(envelope.Error)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{})
}

func waitForSDKTest(t *testing.T, fn func() bool) {
	t.Helper()

	waitForSDKTestWithTimeout(t, 5*time.Second, fn)
}

func waitForSDKTestWithTimeout(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timed out waiting for condition")
}
