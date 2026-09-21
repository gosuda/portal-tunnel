package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

const (
	applicationAuthLoginPath     = "/_portal/auth/login"
	applicationAuthChallengePath = "/_portal/auth/challenge"
	applicationAuthVerifyPath    = "/_portal/auth/verify"
	applicationAuthLogoutPath    = "/_portal/auth/logout"
	applicationAuthCookieName    = "__Host-portal_access"
	applicationAuthChallengeTTL  = 2 * time.Minute
	applicationAuthSessionTTL    = 24 * time.Hour
	applicationAuthBodyLimit     = 64 << 10
	applicationAuthChallengeMax  = 4096
)

const applicationAuthLoginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Portal</title><style>
:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#eef2ff;font:16px/1.5 system-ui,sans-serif}.card{width:min(30rem,calc(100% - 3rem));padding:2rem;border:1px solid #334155;border-radius:1rem;background:#111827;box-shadow:0 1.5rem 4rem #0008}h1{margin:0 0 .5rem;font-size:1.6rem}p{color:#cbd5e1}button{width:100%;padding:.8rem 1rem;border:0;border-radius:.6rem;background:#6366f1;color:white;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6;cursor:wait}#status{min-height:1.5rem;color:#fca5a5;font-size:.9rem}
</style></head><body><main class="card"><h1>Sign in to continue</h1><p>This application is protected by Portal. Connect an Ethereum wallet and sign the one-time message.</p><button id="signin">Connect wallet</button><p id="status" role="alert"></p></main>
<script>
const button=document.querySelector('#signin'),status=document.querySelector('#status');
const next=()=>{const value=new URLSearchParams(location.search).get('next')||'/';return value.startsWith('/')&&!value.startsWith('//')&&!value.includes('\\')?value:'/'};
button.addEventListener('click',async()=>{button.disabled=true;status.textContent='';try{
if(!window.ethereum)throw new Error('No Ethereum wallet was found in this browser.');
const accounts=await window.ethereum.request({method:'eth_requestAccounts'});const address=accounts&&accounts[0];if(!address)throw new Error('The wallet did not provide an account.');
const challengeResponse=await fetch('/_portal/auth/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address})});const challenge=await challengeResponse.json();if(!challengeResponse.ok)throw new Error(challenge.error||'Could not create a sign-in challenge.');
const signature=await window.ethereum.request({method:'personal_sign',params:[challenge.message,address]});
const verifyResponse=await fetch('/_portal/auth/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge_id:challenge.challenge_id,message:challenge.message,signature})});const result=await verifyResponse.json();if(!verifyResponse.ok)throw new Error(result.error||'The signature could not be verified.');location.assign(next());
}catch(error){status.textContent=error&&error.message?error.message:String(error);button.disabled=false;}});
</script></body></html>`

var parsedApplicationAuthLoginPage = template.Must(template.New("application-auth-login").Parse(applicationAuthLoginPage))

// ApplicationAuthConfig configures the tunnel-local SIWE access gate.
type ApplicationAuthConfig struct {
	SigningKey      []byte
	AllowedWallets  []string
	IdentityHeaders bool
}

type applicationAuth struct {
	next            http.Handler
	signingKey      []byte
	allowed         map[string]struct{}
	identityHeaders bool

	mu         sync.Mutex
	challenges map[string]applicationAuthChallenge
}

type applicationAuthChallenge struct {
	address   string
	host      string
	message   string
	expiresAt time.Time
}

type applicationAuthClaims struct {
	Address   string `json:"sub"`
	Host      string `json:"host"`
	ExpiresAt int64  `json:"exp"`
	SessionID string `json:"sid"`
}

type applicationAuthChallengeRequest struct {
	Address string `json:"address"`
}

type applicationAuthChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Message     string    `json:"message"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type applicationAuthVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Message     string `json:"message"`
	Signature   string `json:"signature"`
}

// NewApplicationAuth protects the complete HTTP gateway with local SIWE
// authentication. Its reserved login endpoints are the only bypass paths.
func NewApplicationAuth(next http.Handler, cfg ApplicationAuthConfig) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("application auth handler is required")
	}
	if len(cfg.SigningKey) < 32 {
		return nil, errors.New("application auth signing key must be at least 32 bytes")
	}
	allowedWallets, err := normalizeApplicationAuthWallets(cfg.AllowedWallets)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(allowedWallets))
	for _, address := range allowedWallets {
		allowed[strings.ToLower(address)] = struct{}{}
	}
	return &applicationAuth{
		next:            next,
		signingKey:      append([]byte(nil), cfg.SigningKey...),
		allowed:         allowed,
		identityHeaders: cfg.IdentityHeaders,
		challenges:      make(map[string]applicationAuthChallenge),
	}, nil
}

func normalizeApplicationAuthWallets(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		address, err := identity.NormalizeEVMAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("application auth allowed wallet: %w", err)
		}
		key := strings.ToLower(address)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, address)
	}
	return normalized, nil
}

func (a *applicationAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("X-Portal-User")
	r.Header.Del("X-Portal-Auth")

	switch r.URL.Path {
	case applicationAuthLoginPath:
		a.serveLogin(w, r)
	case applicationAuthChallengePath:
		a.serveChallenge(w, r)
	case applicationAuthVerifyPath:
		a.serveVerify(w, r)
	case applicationAuthLogoutPath:
		a.serveLogout(w, r)
	default:
		address, ok := a.authenticatedAddress(r)
		if !ok {
			a.requireLogin(w, r)
			return
		}
		stripApplicationAuthCookie(r)
		if a.identityHeaders {
			r.Header.Set("X-Portal-User", address)
			r.Header.Set("X-Portal-Auth", "siwe")
		}
		a.next.ServeHTTP(w, r)
	}
}

func stripApplicationAuthCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != applicationAuthCookieName {
			r.AddCookie(cookie)
		}
	}
}

func (a *applicationAuth) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_ = parsedApplicationAuthLoginPage.Execute(w, nil)
}

func (a *applicationAuth) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthChallengeRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	address, err := identity.NormalizeEVMAddress(req.Address)
	if err != nil || !a.addressAllowed(address) {
		a.writeJSONError(w, http.StatusUnauthorized, "wallet is not allowed")
		return
	}
	host := strings.TrimSpace(r.Host)
	now := time.Now().UTC()
	challengeID := "pac_" + rand.Text()
	expiresAt := now.Add(applicationAuthChallengeTTL)
	message, err := identity.FormatSIWEMessage(identity.SIWEMessage{
		Domain: host, Address: address, URI: "https://" + host,
		Statement: "Sign in to this Portal application", Nonce: rand.Text(), RequestID: challengeID,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, "invalid application origin")
		return
	}
	a.mu.Lock()
	a.cleanupChallengesLocked(now)
	if len(a.challenges) >= applicationAuthChallengeMax {
		a.mu.Unlock()
		a.writeJSONError(w, http.StatusTooManyRequests, "too many pending sign-in challenges")
		return
	}
	a.challenges[challengeID] = applicationAuthChallenge{address: address, host: host, message: message, expiresAt: expiresAt}
	a.mu.Unlock()
	a.writeJSON(w, http.StatusOK, applicationAuthChallengeResponse{ChallengeID: challengeID, Message: message, ExpiresAt: expiresAt})
}

func (a *applicationAuth) serveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthVerifyRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	a.mu.Lock()
	a.cleanupChallengesLocked(now)
	challenge, ok := a.challenges[strings.TrimSpace(req.ChallengeID)]
	delete(a.challenges, strings.TrimSpace(req.ChallengeID))
	a.mu.Unlock()
	if !ok || challenge.host != strings.TrimSpace(r.Host) || req.Message != challenge.message || now.After(challenge.expiresAt) {
		a.writeJSONError(w, http.StatusUnauthorized, "sign-in challenge is invalid or expired")
		return
	}
	if err := identity.VerifySIWEMessage(challenge.message, req.Signature, challenge.address, challenge.expiresAt, now); err != nil || !a.addressAllowed(challenge.address) {
		a.writeJSONError(w, http.StatusUnauthorized, "wallet signature is invalid")
		return
	}
	token, err := a.issueSession(challenge.address, challenge.host, now)
	if err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: token, Path: "/", MaxAge: int(applicationAuthSessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	a.writeJSON(w, http.StatusOK, map[string]string{"address": challenge.address})
}

func (a *applicationAuth) serveLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "logout requires a same-origin POST")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *applicationAuth) authenticatedAddress(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(applicationAuthCookieName)
	if err != nil {
		return "", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, a.sign(payload)) {
		return "", false
	}
	var claims applicationAuthClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.SessionID == "" || !strings.EqualFold(claims.Host, strings.TrimSpace(r.Host)) || time.Now().UTC().Unix() >= claims.ExpiresAt {
		return "", false
	}
	address, err := identity.NormalizeEVMAddress(claims.Address)
	if err != nil || !a.addressAllowed(address) {
		return "", false
	}
	return address, true
}

func (a *applicationAuth) issueSession(address, host string, now time.Time) (string, error) {
	payload, err := json.Marshal(applicationAuthClaims{Address: address, Host: host, ExpiresAt: now.Add(applicationAuthSessionTTL).Unix(), SessionID: rand.Text()})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(a.sign(payload)), nil
}

func (a *applicationAuth) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, a.signingKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (a *applicationAuth) addressAllowed(address string) bool {
	if len(a.allowed) == 0 {
		return true
	}
	_, ok := a.allowed[strings.ToLower(address)]
	return ok
}

func (a *applicationAuth) cleanupChallengesLocked(now time.Time) {
	for id, challenge := range a.challenges {
		if now.After(challenge.expiresAt) {
			delete(a.challenges, id)
		}
	}
}

func (a *applicationAuth) requireLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		next := r.URL.RequestURI()
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		http.Redirect(w, r, applicationAuthLoginPath+"?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	a.writeJSONError(w, http.StatusUnauthorized, "authentication required")
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	return strings.EqualFold(origin, "https://"+strings.TrimSpace(r.Host))
}

func decodeApplicationAuthJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, applicationAuthBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func (a *applicationAuth) writeJSONError(w http.ResponseWriter, status int, message string) {
	a.writeJSON(w, status, map[string]string{"error": message})
}

func (a *applicationAuth) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
