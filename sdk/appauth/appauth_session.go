// Package appauth is the application sign-in gate: an http.Handler that signs
// visitors in with a wallet, an access credential, OpenID Connect, SAML, or an
// email link, and passes only signed-in requests to the application behind it.
package appauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

type applicationAuthClaims struct {
	Subject        string `json:"sub"`
	Provider       string `json:"auth,omitempty"`
	Email          string `json:"email,omitempty"`
	Host           string `json:"host"`
	IssuedAtMillis int64  `json:"iat_ms,omitempty"`
	ExpiresAt      int64  `json:"exp"`
	Binding        string `json:"bnd,omitempty"`
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

type applicationAuthRedeemRequest struct {
	Credential string `json:"credential"`
}

type providerCache[T any] struct {
	flight singleflight.Group

	mu        sync.Mutex
	value     T
	fetchedAt time.Time
}

func (c *providerCache[T]) get(ctx context.Context, maxAge time.Duration, fetch func(context.Context) (T, error)) (T, error) {
	if value, ok := c.fresh(maxAge); ok {
		return value, nil
	}
	result := c.flight.DoChan("", func() (any, error) {
		if value, ok := c.fresh(maxAge); ok {
			return value, nil
		}
		value, err := fetch(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.value, c.fetchedAt = value, time.Now()
		c.mu.Unlock()
		return value, nil
	})
	var zero T
	select {
	case res := <-result:
		if res.Err != nil {
			return zero, res.Err
		}
		return res.Val.(T), nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (c *providerCache[T]) fresh(maxAge time.Duration) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value, !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < maxAge
}

func (a *applicationAuth) authorizeMutation(w http.ResponseWriter, r *http.Request, provider string) bool {
	if a.provider != provider {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return false
	}
	return true
}

func (a *applicationAuth) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderSIWE) {
		return
	}
	var req applicationAuthChallengeRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := strings.TrimSpace(r.Host)
	now := time.Now().UTC()
	challenge, err := a.siwe.Issue(req.Address, host, "https://"+host, now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.writeJSON(w, http.StatusOK, applicationAuthChallengeResponse{ChallengeID: challenge.ID, Message: challenge.Message, ExpiresAt: challenge.ExpiresAt})
}

func (a *applicationAuth) serveVerify(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderSIWE) {
		return
	}
	var req applicationAuthVerifyRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	address, err := a.siwe.Verify(req.ChallengeID, req.Message, req.Signature, r.Host, a.heldSince(r.Host), now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, "wallet signature is invalid")
		return
	}
	if err := a.setSession(w, Principal{Provider: ProviderSIWE, Subject: address}, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"address": address})
}

func (a *applicationAuth) serveRedeem(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderCredential) {
		return
	}
	var req applicationAuthRedeemRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	claims, err := verifyApplicationCredential(a.credentialKey, a.tunnelIdentity, r.Host, req.Credential, now)
	if err != nil || !a.subjectAllowed(claims.Subject) {
		a.writeJSONError(w, http.StatusUnauthorized, "application credential is invalid or expired")
		return
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if sessionExpiry := now.Add(applicationAuthSessionTTL); sessionExpiry.Before(expiresAt) {
		expiresAt = sessionExpiry
	}
	if err := a.setSession(w, Principal{Provider: ProviderCredential, Subject: claims.Subject}, strings.TrimSpace(r.Host), now, expiresAt); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": claims.Subject})
}

func (a *applicationAuth) authenticate(r *http.Request, credential string) (Principal, bool) {
	if credential == "" {
		return a.authenticateSession(r)
	}
	if a.provider != ProviderCredential {
		return Principal{}, false
	}
	claims, err := verifyApplicationCredential(a.credentialKey, a.tunnelIdentity, r.Host, credential, time.Now().UTC())
	if err == nil && a.subjectAllowed(claims.Subject) {
		return Principal{Provider: ProviderCredential, Subject: claims.Subject}, true
	}
	return Principal{}, false
}

func (a *applicationAuth) authenticateSession(r *http.Request) (Principal, bool) {
	cookie, err := r.Cookie(applicationAuthCookieName)
	if err != nil {
		return Principal{}, false
	}
	var claims applicationAuthClaims
	if err := decodeSignedApplicationAuthJSON(a.signingKey, cookie.Value, &claims); err != nil || !sameApplicationHost(claims.Host, r.Host) || time.Now().UTC().Unix() >= claims.ExpiresAt {
		return Principal{}, false
	}
	provider := claims.Provider
	if provider != a.provider {
		return Principal{}, false
	}
	if claims.IssuedAtMillis < a.heldSince(r.Host).UnixMilli() {
		return Principal{}, false
	}
	if provider == ProviderSIWE {
		address, err := identity.NormalizeEVMAddress(claims.Subject)
		if err != nil || a.siwe == nil || !a.siwe.AddressAllowed(address) {
			return Principal{}, false
		}
		return Principal{Provider: provider, Subject: address}, true
	}
	subject, ok := a.resolveAuthenticateSessionSubject(provider, claims.Subject, claims.Binding)
	if !ok {
		return Principal{}, false
	}
	return Principal{Provider: provider, Subject: subject, Email: claims.Email}, true
}

func (a *applicationAuth) resolveAuthenticateSessionSubject(provider, subjectClaim, bindingClaim string) (string, bool) {
	var subject string
	var err error
	switch provider {
	case ProviderOIDC, ProviderSAML, ProviderEmail:
		if binding := a.binding(); binding == "" || bindingClaim != binding {
			return "", false
		}
		subject, err = normalizeProviderPrincipal(subjectClaim)
	default:
		subject, err = normalizeApplicationAuthSubject(subjectClaim)
	}
	if err != nil || !a.subjectAllowed(subject) {
		return "", false
	}
	return subject, true
}

func (a *applicationAuth) issueSession(principal Principal, host string, issuedAt, expiresAt time.Time) (string, error) {
	claims := applicationAuthClaims{Subject: principal.Subject, Provider: principal.Provider, Email: principal.Email, Host: host, IssuedAtMillis: issuedAt.UnixMilli(), ExpiresAt: expiresAt.Unix(), Binding: a.binding()}
	return encodeSignedApplicationAuthJSON(a.signingKey, claims)
}

func (a *applicationAuth) binding() string {
	switch {
	case a.oidc != nil:
		return a.oidc.binding
	case a.saml != nil:
		return a.saml.binding
	case a.email != nil:
		return a.email.binding
	default:
		return ""
	}
}

func (a *applicationAuth) setSession(w http.ResponseWriter, principal Principal, host string, now, expiresAt time.Time) error {
	token, err := a.issueSession(principal, host, now, expiresAt)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: token, Path: "/", MaxAge: max(1, int(expiresAt.Sub(now).Seconds())), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return nil
}

func encodeSignedApplicationAuthJSON(key []byte, value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signApplicationAuthPayload(key, payload)), nil
}

func loginStateIssuedAt(expiresAt int64) time.Time {
	return time.Unix(expiresAt, 0).Add(-applicationAuthLoginStateTTL)
}

func encodeApplicationAuthLoginState(key []byte, claims any, next *string) (string, error) {
	token, err := encodeSignedApplicationAuthJSON(key, claims)
	if err == nil && len(token) > applicationAuthStateTokenLimit {
		*next = "/"
		token, err = encodeSignedApplicationAuthJSON(key, claims)
	}
	return token, err
}

func decodeSignedApplicationAuthJSON(key []byte, token string, dst any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errInvalidSignedValue
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errInvalidSignedValue
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, signApplicationAuthPayload(key, payload)) {
		return errInvalidSignedValue
	}
	return json.Unmarshal(payload, dst)
}

func signApplicationAuthPayload(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
