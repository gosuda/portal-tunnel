package identity

import (
	"testing"
	"time"
)

const (
	testTokenIssuer  = "portal-relay"
	testTokenLeaseID = "lease-0001"
)

func TestLeaseAccessTokenClaimsRoundTrip(t *testing.T) {
	leaseIdentity, err := Generate("demo")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	authority := NewLocalAuthority(leaseIdentity)
	now := time.Now().UTC()

	token, issued, err := IssueLeaseAccessToken(authority, testTokenIssuer, leaseIdentity, testTokenLeaseID, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueLeaseAccessToken() error = %v", err)
	}

	claims, err := VerifyLeaseAccessToken(token, authority.Identity().PublicKey, testTokenIssuer, now)
	if err != nil {
		t.Fatalf("VerifyLeaseAccessToken() error = %v", err)
	}
	if claims.Issuer != testTokenIssuer {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, testTokenIssuer)
	}
	if claims.Subject != leaseIdentity.Key() {
		t.Fatalf("subject = %q, want lease identity key %q", claims.Subject, leaseIdentity.Key())
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != leaseAccessTokenAudience {
		t.Fatalf("audience = %v, want [%s]", claims.Audience, leaseAccessTokenAudience)
	}
	if claims.LeaseID != testTokenLeaseID {
		t.Fatalf("lease id = %q, want %q", claims.LeaseID, testTokenLeaseID)
	}
	// The wire identity claim carries only the public fields (name, address).
	if claims.Identity.Name != leaseIdentity.Name || claims.Identity.Address != leaseIdentity.Address {
		t.Fatalf("identity claim = %s/%s, want %s/%s", claims.Identity.Name, claims.Identity.Address, leaseIdentity.Name, leaseIdentity.Address)
	}
	if !claims.Expiry.Time().Equal(issued.Expiry.Time()) {
		t.Fatalf("expiry = %v, want issued expiry %v", claims.Expiry.Time(), issued.Expiry.Time())
	}
}

func TestReverseCapabilityClaimsRoundTrip(t *testing.T) {
	leaseIdentity, err := Generate("demo")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	authority := NewLocalAuthority(leaseIdentity)
	now := time.Now().UTC()

	token, issued, err := IssueReverseCapability(authority, testTokenIssuer, leaseIdentity, testTokenLeaseID, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueReverseCapability() error = %v", err)
	}

	claims, err := VerifyReverseCapability(token, authority.Identity().PublicKey, testTokenIssuer, now)
	if err != nil {
		t.Fatalf("VerifyReverseCapability() error = %v", err)
	}
	if claims.Issuer != testTokenIssuer {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, testTokenIssuer)
	}
	if claims.Subject != leaseIdentity.Key() {
		t.Fatalf("subject = %q, want lease identity key %q", claims.Subject, leaseIdentity.Key())
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != reverseCapabilityAudience {
		t.Fatalf("audience = %v, want [%s]", claims.Audience, reverseCapabilityAudience)
	}
	if claims.LeaseID != testTokenLeaseID {
		t.Fatalf("lease id = %q, want %q", claims.LeaseID, testTokenLeaseID)
	}
	if !claims.Expiry.Time().Equal(issued.Expiry.Time()) {
		t.Fatalf("expiry = %v, want issued expiry %v", claims.Expiry.Time(), issued.Expiry.Time())
	}
}

func TestLeaseTokenAudiencesRejectEachOther(t *testing.T) {
	leaseIdentity, err := Generate("demo")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	authority := NewLocalAuthority(leaseIdentity)
	publicKey := authority.Identity().PublicKey
	now := time.Now().UTC()

	leaseToken, _, err := IssueLeaseAccessToken(authority, testTokenIssuer, leaseIdentity, testTokenLeaseID, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueLeaseAccessToken() error = %v", err)
	}
	reverseToken, _, err := IssueReverseCapability(authority, testTokenIssuer, leaseIdentity, testTokenLeaseID, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueReverseCapability() error = %v", err)
	}

	// A lease access token must never authorize reverse-capability actions.
	if _, err := VerifyReverseCapability(leaseToken, publicKey, testTokenIssuer, now); err == nil {
		t.Fatal("lease access token accepted as a reverse capability: audiences are not mutually exclusive")
	}
	// A reverse capability must never authorize lease operations.
	if _, err := VerifyLeaseAccessToken(reverseToken, publicKey, testTokenIssuer, now); err == nil {
		t.Fatal("reverse capability accepted as a lease access token: audiences are not mutually exclusive")
	}
}

func TestExpiredLeaseAccessTokenRejected(t *testing.T) {
	leaseIdentity, err := Generate("demo")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	authority := NewLocalAuthority(leaseIdentity)

	token, issued, err := IssueLeaseAccessToken(authority, testTokenIssuer, leaseIdentity, testTokenLeaseID, time.Minute)
	if err != nil {
		t.Fatalf("IssueLeaseAccessToken() error = %v", err)
	}

	if _, err := VerifyLeaseAccessToken(token, authority.Identity().PublicKey, testTokenIssuer, issued.Expiry.Time().Add(time.Second)); err == nil {
		t.Fatal("expired lease access token accepted")
	}
}

func TestLeaseAccessTokenSignedByDifferentAuthorityRejected(t *testing.T) {
	leaseIdentity, err := Generate("demo")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	otherIdentity, err := Generate("other")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	token, _, err := IssueLeaseAccessToken(NewLocalAuthority(otherIdentity), testTokenIssuer, leaseIdentity, testTokenLeaseID, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueLeaseAccessToken() error = %v", err)
	}

	if _, err := VerifyLeaseAccessToken(token, NewLocalAuthority(leaseIdentity).Identity().PublicKey, testTokenIssuer, time.Now().UTC()); err == nil {
		t.Fatal("lease access token signed by a different authority accepted")
	}
}
