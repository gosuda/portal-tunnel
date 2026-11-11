package portal

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (r *leaseRegistry) sweepRegisterChallengeLocked(now time.Time, sourceAddr netip.Addr) (int, int) {
	pending := 0
	globalPending := 0
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record == nil || record.registerChallenge == nil {
			i++
			continue
		}
		if record.isExpired(now) {
			r.deleteRecord(i)
			continue
		}
		globalPending++
		if record.sourceAddr == sourceAddr {
			pending++
		}
		i++
	}
	return pending, globalPending
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string, sourceAddr netip.Addr) (types.RegisterChallengeResponse, error) {
	if r == nil {
		return types.RegisterChallengeResponse{}, errFeatureUnavailable
	}
	if _, err := requestedLeaseTTL(req.TTL); err != nil {
		return types.RegisterChallengeResponse{}, err
	}

	now := time.Now().UTC()
	challenge, err := identity.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	if _, err := utils.CanonicalLeaseHostname(challenge.Request.Identity.Name, challenge.Request.Identity.Address, r.rootHostname); err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	pending, globalPending := r.sweepRegisterChallengeLocked(now, sourceAddr)
	if pending >= defaultRegisterChallengeOutstandingPerIP || globalPending >= defaultRegisterChallengeOutstanding {
		return types.RegisterChallengeResponse{}, errRegisterChallengePending
	}
	r.records = append(r.records, &leaseRecord{
		ExpiresAt:         challenge.ExpiresAt,
		sourceAddr:        sourceAddr,
		registerChallenge: challenge,
	})

	return types.RegisterChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (r *leaseRegistry) consumeVerifiedRegisterChallenge(req types.RegisterRequest) (*identity.RegisterChallenge, netip.Addr, error) {
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return nil, netip.Addr{}, identity.ErrRegisterChallengeNotFound
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, record := range r.records {
		if record == nil || record.registerChallenge == nil || record.registerChallenge.ChallengeID != challengeID {
			continue
		}
		challenge, source := record.registerChallenge, record.sourceAddr
		if challenge.Expired(now) {
			r.deleteRecord(i)
			return nil, netip.Addr{}, identity.ErrRegisterChallengeExpired
		}
		if err := challenge.Verify(req, now); err != nil {
			return nil, netip.Addr{}, err
		}

		r.deleteRecord(i)
		return challenge, source, nil
	}
	return nil, netip.Addr{}, identity.ErrRegisterChallengeNotFound
}

func (r *leaseRegistry) verifySigningAccessTokenLease(req *http.Request) (string, bool) {
	now := time.Now().UTC()
	claims, err := identity.VerifyLeaseAccessToken(req.Header.Get(types.HeaderAccessToken), r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return "", false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record, err := r.recordForVerifiedLeaseLocked(claims.Identity.ServiceKey(), claims.LeaseID, now)
	if err != nil {
		return "", false
	}
	if !record.isPublicEntry() {
		return "", false
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return "", false
	}
	return claims.LeaseID, true
}
