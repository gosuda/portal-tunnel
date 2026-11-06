package e2e_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// One source gets a fixed budget of leases that do not route. The budget is
// about resources: an approved identity is never refused.
func TestUnapprovedLeaseLimit(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual", "--unapproved-leases-per-source", "2")
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	ask := func(leaseIdentity types.Identity) (types.RegisterChallengeResponse, error) {
		var challenge types.RegisterChallengeResponse
		err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge)
		return challenge, err
	}
	register := func(leaseIdentity types.Identity) error {
		t.Helper()
		challenge, err := ask(leaseIdentity)
		if err != nil {
			return err
		}
		signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
		if err != nil {
			t.Fatal(err)
		}
		request := types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}
		return utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, request, nil, new(types.RegisterResponse))
	}
	approve := func(leaseIdentity types.Identity) {
		t.Helper()
		isApproved := true
		update := types.LeasePolicyUpdate{IdentityKey: leaseIdentity.Key(), IsApproved: &isApproved}
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicyLeases, update, headers, new(struct{})); err != nil {
			t.Fatal(err)
		}
	}
	generate := func(name string) types.Identity {
		t.Helper()
		leaseIdentity, err := identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		return leaseIdentity
	}
	first, second, third, approved := generate("limit-first"), generate("limit-second"), generate("limit-third"), generate("limit-approved")

	if err := register(first); err != nil {
		t.Fatal(err)
	}
	if err := register(second); err != nil {
		t.Fatal(err)
	}
	// The refusal comes before a client holds anything, so an SDK waits on the
	// challenge step, and more refusals than the pending cap leave it open.
	for range 33 {
		_, refused := ask(third)
		apiErr, ok := errors.AsType[*types.APIRequestError](refused)
		if !ok || apiErr.StatusCode != http.StatusTooManyRequests || !apiErr.IsRateLimited() || apiErr.RetryAfter <= 0 {
			t.Fatalf("third unapproved lease = %#v", refused)
		}
	}
	if err := register(first); err != nil {
		t.Fatalf("a repeat registration counted against itself: %v", err)
	}

	approve(approved)
	if err := register(approved); err != nil {
		t.Fatalf("the budget refused an approved identity: %v", err)
	}

	approve(first)
	if err := register(third); err != nil {
		t.Fatalf("the refused identity did not pass once a slot freed: %v", err)
	}
}
