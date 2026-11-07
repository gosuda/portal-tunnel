package policy

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestParseMode(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]Mode{"auto": ModeAuto, "manual": ModeManual, " manual ": ModeManual} {
		if got, err := ParseMode(raw); err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "  ", "Manual", "off"} {
		if got, err := ParseMode(raw); err == nil {
			t.Fatalf("ParseMode(%q) = %q, want an error", raw, got)
		}
	}
}

func TestAccessNamesTheDecision(t *testing.T) {
	t.Parallel()

	key := types.NewServiceIdentityKey("demo", "0x1234")
	access := NewAccess().Snapshot()
	if got := access.Access(key); got != types.LeaseRoutable {
		t.Fatalf("auto mode = %q", got)
	}
	access.SetMode(ModeManual)
	if got := access.Access(key); got != types.LeasePending {
		t.Fatalf("not approved = %q", got)
	}
	access.Approve(key)
	if got := access.Access(key); got != types.LeaseRoutable {
		t.Fatalf("approved = %q", got)
	}
	access.Revoke(key)
	if got := access.Access(key); got != types.LeasePending {
		t.Fatalf("revoked = %q", got)
	}
	access.Deny(key)
	if got := access.Access(key); got != types.LeaseDenied {
		t.Fatalf("denied = %q", got)
	}
	access.Approve(key)
	access.Ban(key)
	if got := access.Access(key); got != types.LeaseDenied {
		t.Fatalf("banned = %q", got)
	}
}

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	key := types.NewServiceIdentityKey("demo", "0x1234")
	access := NewAccess().Snapshot()
	access.SetMode(ModeManual)

	access.Approve(key)
	if !access.EffectiveApproval(key) || access.IsDenied(key) {
		t.Fatal("Approve() did not leave the identity exclusively approved")
	}

	access.Deny(key)
	if access.EffectiveApproval(key) || !access.IsDenied(key) {
		t.Fatal("Deny() did not leave the identity exclusively denied")
	}

	access.Approve(key)
	if !access.EffectiveApproval(key) || access.IsDenied(key) {
		t.Fatal("Approve() did not clear the prior denial")
	}
}

func TestAccessCommitsCompoundDecisionsAtomically(t *testing.T) {
	key := types.NewServiceIdentityKey("demo", "0x1234")
	access := NewAccess()
	initial := access.Snapshot()
	initial.Ban(key)
	access.Commit(initial)

	proposed := access.Snapshot()
	proposed.Unban(key)
	// A registration arriving between the two edits must still see the
	// committed ban, even though the proposed state temporarily permits it.
	observed := make(chan bool, 1)
	go func() { observed <- access.Snapshot().Access(key) == types.LeaseRoutable }()
	if <-observed {
		t.Fatal("uncommitted unban became routable")
	}
	proposed.Deny(key)
	access.Commit(proposed)
	committed := access.Snapshot()
	if committed.Revision() != 2 {
		t.Fatalf("committed revision = %d, want 2", committed.Revision())
	}
	if committed.IsBanned(key) || !committed.IsDenied(key) || committed.Access(key) == types.LeaseRoutable {
		t.Fatal("compound change did not atomically replace the ban with a denial")
	}
	proposed.Undeny(key)
	if access.Snapshot().Access(key) == types.LeaseRoutable {
		t.Fatal("editing the proposal after commit changed live access")
	}
}

func TestAccessSetDecisionsIgnoresInvalidZeroKeys(t *testing.T) {
	t.Parallel()

	validKey := types.NewServiceIdentityKey("demo", "0x1234")
	zeroKey := types.ServiceIdentityKey{}

	access := NewAccess().Snapshot()
	access.SetMode(ModeManual)
	access.SetDecisions([]types.ServiceIdentityKey{validKey, zeroKey}, []types.ServiceIdentityKey{zeroKey})

	if !access.EffectiveApproval(validKey) {
		t.Fatal("valid key not approved")
	}
	if access.EffectiveApproval(zeroKey) {
		t.Fatal("zero key was approved")
	}
	if len(access.ApprovedKeys()) != 1 || access.ApprovedKeys()[0] != validKey {
		t.Fatalf("approved keys = %v, want [%v]", access.ApprovedKeys(), validKey)
	}
	if len(access.DeniedKeys()) != 0 {
		t.Fatalf("denied keys = %v, want empty", access.DeniedKeys())
	}
}

func TestAccessUnnamedIdentityKeyDecisions(t *testing.T) {
	t.Parallel()

	unnamedKey := types.NewServiceIdentityKey("", "0x1234")
	namedKey := types.NewServiceIdentityKey("demo", "0x1234")

	access := NewAccess().Snapshot()
	access.SetMode(ModeManual)

	access.Approve(unnamedKey)
	if !access.EffectiveApproval(unnamedKey) || access.Access(unnamedKey) != types.LeaseRoutable {
		t.Fatal("unnamed key not approved")
	}
	// Named key under the same address is distinct and not automatically approved.
	if access.EffectiveApproval(namedKey) || access.Access(namedKey) == types.LeaseRoutable {
		t.Fatal("named key should be distinct from unnamed key")
	}

	access.Ban(unnamedKey)
	if !access.IsBanned(unnamedKey) || access.Access(unnamedKey) == types.LeaseRoutable {
		t.Fatal("unnamed key not banned")
	}
}
