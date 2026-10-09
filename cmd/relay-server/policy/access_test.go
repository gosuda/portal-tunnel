package policy

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	key := types.NewServiceIdentityKey("demo", "0x1234")
	access := NewAccess().Snapshot()
	if err := access.SetMode(ModeManual); err != nil {
		t.Fatal(err)
	}

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
	go func() { observed <- access.Snapshot().Routable(key) }()
	if <-observed {
		t.Fatal("uncommitted unban became routable")
	}
	proposed.Deny(key)
	access.Commit(proposed)
	committed := access.Snapshot()
	if committed.Revision() != 2 {
		t.Fatalf("committed revision = %d, want 2", committed.Revision())
	}
	if committed.IsBanned(key) || !committed.IsDenied(key) || committed.Routable(key) {
		t.Fatal("compound change did not atomically replace the ban with a denial")
	}
	proposed.Undeny(key)
	if access.Snapshot().Routable(key) {
		t.Fatal("editing the proposal after commit changed live access")
	}
}

func TestAccessSetDecisionsIgnoresInvalidZeroKeys(t *testing.T) {
	t.Parallel()

	validKey := types.NewServiceIdentityKey("demo", "0x1234")
	zeroKey := types.ServiceIdentityKey{}

	access := NewAccess().Snapshot()
	if err := access.SetMode(ModeManual); err != nil {
		t.Fatal(err)
	}
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
	if err := access.SetMode(ModeManual); err != nil {
		t.Fatal(err)
	}

	access.Approve(unnamedKey)
	if !access.EffectiveApproval(unnamedKey) || !access.Routable(unnamedKey) {
		t.Fatal("unnamed key not approved")
	}
	// Named key under the same address is distinct and not automatically approved.
	if access.EffectiveApproval(namedKey) || access.Routable(namedKey) {
		t.Fatal("named key should be distinct from unnamed key")
	}

	access.Ban(unnamedKey)
	if !access.IsBanned(unnamedKey) || access.Routable(unnamedKey) {
		t.Fatal("unnamed key not banned")
	}
}
