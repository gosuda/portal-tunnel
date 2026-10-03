package policy

import "testing"

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
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
	const key = "demo:0x1234"
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
