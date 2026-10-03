package policy

import "testing"

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	access := NewAccess()
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
