package relay

import "testing"

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	access := NewAccess()

	access.Approve(key)
	if !access.IsApproved(key) || access.IsDenied(key) {
		t.Fatal("Approve() did not leave the identity exclusively approved")
	}

	access.Deny(key)
	if access.IsApproved(key) || !access.IsDenied(key) {
		t.Fatal("Deny() did not leave the identity exclusively denied")
	}

	access.Approve(key)
	if !access.IsApproved(key) || access.IsDenied(key) {
		t.Fatal("Approve() did not clear the prior denial")
	}
}
