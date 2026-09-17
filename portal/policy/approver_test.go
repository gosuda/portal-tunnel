package policy

import "testing"

// TestApproverDecisionsAreMutuallyExclusive protects the security invariant that an
// identity key is either approved or denied at any point in time, never both: Approve
// clears a prior denial and Deny clears a prior approval.
func TestApproverDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	approver := NewApprover()

	approver.Approve(key)
	if !approver.IsApproved(key) || approver.IsDenied(key) {
		t.Fatal("Approve() did not leave the identity exclusively approved")
	}

	approver.Deny(key)
	if approver.IsApproved(key) || !approver.IsDenied(key) {
		t.Fatal("Deny() did not leave the identity exclusively denied")
	}

	approver.Approve(key)
	if !approver.IsApproved(key) || approver.IsDenied(key) {
		t.Fatal("Approve() did not clear the prior denial")
	}
}
