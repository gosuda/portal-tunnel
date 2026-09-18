package policy

import "testing"

func TestRuntimeIsIdentityRoutableComposition(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	runtime, err := NewRuntime(true, false, false, "")
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	// Auto mode approves every identity, so an undecided key is routable.
	if !runtime.IsIdentityRoutable(key) {
		t.Fatal("auto mode did not treat an undecided identity as routable")
	}

	// Manual mode gates effective approval on an explicit approver decision.
	if err := runtime.Approver().SetMode(ModeManual); err != nil {
		t.Fatalf("SetMode(manual) error = %v", err)
	}
	if runtime.EffectiveApproval(key) || runtime.IsIdentityRoutable(key) {
		t.Fatal("manual mode routed an identity without an explicit approval")
	}

	runtime.Approver().Approve(key)
	if !runtime.EffectiveApproval(key) || !runtime.IsIdentityRoutable(key) {
		t.Fatal("approved identity was not routable in manual mode")
	}

	// A denial suppresses routability.
	runtime.Approver().Deny(key)
	if !runtime.IsIdentityDenied(key) || runtime.IsIdentityRoutable(key) {
		t.Fatal("denied identity remained routable")
	}
	runtime.Approver().Undeny(key)
	runtime.Approver().Approve(key)
	if !runtime.IsIdentityRoutable(key) {
		t.Fatal("identity stayed unroutable after the denial was lifted")
	}

	// A ban suppresses routability of an approved identity; only an unban restores it.
	runtime.BanIdentity(key)
	if !runtime.IsIdentityBanned(key) || runtime.IsIdentityRoutable(key) {
		t.Fatal("banned identity remained routable")
	}
	runtime.UnbanIdentity(key)
	if runtime.IsIdentityBanned(key) || !runtime.IsIdentityRoutable(key) {
		t.Fatal("unban did not restore routability")
	}
}
