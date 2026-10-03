package policy

import "testing"

func TestAccessDecisionsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	access := NewAccess()
	if err := access.Replace(ModeManual, []string{key}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !access.EffectiveApproval(key) || access.IsDenied(key) {
		t.Fatal("approved identity was not exclusively approved")
	}

	if err := access.Replace(ModeManual, []string{key}, []string{key}, nil); err != nil {
		t.Fatal(err)
	}
	if access.EffectiveApproval(key) || !access.IsDenied(key) {
		t.Fatal("denied identity was not exclusively denied")
	}

	if err := access.Replace(ModeManual, []string{key}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !access.EffectiveApproval(key) || access.IsDenied(key) {
		t.Fatal("approved identity retained its prior denial")
	}
}

func TestAccessRevisionChangesOnlyWithCommittedState(t *testing.T) {
	t.Parallel()

	const key = "demo:0x1234"
	access := NewAccess()
	initial := access.Decision(key)
	if err := access.Replace(ModeManual, nil, []string{key}, nil); err != nil {
		t.Fatal(err)
	}
	denied := access.Decision(key)
	if denied.Revision <= initial.Revision || denied.Routable {
		t.Fatalf("denied decision = %+v, initial = %+v", denied, initial)
	}
	if err := access.Replace(ModeManual, nil, []string{key}, nil); err != nil {
		t.Fatal(err)
	}
	if unchanged := access.Decision(key); unchanged.Revision != denied.Revision {
		t.Fatalf("unchanged state advanced revision from %d to %d", denied.Revision, unchanged.Revision)
	}
}
