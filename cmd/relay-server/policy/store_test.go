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
	access := NewStore().Snapshot()
	if got := access.Access(key); got != types.LeaseRoutable {
		t.Fatalf("auto mode = %q", got)
	}
	checkStoreAccessManualPending(t, &access, key)
	checkStoreAccessApproveCycle(t, &access, key)
	checkStoreAccessDenyBan(t, &access, key)
}

func checkStoreAccessManualPending(t *testing.T, access *State, key types.ServiceIdentityKey) {
	t.Helper()
	access.SetMode(ModeManual)
	if got := access.Access(key); got != types.LeasePending {
		t.Fatalf("not approved = %q", got)
	}
}

func checkStoreAccessApproveCycle(t *testing.T, access *State, key types.ServiceIdentityKey) {
	t.Helper()
	access.Approve(key)
	if got := access.Access(key); got != types.LeaseRoutable {
		t.Fatalf("approved = %q", got)
	}
	access.Revoke(key)
	if got := access.Access(key); got != types.LeasePending {
		t.Fatalf("revoked = %q", got)
	}
}

func checkStoreAccessDenyBan(t *testing.T, access *State, key types.ServiceIdentityKey) {
	t.Helper()
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
	access := NewStore().Snapshot()
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

func TestPolicyCommitsCompoundDecisionsAtomically(t *testing.T) {
	key := types.NewServiceIdentityKey("demo", "0x1234")
	access := NewStore()
	fixture := storeCompoundDecisionsFixture{access: access, key: key}
	commitStoreCompoundInitialBan(t, fixture)
	proposed := proposeStoreCompoundUnban(t, fixture)
	committed := commitStoreCompoundDenial(t, fixture, proposed)
	checkStoreCompoundCommitted(t, fixture, committed)
	checkStoreCompoundProposalIsolated(t, fixture, proposed)
}

type storeCompoundDecisionsFixture struct {
	access *Store
	key    types.ServiceIdentityKey
}

func commitStoreCompoundInitialBan(t *testing.T, fixture storeCompoundDecisionsFixture) {
	t.Helper()
	initial := fixture.access.Snapshot()
	initial.Ban(fixture.key)
	initial.UDP = types.PolicyPortSettings{Enabled: true, MaxLeases: 2}
	initial.TCPPort = types.PolicyPortSettings{Enabled: true, MaxLeases: 3}
	initial.IdentityBPS = map[types.ServiceIdentityKey]int64{fixture.key: 100}
	fixture.access.Commit(initial)
}

func proposeStoreCompoundUnban(t *testing.T, fixture storeCompoundDecisionsFixture) State {
	t.Helper()
	proposed := fixture.access.Snapshot()
	proposed.Unban(fixture.key)
	proposed.UDP.Enabled = false
	proposed.TCPPort.MaxLeases = 4
	proposed.IdentityBPS[fixture.key] = 200
	before := fixture.access.Snapshot()
	if !before.UDP.Enabled || before.TCPPort.MaxLeases != 3 || before.IdentityBPS[fixture.key] != 100 {
		t.Fatal("editing candidate transport or bandwidth settings changed committed policy")
	}
	observed := make(chan bool, 1)
	go func() { observed <- fixture.access.Snapshot().Access(fixture.key) == types.LeaseRoutable }()
	if <-observed {
		t.Fatal("uncommitted unban became routable")
	}
	return proposed
}

func commitStoreCompoundDenial(t *testing.T, fixture storeCompoundDecisionsFixture, proposed State) State {
	t.Helper()
	proposed.Deny(fixture.key)
	fixture.access.Commit(proposed)
	return fixture.access.Snapshot()
}

func checkStoreCompoundCommitted(t *testing.T, fixture storeCompoundDecisionsFixture, committed State) {
	t.Helper()
	if committed.Revision() != 2 {
		t.Fatalf("committed revision = %d, want 2", committed.Revision())
	}
	if committed.IsBanned(fixture.key) || !committed.IsDenied(fixture.key) || committed.Access(fixture.key) == types.LeaseRoutable {
		t.Fatal("compound change did not atomically replace the ban with a denial")
	}
	if committed.UDP.Enabled || committed.TCPPort.MaxLeases != 4 || committed.IdentityBPS[fixture.key] != 200 {
		t.Fatal("compound commit lost transport or bandwidth settings")
	}
}

func checkStoreCompoundProposalIsolated(t *testing.T, fixture storeCompoundDecisionsFixture, proposed State) {
	t.Helper()
	proposed.Undeny(fixture.key)
	proposed.IdentityBPS[fixture.key] = 300
	if fixture.access.Snapshot().Access(fixture.key) == types.LeaseRoutable {
		t.Fatal("editing the proposal after commit changed live access")
	}
	if fixture.access.Snapshot().IdentityBPS[fixture.key] != 200 {
		t.Fatal("editing the proposal after commit changed the live bandwidth limit")
	}
}

func TestAccessSetDecisionsIgnoresInvalidZeroKeys(t *testing.T) {
	t.Parallel()

	validKey := types.NewServiceIdentityKey("demo", "0x1234")
	zeroKey := types.ServiceIdentityKey{}

	access := NewStore().Snapshot()
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

	access := NewStore().Snapshot()
	access.SetMode(ModeManual)

	access.Approve(unnamedKey)
	if !access.EffectiveApproval(unnamedKey) || access.Access(unnamedKey) != types.LeaseRoutable {
		t.Fatal("unnamed key not approved")
	}
	if access.EffectiveApproval(namedKey) || access.Access(namedKey) == types.LeaseRoutable {
		t.Fatal("named key should be distinct from unnamed key")
	}

	access.Ban(unnamedKey)
	if !access.IsBanned(unnamedKey) || access.Access(unnamedKey) == types.LeaseRoutable {
		t.Fatal("unnamed key not banned")
	}
}
