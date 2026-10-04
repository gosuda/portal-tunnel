package policy

import (
	"fmt"
	"maps"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeManual Mode = "manual"
)

// Access owns committed relay access decisions. A transaction edits a detached
// Snapshot, persists it, then commits the complete state with a new revision.
type Access struct {
	state *utils.Snapshot[AccessState]
}

// AccessState is a detached set of decisions. Editing it never changes the live
// relay policy; Commit installs the whole state once persistence has succeeded.
type AccessState struct {
	revision uint64
	mode     Mode
	approved map[types.ServiceIdentityKey]struct{}
	denied   map[types.ServiceIdentityKey]struct{}
	banned   map[types.ServiceIdentityKey]struct{}
}

func (s AccessState) snapshot() AccessState {
	s.approved = maps.Clone(s.approved)
	s.denied = maps.Clone(s.denied)
	s.banned = maps.Clone(s.banned)
	return s
}

func NewAccess() *Access {
	return &Access{state: utils.NewSnapshot(AccessState{}, AccessState.snapshot)}
}

// Snapshot returns an independent copy for readers or a proposed transaction.
func (a *Access) Snapshot() AccessState {
	if a == nil {
		return AccessState{}
	}
	return a.state.Load()
}

// Commit installs a durably saved candidate as one immutable revision. The
// relay serializes transactions from Snapshot through persistence and Commit.
// Revisions belong to this running relay; both Access and Portal start fresh
// on restart, so policy.json needs no revision field or schema migration.
func (a *Access) Commit(next AccessState) AccessState {
	return a.state.Update(func(previous AccessState) AccessState {
		next.revision = previous.revision + 1
		return next
	})
}

func (s AccessState) Revision() uint64 {
	return s.revision
}

func (s AccessState) Routable(key types.ServiceIdentityKey) bool {
	if !key.Valid() {
		return true
	}
	return !s.IsBanned(key) && !s.IsDenied(key) && s.EffectiveApproval(key)
}

func (s AccessState) Mode() Mode {
	if s.mode == "" {
		return ModeAuto
	}
	return s.mode
}

func (s *AccessState) SetMode(mode Mode) error {
	if mode != ModeAuto && mode != ModeManual {
		return fmt.Errorf("invalid approval mode: %q", mode)
	}
	s.mode = mode
	return nil
}

func (s AccessState) EffectiveApproval(key types.ServiceIdentityKey) bool {
	if s.Mode() == ModeAuto {
		return true
	}
	_, ok := s.approved[key]
	return ok
}

func (s *AccessState) Approve(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.approved == nil {
		s.approved = make(map[types.ServiceIdentityKey]struct{})
	}
	s.approved[key] = struct{}{}
	delete(s.denied, key)
}

func (s *AccessState) Revoke(key types.ServiceIdentityKey) {
	delete(s.approved, key)
}

func (s AccessState) ApprovedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.approved))
	for key := range s.approved {
		out = append(out, key)
	}
	return out
}

func (s AccessState) IsDenied(key types.ServiceIdentityKey) bool {
	_, ok := s.denied[key]
	return ok
}

func (s *AccessState) Deny(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.denied == nil {
		s.denied = make(map[types.ServiceIdentityKey]struct{})
	}
	s.denied[key] = struct{}{}
	delete(s.approved, key)
}

func (s *AccessState) Undeny(key types.ServiceIdentityKey) {
	delete(s.denied, key)
}

func (s AccessState) DeniedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.denied))
	for key := range s.denied {
		out = append(out, key)
	}
	return out
}

// SetDecisions keeps denied keys from also counting as approved.
func (s *AccessState) SetDecisions(approvedKeys, deniedKeys []types.ServiceIdentityKey) {
	s.approved = make(map[types.ServiceIdentityKey]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		s.approved[key] = struct{}{}
	}
	s.denied = make(map[types.ServiceIdentityKey]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		delete(s.approved, key)
		s.denied[key] = struct{}{}
	}
}

func (s AccessState) IsBanned(key types.ServiceIdentityKey) bool {
	_, ok := s.banned[key]
	return ok
}

func (s *AccessState) Ban(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.banned == nil {
		s.banned = make(map[types.ServiceIdentityKey]struct{})
	}
	s.banned[key] = struct{}{}
}

func (s *AccessState) Unban(key types.ServiceIdentityKey) {
	delete(s.banned, key)
}

func (s AccessState) BannedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.banned))
	for key := range s.banned {
		out = append(out, key)
	}
	return out
}

func (s *AccessState) SetBannedKeys(keys []types.ServiceIdentityKey) {
	s.banned = make(map[types.ServiceIdentityKey]struct{}, len(keys))
	for _, key := range keys {
		s.Ban(key)
	}
}
