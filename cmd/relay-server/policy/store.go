package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeManual Mode = "manual"
)

// ParseMode owns approval mode validation. An empty value is invalid, so a
// caller that allows a missing mode has to skip parsing on purpose.
func ParseMode(raw string) (Mode, error) {
	mode := Mode(strings.TrimSpace(raw))
	if mode != ModeAuto && mode != ModeManual {
		return "", fmt.Errorf("invalid approval mode: %q", raw)
	}
	return mode, nil
}

// Store owns committed relay operator policy. A transaction edits a detached
// Snapshot, persists it, then commits the complete state with a new revision.
type Store struct {
	state *utils.Snapshot[State]
}

// State is a detached operator policy. Editing it never changes the live
// relay policy; Commit installs the whole state once persistence has succeeded.
type State struct {
	revision    uint64
	mode        Mode
	approved    map[types.ServiceIdentityKey]struct{}
	denied      map[types.ServiceIdentityKey]struct{}
	banned      map[types.ServiceIdentityKey]struct{}
	UDP         types.PolicyPortSettings
	TCPPort     types.PolicyPortSettings
	IdentityBPS map[types.ServiceIdentityKey]int64
}

func (s State) snapshot() State {
	s.approved = maps.Clone(s.approved)
	s.denied = maps.Clone(s.denied)
	s.banned = maps.Clone(s.banned)
	s.IdentityBPS = maps.Clone(s.IdentityBPS)
	return s
}

func NewStore() *Store {
	return &Store{state: utils.NewSnapshot(State{}, State.snapshot)}
}

// Snapshot returns an independent copy for readers or a proposed transaction.
func (a *Store) Snapshot() State {
	if a == nil {
		return State{}
	}
	return a.state.Load()
}

// Commit installs a durably saved candidate as one immutable revision. The
// relay serializes transactions from Snapshot through persistence and Commit.
// Revisions belong to this running relay; both Store and Portal start fresh
// on restart, so policy.json needs no revision field or schema migration.
func (a *Store) Commit(next State) State {
	return a.state.Update(func(previous State) State {
		next.revision = previous.revision + 1
		return next
	})
}

func (s State) Revision() uint64 {
	return s.revision
}

func (s State) Access(key types.ServiceIdentityKey) types.LeaseAccess {
	switch {
	case !key.Valid():
		return types.LeaseRoutable
	case s.IsBanned(key) || s.IsDenied(key):
		return types.LeaseDenied
	case !s.EffectiveApproval(key):
		return types.LeasePending
	default:
		return types.LeaseRoutable
	}
}

func (s State) Mode() Mode {
	if s.mode == "" {
		return ModeAuto
	}
	return s.mode
}

func (s *State) SetMode(mode Mode) {
	s.mode = mode
}

func (s State) EffectiveApproval(key types.ServiceIdentityKey) bool {
	if s.Mode() == ModeAuto {
		return true
	}
	_, ok := s.approved[key]
	return ok
}

func (s *State) Approve(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.approved == nil {
		s.approved = make(map[types.ServiceIdentityKey]struct{})
	}
	s.approved[key] = struct{}{}
	delete(s.denied, key)
}

func (s *State) Revoke(key types.ServiceIdentityKey) {
	delete(s.approved, key)
}

func (s State) ApprovedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.approved))
	for key := range s.approved {
		out = append(out, key)
	}
	return out
}

func (s State) IsDenied(key types.ServiceIdentityKey) bool {
	_, ok := s.denied[key]
	return ok
}

func (s *State) Deny(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.denied == nil {
		s.denied = make(map[types.ServiceIdentityKey]struct{})
	}
	s.denied[key] = struct{}{}
	delete(s.approved, key)
}

func (s *State) Undeny(key types.ServiceIdentityKey) {
	delete(s.denied, key)
}

func (s State) DeniedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.denied))
	for key := range s.denied {
		out = append(out, key)
	}
	return out
}

// SetDecisions keeps denied keys from also counting as approved.
func (s *State) SetDecisions(approvedKeys, deniedKeys []types.ServiceIdentityKey) {
	s.approved = make(map[types.ServiceIdentityKey]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		if key.Valid() {
			s.approved[key] = struct{}{}
		}
	}
	s.denied = make(map[types.ServiceIdentityKey]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		if key.Valid() {
			delete(s.approved, key)
			s.denied[key] = struct{}{}
		}
	}
}

func (s State) IsBanned(key types.ServiceIdentityKey) bool {
	_, ok := s.banned[key]
	return ok
}

func (s *State) Ban(key types.ServiceIdentityKey) {
	if !key.Valid() {
		return
	}
	if s.banned == nil {
		s.banned = make(map[types.ServiceIdentityKey]struct{})
	}
	s.banned[key] = struct{}{}
}

func (s *State) Unban(key types.ServiceIdentityKey) {
	delete(s.banned, key)
}

func (s State) BannedKeys() []types.ServiceIdentityKey {
	out := make([]types.ServiceIdentityKey, 0, len(s.banned))
	for key := range s.banned {
		out = append(out, key)
	}
	return out
}

func (s *State) SetBannedKeys(keys []types.ServiceIdentityKey) {
	s.banned = make(map[types.ServiceIdentityKey]struct{}, len(keys))
	for _, key := range keys {
		s.Ban(key)
	}
}
