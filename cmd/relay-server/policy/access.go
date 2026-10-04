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

func (s AccessState) Routable(key string) bool {
	if key == "" {
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

func (s AccessState) EffectiveApproval(key string) bool {
	if s.Mode() == ModeAuto {
		return true
	}
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return false
	}
	_, ok := s.approved[serviceKey]
	return ok
}

func (s *AccessState) Approve(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return
	}
	if s.approved == nil {
		s.approved = make(map[types.ServiceIdentityKey]struct{})
	}
	s.approved[serviceKey] = struct{}{}
	delete(s.denied, serviceKey)
}

func (s *AccessState) Revoke(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err == nil {
		delete(s.approved, serviceKey)
	}
}

func (s AccessState) ApprovedKeys() []string {
	out := make([]string, 0, len(s.approved))
	for key := range s.approved {
		out = append(out, key.String())
	}
	return out
}

func (s AccessState) IsDenied(key string) bool {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return false
	}
	_, ok := s.denied[serviceKey]
	return ok
}

func (s *AccessState) Deny(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return
	}
	if s.denied == nil {
		s.denied = make(map[types.ServiceIdentityKey]struct{})
	}
	s.denied[serviceKey] = struct{}{}
	delete(s.approved, serviceKey)
}

func (s *AccessState) Undeny(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err == nil {
		delete(s.denied, serviceKey)
	}
}

func (s AccessState) DeniedKeys() []string {
	out := make([]string, 0, len(s.denied))
	for key := range s.denied {
		out = append(out, key.String())
	}
	return out
}

// SetDecisions keeps denied keys from also counting as approved.
func (s *AccessState) SetDecisions(approvedKeys, deniedKeys []string) {
	s.approved = make(map[types.ServiceIdentityKey]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		if serviceKey, err := types.ParseServiceIdentityKey(key); err == nil {
			s.approved[serviceKey] = struct{}{}
		}
	}
	s.denied = make(map[types.ServiceIdentityKey]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		if serviceKey, err := types.ParseServiceIdentityKey(key); err == nil {
			delete(s.approved, serviceKey)
			s.denied[serviceKey] = struct{}{}
		}
	}
}

func (s AccessState) IsBanned(key string) bool {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return false
	}
	_, ok := s.banned[serviceKey]
	return ok
}

func (s *AccessState) Ban(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err != nil {
		return
	}
	if s.banned == nil {
		s.banned = make(map[types.ServiceIdentityKey]struct{})
	}
	s.banned[serviceKey] = struct{}{}
}

func (s *AccessState) Unban(key string) {
	serviceKey, err := types.ParseServiceIdentityKey(key)
	if err == nil {
		delete(s.banned, serviceKey)
	}
}

func (s AccessState) BannedKeys() []string {
	out := make([]string, 0, len(s.banned))
	for key := range s.banned {
		out = append(out, key.String())
	}
	return out
}

func (s *AccessState) SetBannedKeys(keys []string) {
	s.banned = make(map[types.ServiceIdentityKey]struct{}, len(keys))
	for _, key := range keys {
		s.Ban(key)
	}
}
