package policy

import (
	"fmt"
	"maps"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeManual Mode = "manual"
)

// Filename is the relay policy state file name. The relay API persists
// PolicySettings under it in the relay state directory.
const Filename = "policy.json"

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
	approved map[string]struct{}
	denied   map[string]struct{}
	banned   map[string]struct{}
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
	_, ok := s.approved[key]
	return ok
}

func (s *AccessState) Approve(key string) {
	if s.approved == nil {
		s.approved = make(map[string]struct{})
	}
	s.approved[key] = struct{}{}
	delete(s.denied, key)
}

func (s *AccessState) Revoke(key string) {
	delete(s.approved, key)
}

func (s AccessState) ApprovedKeys() []string {
	out := make([]string, 0, len(s.approved))
	for key := range s.approved {
		out = append(out, key)
	}
	return out
}

func (s AccessState) IsDenied(key string) bool {
	_, ok := s.denied[key]
	return ok
}

func (s *AccessState) Deny(key string) {
	if s.denied == nil {
		s.denied = make(map[string]struct{})
	}
	s.denied[key] = struct{}{}
	delete(s.approved, key)
}

func (s *AccessState) Undeny(key string) {
	delete(s.denied, key)
}

func (s AccessState) DeniedKeys() []string {
	out := make([]string, 0, len(s.denied))
	for key := range s.denied {
		out = append(out, key)
	}
	return out
}

// SetDecisions keeps denied keys from also counting as approved.
func (s *AccessState) SetDecisions(approvedKeys, deniedKeys []string) {
	s.approved = make(map[string]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		if key != "" {
			s.approved[key] = struct{}{}
		}
	}
	s.denied = make(map[string]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		if key != "" {
			delete(s.approved, key)
			s.denied[key] = struct{}{}
		}
	}
}

func (s AccessState) IsBanned(key string) bool {
	_, ok := s.banned[key]
	return ok
}

func (s *AccessState) Ban(key string) {
	if key == "" {
		return
	}
	if s.banned == nil {
		s.banned = make(map[string]struct{})
	}
	s.banned[key] = struct{}{}
}

func (s *AccessState) Unban(key string) {
	delete(s.banned, key)
}

func (s AccessState) BannedKeys() []string {
	out := make([]string, 0, len(s.banned))
	for key := range s.banned {
		out = append(out, key)
	}
	return out
}

func (s *AccessState) SetBannedKeys(keys []string) {
	s.banned = make(map[string]struct{}, len(keys))
	for _, key := range keys {
		s.Ban(key)
	}
}
