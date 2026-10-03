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

// Access owns relay-local identity access decisions: the approval mode,
// approved and denied identities, and identity bans. It is the single writer
// of the routability results the relay pushes into the portal data path;
// portal code consumes pushed values and never reads this state.
type Access struct {
	state *utils.Snapshot[accessState]
}

type accessState struct {
	mode     Mode
	approved map[string]struct{}
	denied   map[string]struct{}
	banned   map[string]struct{}
}

func newAccessState() accessState {
	return accessState{
		mode:     ModeAuto,
		approved: make(map[string]struct{}),
		denied:   make(map[string]struct{}),
		banned:   make(map[string]struct{}),
	}
}

func (s accessState) snapshot() accessState {
	s.approved = maps.Clone(s.approved)
	s.denied = maps.Clone(s.denied)
	s.banned = maps.Clone(s.banned)
	return s
}

func NewAccess() *Access {
	return &Access{state: utils.NewSnapshot(newAccessState(), accessState.snapshot)}
}

func (a *Access) current() accessState {
	if a == nil || a.state == nil {
		return newAccessState()
	}
	return a.state.Load()
}

// Routable reports whether the relay routes the identity: not banned, not
// denied, and approved when the approval mode is manual. It is the only
// decision the portal data path consumes, as a value pushed by the relay.
func (a *Access) Routable(key string) bool {
	if key == "" {
		return true
	}
	state := a.current()
	if _, ok := state.banned[key]; ok {
		return false
	}
	if _, ok := state.denied[key]; ok {
		return false
	}
	if state.mode == ModeAuto {
		return true
	}
	_, ok := state.approved[key]
	return ok
}

func (a *Access) Mode() Mode {
	return a.current().mode
}

func (a *Access) SetMode(mode Mode) error {
	if mode != ModeAuto && mode != ModeManual {
		return fmt.Errorf("invalid approval mode: %q", mode)
	}
	if a == nil || a.state == nil {
		return nil
	}
	a.state.UpdateCopy(func(state *accessState) {
		state.mode = mode
	})
	return nil
}

// EffectiveApproval reports the approval that governs routing: automatic in
// auto mode, explicit otherwise.
func (a *Access) EffectiveApproval(key string) bool {
	state := a.current()
	if state.mode == ModeAuto {
		return true
	}
	_, ok := state.approved[key]
	return ok
}

func (a *Access) Approve(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		if state.approved == nil {
			state.approved = make(map[string]struct{})
		}
		state.approved[key] = struct{}{}
		delete(state.denied, key)
	})
}

func (a *Access) Revoke(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		delete(state.approved, key)
	})
}

func (a *Access) ApprovedKeys() []string {
	approved := a.current().approved
	out := make([]string, 0, len(approved))
	for key := range approved {
		out = append(out, key)
	}
	return out
}

func (a *Access) IsDenied(key string) bool {
	_, ok := a.current().denied[key]
	return ok
}

func (a *Access) Deny(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		if state.denied == nil {
			state.denied = make(map[string]struct{})
		}
		state.denied[key] = struct{}{}
		delete(state.approved, key)
	})
}

func (a *Access) Undeny(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		delete(state.denied, key)
	})
}

func (a *Access) DeniedKeys() []string {
	denied := a.current().denied
	out := make([]string, 0, len(denied))
	for key := range denied {
		out = append(out, key)
	}
	return out
}

// SetDecisions replaces the approval decisions wholesale, keeping a denied
// key from also counting as approved regardless of input order.
func (a *Access) SetDecisions(approvedKeys, deniedKeys []string) {
	if a == nil {
		return
	}

	approved := make(map[string]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		if key == "" {
			continue
		}
		approved[key] = struct{}{}
	}

	denied := make(map[string]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		if key == "" {
			continue
		}
		delete(approved, key)
		denied[key] = struct{}{}
	}

	if a.state == nil {
		return
	}
	a.state.Update(func(state accessState) accessState {
		state.approved = approved
		state.denied = denied
		return state
	})
}

func (a *Access) IsBanned(key string) bool {
	if key == "" {
		return false
	}
	_, ok := a.current().banned[key]
	return ok
}

func (a *Access) Ban(key string) {
	if a == nil || a.state == nil || key == "" {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		if state.banned == nil {
			state.banned = make(map[string]struct{})
		}
		state.banned[key] = struct{}{}
	})
}

func (a *Access) Unban(key string) {
	if a == nil || a.state == nil || key == "" {
		return
	}
	a.state.UpdateCopy(func(state *accessState) {
		delete(state.banned, key)
	})
}

func (a *Access) BannedKeys() []string {
	banned := a.current().banned
	out := make([]string, 0, len(banned))
	for key := range banned {
		out = append(out, key)
	}
	return out
}

// SetBannedKeys replaces the ban set wholesale.
func (a *Access) SetBannedKeys(keys []string) {
	if a == nil || a.state == nil {
		return
	}
	banned := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		banned[key] = struct{}{}
	}
	a.state.UpdateCopy(func(state *accessState) {
		state.banned = banned
	})
}
