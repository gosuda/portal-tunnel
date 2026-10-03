package policy

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeManual Mode = "manual"
)

// Access owns relay-local identity access decisions: the approval mode,
// approved and denied identities, and identity bans. It produces immutable,
// versioned routability values; portal code consumes those values and never
// reads this state.
type Access struct {
	state *utils.Snapshot[accessState]
}

type accessState struct {
	revision uint64
	mode     Mode
	approved map[string]struct{}
	denied   map[string]struct{}
	banned   map[string]struct{}
}

func newAccessState() accessState {
	return accessState{
		revision: 1,
		mode:     ModeAuto,
		approved: make(map[string]struct{}),
		denied:   make(map[string]struct{}),
		banned:   make(map[string]struct{}),
	}
}

// AccessDecision is the versioned value projected into Portal. Portal can
// reject an older decision without importing relay policy state.
type AccessDecision struct {
	Revision uint64
	Routable bool
}

// AccessConfig is a stable copy of the relay's canonical access settings.
type AccessConfig struct {
	Mode         Mode
	ApprovedKeys []string
	DeniedKeys   []string
	BannedKeys   []string
}

func routable(state accessState, key string) bool {
	if key == "" {
		return true
	}
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
	return routable(a.current(), key)
}

// Decision returns one identity's routability and the snapshot revision that
// produced it.
func (a *Access) Decision(key string) AccessDecision {
	state := a.current()
	return AccessDecision{Revision: state.revision, Routable: routable(state, key)}
}

// Decisions returns one coherent revision for the supplied identities and
// every identity named by access policy.
func (a *Access) Decisions(keys []string) (uint64, map[string]bool) {
	state := a.current()
	decisions := make(map[string]bool, len(keys)+len(state.approved)+len(state.denied)+len(state.banned))
	for _, key := range keys {
		if key != "" {
			decisions[key] = routable(state, key)
		}
	}
	for key := range state.approved {
		decisions[key] = routable(state, key)
	}
	for key := range state.denied {
		decisions[key] = routable(state, key)
	}
	for key := range state.banned {
		decisions[key] = routable(state, key)
	}
	return state.revision, decisions
}

// Config returns a coherent copy of the canonical access settings.
func (a *Access) Config() AccessConfig {
	state := a.current()
	config := AccessConfig{Mode: state.mode}
	for key := range state.approved {
		config.ApprovedKeys = append(config.ApprovedKeys, key)
	}
	for key := range state.denied {
		config.DeniedKeys = append(config.DeniedKeys, key)
	}
	for key := range state.banned {
		config.BannedKeys = append(config.BannedKeys, key)
	}
	slices.Sort(config.ApprovedKeys)
	slices.Sort(config.DeniedKeys)
	slices.Sort(config.BannedKeys)
	return config
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

func (a *Access) IsDenied(key string) bool {
	_, ok := a.current().denied[key]
	return ok
}

func (a *Access) IsBanned(key string) bool {
	if key == "" {
		return false
	}
	_, ok := a.current().banned[key]
	return ok
}

// Replace commits a complete access configuration as one immutable snapshot.
func (a *Access) Replace(mode Mode, approvedKeys, deniedKeys, bannedKeys []string) error {
	if mode != ModeAuto && mode != ModeManual {
		return fmt.Errorf("invalid approval mode: %q", mode)
	}
	if a == nil || a.state == nil {
		return nil
	}
	approved := make(map[string]struct{}, len(approvedKeys))
	for _, key := range approvedKeys {
		if key != "" {
			approved[key] = struct{}{}
		}
	}
	denied := make(map[string]struct{}, len(deniedKeys))
	for _, key := range deniedKeys {
		if key != "" {
			delete(approved, key)
			denied[key] = struct{}{}
		}
	}
	banned := make(map[string]struct{}, len(bannedKeys))
	for _, key := range bannedKeys {
		if key != "" {
			banned[key] = struct{}{}
		}
	}
	a.state.Update(func(current accessState) accessState {
		if current.mode == mode && maps.Equal(current.approved, approved) && maps.Equal(current.denied, denied) && maps.Equal(current.banned, banned) {
			return current
		}
		return accessState{
			revision: current.revision + 1,
			mode:     mode,
			approved: approved,
			denied:   denied,
			banned:   banned,
		}
	})
	return nil
}
