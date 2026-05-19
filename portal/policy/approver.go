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

type Approver struct {
	state *utils.Snapshot[approvalState]
}

type approvalState struct {
	approvedKeys map[string]struct{}
	deniedKeys   map[string]struct{}
	approvalMode Mode
}

func newApprovalState() approvalState {
	return approvalState{
		approvalMode: ModeAuto,
		approvedKeys: make(map[string]struct{}),
		deniedKeys:   make(map[string]struct{}),
	}
}

func (state approvalState) snapshot() approvalState {
	state.approvedKeys = maps.Clone(state.approvedKeys)
	state.deniedKeys = maps.Clone(state.deniedKeys)
	return state
}

func NewApprover() *Approver {
	return &Approver{
		state: utils.NewSnapshot(newApprovalState(), approvalState.snapshot),
	}
}

func (a *Approver) current() approvalState {
	if a == nil || a.state == nil {
		return newApprovalState()
	}
	return a.state.Load()
}

func (a *Approver) Mode() Mode {
	return a.current().approvalMode
}

func (a *Approver) SetMode(mode Mode) error {
	if mode != ModeAuto && mode != ModeManual {
		return fmt.Errorf("invalid approval mode: %q", mode)
	}
	if a == nil || a.state == nil {
		return nil
	}
	a.state.UpdateCopy(func(state *approvalState) {
		state.approvalMode = mode
	})
	return nil
}

func (a *Approver) IsApproved(key string) bool {
	_, ok := a.current().approvedKeys[key]
	return ok
}

func (a *Approver) Approve(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *approvalState) {
		if state.approvedKeys == nil {
			state.approvedKeys = make(map[string]struct{})
		}
		state.approvedKeys[key] = struct{}{}
		delete(state.deniedKeys, key)
	})
}

func (a *Approver) Revoke(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *approvalState) {
		delete(state.approvedKeys, key)
	})
}

func (a *Approver) ApprovedKeys() []string {
	approvedKeys := a.current().approvedKeys
	out := make([]string, 0, len(approvedKeys))
	for key := range approvedKeys {
		out = append(out, key)
	}
	return out
}

func (a *Approver) IsDenied(key string) bool {
	_, ok := a.current().deniedKeys[key]
	return ok
}

func (a *Approver) Deny(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *approvalState) {
		if state.deniedKeys == nil {
			state.deniedKeys = make(map[string]struct{})
		}
		state.deniedKeys[key] = struct{}{}
		delete(state.approvedKeys, key)
	})
}

func (a *Approver) Undeny(key string) {
	if a == nil || a.state == nil {
		return
	}
	a.state.UpdateCopy(func(state *approvalState) {
		delete(state.deniedKeys, key)
	})
}

func (a *Approver) DeniedKeys() []string {
	deniedKeys := a.current().deniedKeys
	out := make([]string, 0, len(deniedKeys))
	for key := range deniedKeys {
		out = append(out, key)
	}
	return out
}

func (a *Approver) SetDecisions(approvedKeys, deniedKeys []string) {
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
	a.state.Update(func(state approvalState) approvalState {
		state.approvedKeys = approved
		state.deniedKeys = denied
		return state
	})
}
