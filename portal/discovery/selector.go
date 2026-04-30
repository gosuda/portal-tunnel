package discovery

import "context"

// Selector is the pluggable per-client relay-selection seam introduced in
// Phase 2. Implementations are deterministic: an empty slice signals no
// candidates. The ctx parameter is reserved for future cancellation and
// tracing; current implementations may safely ignore it.
//
// No error is returned because selection is a pure ranking operation over
// an already-validated pool. Transport and validation errors are handled by
// the RelaySet layer before selection is invoked.
type Selector interface {
	Name() string
	SelectPriority(ctx context.Context, pool []RelayState, client ClientState) ([]string, SelectionTrace)
	SelectMultiHop(ctx context.Context, pool []RelayState, client ClientState) ([]string, SelectionTrace)
}
