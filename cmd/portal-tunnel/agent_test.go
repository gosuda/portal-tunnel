package main

import "testing"

// A missing endpoint file means the agent is not running: stop --wait must
// treat it as already stopped, not as an error.
func TestWaitAgentStoppedAcceptsMissingEndpoint(t *testing.T) {
	if err := waitAgentStopped(t.Context(), t.TempDir()); err != nil {
		t.Fatalf("waitAgentStopped() error = %v, want nil for stopped agent", err)
	}
}
