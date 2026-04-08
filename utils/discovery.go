package utils

import (
	"fmt"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// ValidateMaxRouting ensures the configured MaxRouting is within the supported range.
func ValidateMaxRouting(attempts int) error {
	if attempts < types.MinDiscoveryRoutingAttempts || attempts > types.MaxDiscoveryRoutingAttempts {
		return fmt.Errorf("max routing attempts must be between %d and %d (got %d)",
			types.MinDiscoveryRoutingAttempts, types.MaxDiscoveryRoutingAttempts, attempts)
	}
	return nil
}
