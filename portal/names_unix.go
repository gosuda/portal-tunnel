//go:build !windows

package portal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (s *nameReservations) commit(temp string, next map[string]nameReservation) error {
	if err := os.Rename(temp, s.path); err != nil {
		return fmt.Errorf("replace name reservations: %w", err)
	}
	// Rename has committed: retain the new owner even if directory sync fails.
	// Stop further publication on uncertain durability until the relay restarts.
	s.entries = next
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		s.writeErr = fmt.Errorf("open name reservation directory: %w", err)
		return s.writeErr
	}
	err = errors.Join(directory.Sync(), directory.Close())
	if err != nil {
		s.writeErr = fmt.Errorf("sync name reservation directory: %w", err)
	}
	if s.writeErr == nil {
		s.durable = next
	}
	return s.writeErr
}
