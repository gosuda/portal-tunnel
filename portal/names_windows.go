package portal

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func (s *nameReservations) commit(temp string, next map[string]nameReservation) error {
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return fmt.Errorf("prepare name reservation source: %w", err)
	}
	to, err := windows.UTF16PtrFromString(s.path)
	if err != nil {
		return fmt.Errorf("prepare name reservation destination: %w", err)
	}
	// Windows cannot fsync a directory through os.File. Request write-through
	// replacement after the temporary file's contents have already been synced.
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace name reservations: %w", err)
	}
	s.entries = next
	return nil
}
