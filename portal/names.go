package portal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// DefaultNameReservationTTL protects an offline browser origin for seven days.
const DefaultNameReservationTTL = 7 * 24 * time.Hour

type nameReservation struct {
	Owner         string    `json:"owner_identity_key"`
	ReservedUntil time.Time `json:"reserved_until"`
}

// Name ownership is durable relay state, separate from transport leases. The
// registry lock serializes ownership decisions with lease publication.
type nameReservations struct {
	path     string
	ttl      time.Duration
	entries  map[string]nameReservation
	durable  map[string]nameReservation
	writeErr error
}

// Hash the effective public namespace, including loopback normalization. Domain
// changes preserve the old namespace so switching back restores its ownership.
func nameReservationsPath(dir, root string) string {
	hostname, _ := utils.LeaseHostname("namespace", root)
	return filepath.Join(dir, fmt.Sprintf("name-reservations-%x.json", sha256.Sum256([]byte(hostname))))
}

func loadNameReservations(path, root string, ttl time.Duration) (*nameReservations, error) {
	store := &nameReservations{
		path: path, ttl: ttl,
		entries: make(map[string]nameReservation),
	}
	store.durable = store.entries
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read name reservations: %w", err)
	}
	if err := json.Unmarshal(data, &store.entries); err != nil {
		return nil, fmt.Errorf("decode name reservations: %w", err)
	}
	if store.entries == nil {
		return nil, errors.New("name reservations must be a JSON object")
	}
	for hostname, entry := range store.entries {
		key, err := types.ParseIdentityKey(entry.Owner)
		if err != nil {
			return nil, fmt.Errorf("invalid name reservation owner: %w", err)
		}
		name, _, _ := strings.Cut(key, types.IdentityKeySeparator)
		want, err := utils.LeaseHostname(name, root)
		valid := err == nil && hostname == want && key == entry.Owner
		if !valid || entry.ReservedUntil.IsZero() {
			return nil, fmt.Errorf("invalid name reservation for %q", hostname)
		}
	}
	store.durable = store.entries
	return store, nil
}

// Reserve persists before making a route visible or extending its lease. The
// deadline includes the granted lease lifetime so a long lease never outlives
// its reservation; an explicit unregister retains that conservative deadline.
func (s *nameReservations) Reserve(record *leaseRecord, expiresAt, now time.Time) (err error) {
	if s == nil {
		return nil
	}
	defer func() {
		if err != nil && !errors.Is(err, errHostnameConflict) {
			log.Error().Err(err).Msg("persist public name reservation")
			err = &apiError{
				code:   types.APIErrorCodeInternal,
				msg:    "name reservation storage unavailable",
				status: http.StatusInternalServerError,
			}
		}
	}()
	owner := record.Key()
	entry, exists := s.entries[record.Hostname]
	if exists && entry.Owner != owner && now.Before(entry.ReservedUntil) {
		return errHostnameConflict
	}
	until := expiresAt.Add(s.ttl)
	// Only a confirmed durable entry may authorize publication without a write.
	// A failed post-rename sync may protect a new owner in entries, but must
	// never be mistaken for acknowledged durable ownership.
	confirmed := s.durable[record.Hostname]
	if confirmed.Owner == owner && !until.After(confirmed.ReservedUntil) {
		return nil
	}
	if s.writeErr != nil {
		return s.writeErr
	}
	// Reserve a bounded refresh margin to amortize full-file fsyncs while
	// always retaining at least ttl beyond every acknowledged lease expiry.
	until = until.Add(min(s.ttl/8, time.Hour))
	next := make(map[string]nameReservation, len(s.entries)+1)
	for hostname, reserved := range s.entries {
		if now.Before(reserved.ReservedUntil) {
			next[hostname] = reserved
		}
	}
	next[record.Hostname] = nameReservation{Owner: owner, ReservedUntil: until}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode name reservations: %w", err)
	}
	// The common atomic-file helper does not sync data or the directory. Name
	// ownership must survive a crash before registration is acknowledged.
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".name-reservations-*")
	if err != nil {
		return fmt.Errorf("prepare name reservations: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write name reservations: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync name reservations: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close name reservations: %w", err)
	}
	return s.commit(tmp.Name(), next)
}
