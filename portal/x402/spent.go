package x402

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SpentDigests records x402 settlement digests that have already granted
// access, so one on-chain payment cannot be replayed for another request.
// The store is security state scoped to a whole resource server: every paid
// route of one HTTP surface must share a single instance, because a
// settlement digest is globally single-use. State is a process-local set
// plus an optional append-only journal that restores protection across
// restarts. A nil SpentDigests performs no tracking for direct Consume
// callers; Payment.Settle rejects payments that have no store, so payments
// built through the constructors always enforce single-use settlements.
type SpentDigests struct {
	mu      sync.Mutex
	spent   map[string]struct{}
	journal *os.File
	// persistent records that a journal path was configured. Once set it
	// never clears: a closed or failed journal must fail consumption rather
	// than silently degrade to memory-only tracking.
	persistent bool
}

// NewSpentDigests builds a spent-digest set. When path is non-empty the file
// is created if missing, previously consumed digests are restored, and new
// consumptions are appended; failing to open or read an explicitly
// configured journal is an error so operators notice degraded persistence.
// An empty path keeps consumed digests in process memory only.
func NewSpentDigests(path string) (*SpentDigests, error) {
	spent := &SpentDigests{spent: make(map[string]struct{})}
	path = strings.TrimSpace(path)
	if path == "" {
		return spent, nil
	}
	spent.persistent = true
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			spent.spent[spentKey(fields[0], fields[1])] = struct{}{}
		}
	} else if !os.IsNotExist(err) {
		return nil, errors.Join(errors.New("read x402 spent-payment journal"), err)
	}
	journal, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, errors.Join(errors.New("open x402 spent-payment journal"), err)
	}
	spent.journal = journal
	return spent, nil
}

// Close releases the journal file, if any. A persistent store that is closed
// fails consumption rather than degrading to memory-only tracking.
func (s *SpentDigests) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil {
		return nil
	}
	err := s.journal.Close()
	s.journal = nil
	return err
}

// Consume atomically records that (network, digest) granted access and
// reports whether this is the first time that payment is used. Concurrent
// callers racing on the same payment get exactly one success. An empty
// network or digest never grants. When the store persists to a journal, a
// failed append returns an error and the caller must reject the request:
// granting without a durable record would reopen the replay window on
// restart.
func (s *SpentDigests) Consume(network, digest string) (bool, error) {
	if s == nil {
		return true, nil
	}
	network = strings.TrimSpace(network)
	digest = strings.TrimSpace(digest)
	if network == "" || digest == "" {
		return false, nil
	}
	key := spentKey(network, digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.spent[key]; ok {
		return false, nil
	}
	s.spent[key] = struct{}{}
	if s.persistent {
		if s.journal == nil {
			log.Error().Msg("x402 spent-payment journal is closed")
			return false, errors.New("x402 spent-payment journal is closed")
		}
		line := network + " " + digest + " " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"
		if _, err := s.journal.WriteString(line); err != nil {
			log.Error().Err(err).Msg("append x402 spent-payment journal")
			return false, errors.Join(errors.New("append x402 spent-payment journal"), err)
		}
	}
	return true, nil
}

func spentKey(network, digest string) string {
	return network + "\x00" + digest
}
