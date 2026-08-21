package x402

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SpentDigests records x402 settlement digests that have already granted
// access, so one on-chain payment cannot be replayed for another request.
// State is a process-local set plus an optional append-only journal that
// restores protection across restarts. A nil SpentDigests disables
// tracking, which keeps zero-value Payments usable.
type SpentDigests struct {
	mu      sync.Mutex
	spent   map[string]struct{}
	journal *os.File
}

// NewSpentDigests builds a spent-digest set. When path is non-empty the file
// is created if missing, previously consumed digests are restored, and new
// consumptions are appended. Journal failures degrade to in-memory tracking
// with a warning rather than disabling payments.
func NewSpentDigests(path string) *SpentDigests {
	spent := &SpentDigests{spent: make(map[string]struct{})}
	path = strings.TrimSpace(path)
	if path == "" {
		return spent
	}
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			spent.spent[spentKey(fields[0], fields[1])] = struct{}{}
		}
	} else if !os.IsNotExist(err) {
		log.Warn().Err(err).Str("path", path).Msg("read x402 spent-payment journal")
	}
	journal, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("open x402 spent-payment journal")
		return spent
	}
	spent.journal = journal
	return spent
}

// Consume atomically records that (network, digest) granted access and
// reports whether this is the first time that payment is used. Concurrent
// callers racing on the same payment get exactly one true.
func (s *SpentDigests) Consume(network, digest string) bool {
	if s == nil {
		return true
	}
	network = strings.TrimSpace(network)
	digest = strings.TrimSpace(digest)
	if network == "" || digest == "" {
		return true
	}
	key := spentKey(network, digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.spent[key]; ok {
		return false
	}
	s.spent[key] = struct{}{}
	if s.journal != nil {
		line := network + " " + digest + " " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"
		if _, err := s.journal.WriteString(line); err != nil {
			log.Warn().Err(err).Msg("append x402 spent-payment journal")
		}
	}
	return true
}

func spentKey(network, digest string) string {
	return network + "\x00" + digest
}
