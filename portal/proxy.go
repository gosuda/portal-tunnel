package portal

import (
	"errors"
	"io"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type proxy struct {
	activeConns  atomic.Int64
	tcpBytes     atomic.Int64
	tcpLoadMu    sync.Mutex
	tcpLoadAt    time.Time
	tcpLoadBytes int64
}

func (p *proxy) bridge(left, right net.Conn, identityKey types.ServiceIdentityKey, bpsManager *BPSManager) {
	p.activeConns.Add(1)
	defer p.activeConns.Add(-1)

	defer left.Close()
	defer right.Close()

	var group errgroup.Group
	group.Go(func() error {
		err := p.copy(right, left, identityKey, bpsManager)
		closeWrite(right)
		return err
	})
	group.Go(func() error {
		err := p.copy(left, right, identityKey, bpsManager)
		closeWrite(left)
		return err
	})
	_ = group.Wait()
}

func (p *proxy) activeConnectionCount() int64 {
	return p.activeConns.Load()
}

func (p *proxy) currentTCPBPS(now time.Time) float64 {
	totalTCPBytes := p.tcpBytes.Load()

	p.tcpLoadMu.Lock()
	defer p.tcpLoadMu.Unlock()

	if p.tcpLoadAt.IsZero() {
		p.tcpLoadAt = now
		p.tcpLoadBytes = totalTCPBytes
		return 0
	}

	if elapsed := now.Sub(p.tcpLoadAt); elapsed > 0 {
		tcpTrafficBPS := float64(totalTCPBytes-p.tcpLoadBytes) / elapsed.Seconds()
		p.tcpLoadAt = now
		p.tcpLoadBytes = totalTCPBytes
		return tcpTrafficBPS
	}

	return 0
}

// copy streams src into dst, re-reading the identity's BPS limit on every
// chunk so runtime limit changes apply to connections already open: a limit
// set mid-stream starts pacing from the next chunk, and removing it releases
// the connection at full speed. ThrottleIdentityBPS returns the full length
// without sleeping when no limit is set, so one loop serves both modes.
func (p *proxy) copy(dst, src net.Conn, identityKey types.ServiceIdentityKey, bpsManager *BPSManager) error {
	buf := make([]byte, 32*1024)
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			data := buf[:nr]
			for len(data) > 0 {
				chunkSize := bpsManager.ThrottleIdentityBPS(identityKey, len(data))

				n, err := dst.Write(data[:chunkSize])
				if n > 0 {
					p.tcpBytes.Add(int64(n))
					data = data[n:]
				}
				if err != nil {
					return err
				}
				if n == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

type BPSManager struct {
	identityBPS      *utils.Snapshot[map[types.ServiceIdentityKey]int64]
	identityLimiters map[types.ServiceIdentityKey]*bpsLimiter
	mu               sync.RWMutex
}

func NewBPSManager() *BPSManager {
	return &BPSManager{
		identityBPS:      utils.NewSnapshot(map[types.ServiceIdentityKey]int64{}, maps.Clone[map[types.ServiceIdentityKey]int64]),
		identityLimiters: make(map[types.ServiceIdentityKey]*bpsLimiter),
	}
}

func (m *BPSManager) IdentityBPS(key types.ServiceIdentityKey) int64 {
	if m == nil || !key.Valid() {
		return 0
	}
	if m.identityBPS == nil {
		return 0
	}
	return m.identityBPS.Load()[key]
}

func (m *BPSManager) SetIdentityBPS(key types.ServiceIdentityKey, bps int64) {
	if m == nil || !key.Valid() {
		return
	}

	if m.identityBPS == nil {
		return
	}
	if bps <= 0 {
		m.identityBPS.UpdateCopy(func(limits *map[types.ServiceIdentityKey]int64) {
			delete(*limits, key)
		})
		m.mu.Lock()
		delete(m.identityLimiters, key)
		m.mu.Unlock()
		return
	}
	m.identityBPS.UpdateCopy(func(limits *map[types.ServiceIdentityKey]int64) {
		if *limits == nil {
			*limits = make(map[types.ServiceIdentityKey]int64)
		}
		(*limits)[key] = bps
	})
}

func (m *BPSManager) DeleteIdentityBPS(key types.ServiceIdentityKey) {
	if m == nil || !key.Valid() {
		return
	}

	if m.identityBPS != nil {
		m.identityBPS.UpdateCopy(func(limits *map[types.ServiceIdentityKey]int64) {
			delete(*limits, key)
		})
	}
	m.mu.Lock()
	delete(m.identityLimiters, key)
	m.mu.Unlock()
}

// ResetIdentityLimiter forgets ephemeral token state while preserving the
// operator-configured limit for the stable identity.
func (m *BPSManager) ResetIdentityLimiter(key types.ServiceIdentityKey) {
	if m == nil || !key.Valid() {
		return
	}
	m.mu.Lock()
	delete(m.identityLimiters, key)
	m.mu.Unlock()
}

func (m *BPSManager) IdentityBPSLimits() map[string]int64 {
	if m == nil {
		return nil
	}

	if m.identityBPS == nil {
		return nil
	}
	limits := m.identityBPS.Load()
	out := make(map[string]int64, len(limits))
	for key, bps := range limits {
		out[key.String()] = bps
	}
	return out
}

func (m *BPSManager) SetIdentityBPSLimits(limits map[string]int64) {
	if m == nil {
		return
	}

	next := make(map[types.ServiceIdentityKey]int64, len(limits))
	for key, bps := range limits {
		serviceKey, err := types.ParseServiceIdentityKey(key)
		if err != nil || bps <= 0 {
			continue
		}
		next[serviceKey] = bps
	}
	m.SetServiceIdentityBPSLimits(next)
}

func (m *BPSManager) SetServiceIdentityBPSLimits(next map[types.ServiceIdentityKey]int64) {
	if m == nil {
		return
	}
	limits := make(map[types.ServiceIdentityKey]int64, len(next))
	for key, bps := range next {
		if key.Valid() && bps > 0 {
			limits[key] = bps
		}
	}
	if m.identityBPS != nil {
		m.identityBPS.Store(limits)
	}
	m.mu.Lock()
	m.identityLimiters = make(map[types.ServiceIdentityKey]*bpsLimiter)
	m.mu.Unlock()
}

func (m *BPSManager) ThrottleIdentityBPS(key types.ServiceIdentityKey, maxBytes int) int {
	if m == nil || !key.Valid() || maxBytes <= 0 {
		return maxBytes
	}

	for {
		bps, limiter := m.identityLimiter(key)
		if bps <= 0 || limiter == nil {
			return maxBytes
		}
		chunkSize := bpsChunkSize(maxBytes, bps)
		if wait := limiter.reserve(float64(chunkSize), float64(bps)); wait > 0 {
			time.Sleep(wait)
			continue
		}
		return chunkSize
	}
}

func (m *BPSManager) identityLimiter(key types.ServiceIdentityKey) (int64, *bpsLimiter) {
	bps := m.IdentityBPS(key)
	if bps <= 0 {
		return 0, nil
	}

	m.mu.RLock()
	limiter := m.identityLimiters[key]
	m.mu.RUnlock()
	if limiter != nil {
		return bps, limiter
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bps = m.IdentityBPS(key)
	if bps <= 0 {
		return 0, nil
	}
	if m.identityLimiters == nil {
		m.identityLimiters = make(map[types.ServiceIdentityKey]*bpsLimiter)
	}
	limiter = m.identityLimiters[key]
	if limiter == nil {
		limiter = &bpsLimiter{}
		m.identityLimiters[key] = limiter
	}
	return bps, limiter
}

func bpsChunkSize(length int, bps int64) int {
	if bps <= 0 {
		return length
	}
	chunk := max(bps/10, 1)
	if chunk > int64(length) {
		chunk = int64(length)
	}
	return int(chunk)
}

type bpsLimiter struct {
	mu        sync.Mutex
	tokens    float64
	updatedAt time.Time
}

func (l *bpsLimiter) reserve(bytes, bps float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if l.updatedAt.IsZero() {
		l.updatedAt = now
	} else if elapsed := now.Sub(l.updatedAt).Seconds(); elapsed > 0 {
		l.tokens += elapsed * bps
		l.updatedAt = now
	}
	if l.tokens > bps {
		l.tokens = bps
	}

	if l.tokens >= bytes {
		l.tokens -= bytes
		return 0
	}

	missing := bytes - l.tokens
	// Waiting must retain accrued credit; otherwise an early retry discards
	// progress and can keep an open connection throttled indefinitely.
	l.updatedAt = now
	return time.Duration(missing / bps * float64(time.Second))
}
