package policy

import (
	"sync"
	"sync/atomic"
	"time"
)

// LoadManager tracks active connection counts and byte-transfer totals
// for OLS load accounting. All counters are updated via atomic operations
// so callers may increment/decrement from concurrent goroutines without
// additional locking.
type LoadManager struct {
	activeConns int64
	bytesIn     int64
	bytesOut    int64
	connCount   int64

	mu        sync.Mutex
	lastCheck time.Time
	rate      float64
}

// NewLoadManager returns a ready-to-use LoadManager.
func NewLoadManager() *LoadManager {
	return &LoadManager{lastCheck: time.Now()}
}

// ActiveConns returns the current number of active connections.
func (m *LoadManager) ActiveConns() int64 {
	return atomic.LoadInt64(&m.activeConns)
}

// RecordConnStart increments the active-connection and total-connection counters.
func (m *LoadManager) RecordConnStart() {
	atomic.AddInt64(&m.activeConns, 1)
	atomic.AddInt64(&m.connCount, 1)
}

// RecordConnEnd decrements the active-connection counter.
func (m *LoadManager) RecordConnEnd() {
	atomic.AddInt64(&m.activeConns, -1)
}

// RecordBytesIn adds n to the inbound byte counter.
func (m *LoadManager) RecordBytesIn(n int64) {
	atomic.AddInt64(&m.bytesIn, n)
}

// RecordBytesOut adds n to the outbound byte counter.
func (m *LoadManager) RecordBytesOut(n int64) {
	atomic.AddInt64(&m.bytesOut, n)
}

// Snapshot returns a NodeLoad with the current metric values.
// The connection rate is recomputed at most once every five seconds.
func (m *LoadManager) Snapshot() NodeLoad {
	m.mu.Lock()
	now := time.Now()
	if diff := now.Sub(m.lastCheck).Seconds(); diff >= 5.0 {
		count := atomic.SwapInt64(&m.connCount, 0)
		m.rate = float64(count) / diff
		m.lastCheck = now
	}
	rate := m.rate
	m.mu.Unlock()

	return NodeLoad{
		ActiveConns: atomic.LoadInt64(&m.activeConns),
		BytesIn:     atomic.LoadInt64(&m.bytesIn),
		BytesOut:    atomic.LoadInt64(&m.bytesOut),
		ConnRate:    rate,
	}
}
