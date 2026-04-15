package policy

import (
	"sync"
	"time"
)

// RelayHealth describes the overlay health metrics tracked for each relay node.
type RelayHealth struct {
	PingLatencyMs float64
	RTTMs         float64
	Healthy       bool
	Fallback      bool
}

// NodeLoad is a coarse snapshot of the proxy's recent load and latency profile.
// AvgLatencyMs is an average of observed latency samples. When no samples are
// recorded it remains zero so congestion detection defaults to the magic grid.
type NodeLoad struct {
	AvgLatencyMs float64
	ActiveConns  int64
	BytesIn      int64
	BytesOut     int64
}

// LoadManager aggregates lightweight runtime load statistics that are used by
// the route policy to decide whether to switch to the congestion grid.
type LoadManager struct {
	mu             sync.RWMutex
	activeConns    int64
	bytesIn        int64
	bytesOut       int64
	latencySamples int64
	latencyTotalMs float64
}

// NewLoadManager constructs a ready-to-use LoadManager.
func NewLoadManager() *LoadManager {
	return &LoadManager{}
}

// RecordConnStart increments the number of active bridged connections.
func (m *LoadManager) RecordConnStart() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.activeConns++
	m.mu.Unlock()
}

// RecordConnEnd decrements the number of active connections.
func (m *LoadManager) RecordConnEnd() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.activeConns > 0 {
		m.activeConns--
	} else {
		m.activeConns = 0
	}
	m.mu.Unlock()
}

// RecordBytesIn accumulates inbound byte counts.
func (m *LoadManager) RecordBytesIn(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.bytesIn += n
	m.mu.Unlock()
}

// RecordBytesOut accumulates outbound byte counts.
func (m *LoadManager) RecordBytesOut(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.bytesOut += n
	m.mu.Unlock()
}

// RecordLatencySample feeds an observed RTT/latency sample into the moving
// average used for congestion decisions.
func (m *LoadManager) RecordLatencySample(d time.Duration) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	m.latencyTotalMs += float64(d) / float64(time.Millisecond)
	m.latencySamples++
	m.mu.Unlock()
}

// Snapshot returns the current aggregate load metrics.
func (m *LoadManager) Snapshot() NodeLoad {
	if m == nil {
		return NodeLoad{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var avgLatency float64
	if m.latencySamples > 0 {
		avgLatency = m.latencyTotalMs / float64(m.latencySamples)
	}

	return NodeLoad{
		AvgLatencyMs: avgLatency,
		ActiveConns:  m.activeConns,
		BytesIn:      m.bytesIn,
		BytesOut:     m.bytesOut,
	}
}
