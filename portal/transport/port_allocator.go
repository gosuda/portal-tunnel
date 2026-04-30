package transport

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var ErrPortExhausted = errors.New("no ports available")

type portReservation struct {
	port      int
	expiresAt time.Time
}

// PortAllocator manages a pool of ports for dynamic per-lease allocation.
type PortAllocator struct {
	available []int
	inUse     map[int]string
	reserved  map[string]portReservation
	grace     time.Duration
	mu        sync.Mutex
}

func NewPortAllocator(min, max int, grace time.Duration) *PortAllocator {
	if min <= 0 || max <= 0 || min > max {
		return &PortAllocator{
			inUse:    make(map[int]string),
			reserved: make(map[string]portReservation),
			grace:    grace,
		}
	}

	available := make([]int, 0, max-min+1)
	for port := min; port <= max; port++ {
		available = append(available, port)
	}
	return &PortAllocator{
		available: available,
		inUse:     make(map[int]string),
		reserved:  make(map[string]portReservation),
		grace:     grace,
	}
}

func (a *PortAllocator) Allocate(name string) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.cleanupExpiredLocked(time.Now())

	if res, ok := a.reserved[name]; ok {
		delete(a.reserved, name)
		a.inUse[res.port] = name
		return res.port, nil
	}

	if len(a.available) == 0 {
		return 0, ErrPortExhausted
	}

	port := a.available[0]
	a.available = a.available[1:]
	a.inUse[port] = name
	return port, nil
}

func (a *PortAllocator) Release(port int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	name, ok := a.inUse[port]
	if !ok {
		return
	}
	delete(a.inUse, port)

	if prev, exists := a.reserved[name]; exists {
		a.sortedInsertLocked(prev.port)
	}

	a.reserved[name] = portReservation{
		port:      port,
		expiresAt: time.Now().Add(a.grace),
	}
	a.cleanupExpiredLocked(time.Now())
}

func (a *PortAllocator) cleanupExpiredLocked(now time.Time) {
	for name, res := range a.reserved {
		if now.After(res.expiresAt) {
			delete(a.reserved, name)
			a.sortedInsertLocked(res.port)
		}
	}
}

func (a *PortAllocator) sortedInsertLocked(port int) {
	i := sort.SearchInts(a.available, port)
	a.available = append(a.available, 0)
	copy(a.available[i+1:], a.available[i:])
	a.available[i] = port
}
