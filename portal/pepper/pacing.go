package pepper

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

type EmitFunc func([]Cell)

type Pacer struct {
	batchWindow time.Duration
	jitter      time.Duration
	rand        *rand.Rand

	mu      sync.Mutex
	queue   []Cell
	flushAt time.Time
}

func NewPacer(batchWindow, jitter time.Duration, seed int64) (*Pacer, error) {
	switch {
	case batchWindow <= 0:
		return nil, errors.New("batch window must be greater than zero")
	case jitter < 0:
		return nil, errors.New("jitter cannot be negative")
	}
	return &Pacer{
		batchWindow: batchWindow,
		jitter:      jitter,
		rand:        rand.New(rand.NewSource(seed)),
	}, nil
}

func (p *Pacer) Submit(cell Cell) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.queue = append(p.queue, cell)
	if p.flushAt.IsZero() {
		p.flushAt = time.Now().Add(p.batchWindow + p.sampleJitterLocked())
	}
}

func (p *Pacer) Run(ctx context.Context, pollInterval time.Duration, emit EmitFunc) error {
	if pollInterval <= 0 {
		pollInterval = time.Millisecond
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.flush(emit)
			return ctx.Err()
		case <-ticker.C:
			p.flushReady(time.Now(), emit)
		}
	}
}

func (p *Pacer) flushReady(now time.Time, emit EmitFunc) {
	p.mu.Lock()
	if p.flushAt.IsZero() || now.Before(p.flushAt) || len(p.queue) == 0 {
		p.mu.Unlock()
		return
	}
	batch := append([]Cell(nil), p.queue...)
	p.queue = p.queue[:0]
	p.flushAt = time.Time{}
	p.mu.Unlock()

	emit(batch)
}

func (p *Pacer) flush(emit EmitFunc) {
	p.mu.Lock()
	if len(p.queue) == 0 {
		p.mu.Unlock()
		return
	}
	batch := append([]Cell(nil), p.queue...)
	p.queue = p.queue[:0]
	p.flushAt = time.Time{}
	p.mu.Unlock()

	emit(batch)
}

func (p *Pacer) sampleJitterLocked() time.Duration {
	if p.jitter == 0 {
		return 0
	}
	max := int64(p.jitter)*2 + 1
	offset := p.rand.Int63n(max) - int64(p.jitter)
	return time.Duration(offset)
}
