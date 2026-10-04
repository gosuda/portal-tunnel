package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var errPoolFull = errors.New("reverse ready queue full")

// ReversePool owns idle connections until Acquire transfers them to a caller.
// Idle keepalives detect disconnected peers; activation framing and carriers
// belong to the caller.
type ReversePool struct {
	mu           sync.Mutex
	cond         *sync.Cond
	notify       chan struct{}
	ready        []*pooledConn
	idleInterval time.Duration
	readyLimit   int
	reserved     int
	closing      bool
	closeOnce    sync.Once
}

// pooledConn coordinates the idle writer with acquisition and shutdown. It
// never escapes the pool: acquired connections retain their original net.Conn.
type pooledConn struct {
	net.Conn
	stop chan struct{}
	done chan struct{}
	err  error // published by closing done
}

// offerReservation protects the acknowledgement/commit boundary for overlay
// admission. The caller owns conn until Commit and must Commit or Cancel.
type offerReservation struct {
	pool     *ReversePool
	conn     net.Conn
	finished bool // protected by pool.mu
}

func NewReversePool(idleInterval time.Duration, readyLimit int) *ReversePool {
	p := &ReversePool{idleInterval: idleInterval, readyLimit: readyLimit, notify: make(chan struct{})}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Offer transfers conn to the pool, closing it if admission fails.
func (p *ReversePool) Offer(conn net.Conn) error {
	r, err := p.ReserveOffer(conn)
	if err == nil {
		err = r.Commit()
	}
	if err != nil && conn != nil {
		_ = conn.Close()
	}
	return err
}

// ReserveOffer reserves capacity before the caller acknowledges a remote
// offer. Rejection leaves conn with the caller so it can send a refusal.
// Close waits for outstanding reservations; no new offers enter after it begins.
func (p *ReversePool) ReserveOffer(conn net.Conn) (*offerReservation, error) {
	if conn == nil {
		return nil, errors.New("reverse connection is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return nil, net.ErrClosed
	}
	if p.readyLimit > 0 && len(p.ready)+p.reserved >= p.readyLimit {
		return nil, errPoolFull
	}
	p.reserved++
	return &offerReservation{pool: p, conn: conn}, nil
}

func (r *offerReservation) Commit() error {
	p := r.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.finished {
		return net.ErrClosed
	}
	r.finished = true
	p.reserved--
	c := &pooledConn{Conn: r.conn, stop: make(chan struct{}), done: make(chan struct{})}
	p.ready = append(p.ready, c)
	go p.keepIdle(c)
	p.signalLocked()
	p.cond.Broadcast()
	return nil
}

func (r *offerReservation) Cancel() {
	p := r.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if !r.finished {
		r.finished = true
		p.reserved--
		p.cond.Broadcast()
	}
}

// Acquire stops idle writes before transferring a connection to its caller.
// It does not write a raw/TLS start frame or retain the acquired connection.
func (p *ReversePool) Acquire(ctx context.Context) (net.Conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if len(p.ready) > 0 {
			c := p.ready[0]
			p.ready[0] = nil
			p.ready = p.ready[1:]
			close(c.stop)
			p.mu.Unlock()
			select {
			case <-c.done:
			case <-ctx.Done():
				_ = c.Close()
				<-c.done
				return nil, ctx.Err()
			}
			if c.err != nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				_ = c.Close()
				return nil, err
			}
			return c.Conn, nil
		}
		notify := p.notify
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}

func (p *ReversePool) Close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		p.signalLocked()
		for p.reserved > 0 {
			p.cond.Wait()
		}
		ready := p.ready
		p.ready = nil
		for _, c := range ready {
			close(c.stop)
		}
		p.mu.Unlock()
		for _, c := range ready {
			_ = c.Close() // interrupt an idle write before waiting for it
			<-c.done
		}
	})
}

func (p *ReversePool) ReadyCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready)
}

func (p *ReversePool) signalLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

func (p *ReversePool) keepIdle(c *pooledConn) {
	defer close(c.done)
	if p.idleInterval <= 0 {
		<-c.stop
		return
	}
	ticker := time.NewTicker(p.idleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}
		if c.err = WriteKeepalive(c.Conn); c.err != nil {
			_ = c.Close()
			p.mu.Lock()
			for i, queued := range p.ready {
				if queued == c {
					p.ready = append(p.ready[:i], p.ready[i+1:]...)
					break
				}
			}
			p.mu.Unlock()
			return
		}
	}
}
