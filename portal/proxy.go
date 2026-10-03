package portal

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

type proxy struct {
	activeConns  atomic.Int64
	tcpBytes     atomic.Int64
	tcpLoadMu    sync.Mutex
	tcpLoadAt    time.Time
	tcpLoadBytes int64
}

func (p *proxy) bridge(left, right net.Conn, identityKey string, bpsManager *BPSManager) {
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
func (p *proxy) copy(dst, src net.Conn, identityKey string, bpsManager *BPSManager) error {
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
