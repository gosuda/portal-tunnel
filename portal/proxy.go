package portal

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
)

type proxy struct {
	activeConns  atomic.Int64
	tcpBytes     atomic.Int64
	tcpLoadMu    sync.Mutex
	tcpLoadAt    time.Time
	tcpLoadBytes int64
	load         *policy.LoadManager
}

func (p *proxy) bridge(left, right net.Conn, identityKey string, bpsManager *policy.BPSManager) {
	p.activeConns.Add(1)
	defer p.activeConns.Add(-1)

	defer left.Close()
	defer right.Close()

	if p.load != nil {
		p.load.RecordConnStart()
		defer p.load.RecordConnEnd()
	}

	throttled := bpsManager != nil && bpsManager.IdentityBPS(identityKey) > 0
	var group errgroup.Group
	group.Go(func() error {
		err := p.copy(right, left, identityKey, bpsManager, throttled, p.recordBytesIn)
		closeWrite(right)
		return err
	})
	group.Go(func() error {
		err := p.copy(left, right, identityKey, bpsManager, throttled, p.recordBytesOut)
		closeWrite(left)
		return err
	})
	_ = group.Wait()
}

func (p *proxy) recordBytesIn(n int64) {
	if p.load != nil && n > 0 {
		p.load.RecordBytesIn(n)
	}
}

func (p *proxy) recordBytesOut(n int64) {
	if p.load != nil && n > 0 {
		p.load.RecordBytesOut(n)
	}
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

func (p *proxy) copy(dst, src net.Conn, identityKey string, bpsManager *policy.BPSManager, throttled bool, record func(int64)) error {
	// fast path
	if !throttled {
		_, err := io.Copy(&countingConn{
			Conn:   dst,
			bytes:  &p.tcpBytes,
			record: record,
		}, src)
		return err
	}

	buf := make([]byte, 32*1024)
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			data := buf[:nr]
			for len(data) > 0 {
				chunkSize := len(data)
				if bpsManager != nil {
					chunkSize = bpsManager.ThrottleIdentityBPS(identityKey, chunkSize)
				}

				n, err := dst.Write(data[:chunkSize])
				if n > 0 {
					p.tcpBytes.Add(int64(n))
					if record != nil {
						record(int64(n))
					}
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

type countingConn struct {
	net.Conn
	bytes  *atomic.Int64
	record func(int64)
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytes.Add(int64(n))
		if c.record != nil {
			c.record(int64(n))
		}
	}
	return n, err
}

func (c *countingConn) ReadFrom(r io.Reader) (int64, error) {
	readerFrom, ok := c.Conn.(io.ReaderFrom)
	if !ok {
		return io.Copy(struct{ io.Writer }{Writer: c}, r)
	}

	n, err := readerFrom.ReadFrom(r)
	if n > 0 {
		c.bytes.Add(n)
		if c.record != nil {
			c.record(n)
		}
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
