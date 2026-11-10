package portal

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type proxyShortWriteConn struct {
	net.Conn
}

func (c *proxyShortWriteConn) Write(b []byte) (int, error) {
	return 0, nil
}

func TestCopyProxyZeroWriteReturnsShortWrite(t *testing.T) {
	var p proxy
	bps := NewBPSManager(0)
	key := types.NewServiceIdentityKey("tenant", "address")
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	dst := &proxyShortWriteConn{Conn: local}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type copyResult struct {
		err error
	}
	done := make(chan copyResult, 1)
	go func() {
		done <- copyResult{p.copyProxyDrain(ctx, dst, key, bps, []byte("proxy-short-write"))}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, io.ErrShortWrite) {
			t.Fatalf("copyProxyDrain() error = %v, want %v", r.err, io.ErrShortWrite)
		}
	case <-ctx.Done():
		t.Fatal("copyProxyDrain() did not return on zero-byte write")
	}
}
