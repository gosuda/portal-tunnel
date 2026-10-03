package portal

import (
	"bytes"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// openBridge wires proxy.bridge across two in-memory pipe pairs and returns
// the client ends of the connection pair plus the BPS manager the bridge
// observes.
func openBridge(t *testing.T) (send, recv net.Conn, bps *BPSManager, closeBridge func()) {
	t.Helper()
	send, sendRelay := net.Pipe()
	recvRelay, recv := net.Pipe()
	bps = NewBPSManager()
	var p proxy
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p.bridge(sendRelay, recvRelay, "demo:0x1", bps)
	}()
	return send, recv, bps, func() {
		c0 := time.Now()
		_ = send.Close()
		t.Logf("close(send)=%v", time.Since(c0).Round(time.Millisecond))
		c1 := time.Now()
		_ = recv.Close()
		t.Logf("close(recv)=%v", time.Since(c1).Round(time.Millisecond))
		c2 := time.Now()
		<-finished
		t.Logf("wait(finished)=%v", time.Since(c2).Round(time.Millisecond))
	}
}

// readFor consumes recv until size bytes arrive or the deadline passes and
// reports how many bytes arrived.
func readFor(recv net.Conn, size int, within time.Duration) int {
	buf := make([]byte, size)
	deadline := time.Now().Add(within)
	total := 0
	for total < size {
		_ = recv.SetReadDeadline(deadline)
		n, err := recv.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	return total
}

func TestBridgeAppliesBPSLimitToOpenConnection(t *testing.T) {
	send, recv, bps, closeBridge := openBridge(t)
	defer closeBridge()

	// Unlimited: a large payload crosses at full speed.
	phaseA := time.Now()
	payload := bytes.Repeat([]byte{'x'}, 64<<10)
	go func() { _, _ = send.Write(payload) }()
	if got := readFor(recv, len(payload), 2*time.Second); got != len(payload) {
		t.Fatalf("unlimited transfer = %d/%d bytes", got, len(payload))
	}
	t.Logf("phaseA=%v", time.Since(phaseA).Round(time.Millisecond))

	// A limit set while the connection is already open must pace it: at
	// 1KiB/s, 4KiB needs about four seconds and cannot arrive in 300ms.
	bps.SetIdentityBPS("demo:0x1", 1024)
	phaseB := time.Now()
	limited := bytes.Repeat([]byte{'y'}, 4<<10)
	go func() { _, _ = send.Write(limited) }()
	if got := readFor(recv, len(limited), 300*time.Millisecond); got >= len(limited) {
		t.Fatalf("4KiB crossed at full speed after SetIdentityBPS on an open connection (%d bytes in 300ms)", got)
	}
	t.Logf("phaseB=%v", time.Since(phaseB).Round(time.Millisecond))
}

func TestBridgeClearsBPSLimitOnOpenConnection(t *testing.T) {
	send, recv, bps, closeBridge := openBridge(t)
	defer closeBridge()

	bps.SetIdentityBPS("demo:0x1", 1024)
	payload := bytes.Repeat([]byte{'y'}, 4<<10)
	go func() { _, _ = send.Write(payload) }()

	// Paced at 1KiB/s the payload cannot complete quickly...
	got := readFor(recv, len(payload), 300*time.Millisecond)
	if got >= len(payload) {
		t.Fatalf("4KiB crossed at full speed while throttled (%d bytes in 300ms)", got)
	}

	// ...and removing the limit must release the same open connection.
	bps.SetIdentityBPS("demo:0x1", 0)
	if rest := readFor(recv, len(payload)-got, 2*time.Second); rest < len(payload)-got {
		t.Fatalf("transfer stayed throttled after SetIdentityBPS(0) on an open connection (%d/%d remaining bytes)", rest, len(payload)-got)
	}
}

func TestBPSWaitRetainsAccruedCredit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var limiter bpsLimiter
		if wait := limiter.reserve(10, 100); wait != 100*time.Millisecond {
			t.Fatalf("initial wait = %v, want 100ms", wait)
		}
		synctest.Sleep(60 * time.Millisecond)
		if wait := limiter.reserve(10, 100); wait != 40*time.Millisecond {
			t.Fatalf("remaining wait = %v, want 40ms", wait)
		}
		synctest.Sleep(40 * time.Millisecond)
		if wait := limiter.reserve(10, 100); wait != 0 {
			t.Fatalf("10 bytes still throttled after 100ms at 100 B/s: %v", wait)
		}
	})
}
