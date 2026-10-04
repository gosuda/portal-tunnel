package portal

import (
	"errors"
	"testing"
	"time"
)

func TestPortPoolReservesReleasedPortForOwner(t *testing.T) {
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate("first")
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port)
	if _, err := pool.allocate("other"); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another owner consumed reserved port: %v", err)
	}
	if reclaimed, err := pool.allocate("first"); err != nil || reclaimed != port {
		t.Fatalf("owner reclaim = %d, %v", reclaimed, err)
	}
}

func TestPortPoolReusesPortAfterReservationExpires(t *testing.T) {
	pool := newPortPool(10000, 10000, -time.Second)
	port, err := pool.allocate("first")
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port)
	if reused, err := pool.allocate("other"); err != nil || reused != port {
		t.Fatalf("expired reservation = %d, %v", reused, err)
	}
}
