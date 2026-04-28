package pepper

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPacerBatchesWritesByTimeWindow(t *testing.T) {
	t.Parallel()

	pacer, err := NewPacer(20*time.Millisecond, 0, 1)
	if err != nil {
		t.Fatalf("new pacer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu      sync.Mutex
		batches [][]Cell
	)
	done := make(chan error, 1)
	go func() {
		done <- pacer.Run(ctx, time.Millisecond, func(batch []Cell) {
			mu.Lock()
			defer mu.Unlock()
			batches = append(batches, append([]Cell(nil), batch...))
		})
	}()

	pacer.Submit(Cell{Flags: 0x01})
	pacer.Submit(Cell{Flags: 0x02})

	time.Sleep(5 * time.Millisecond)
	mu.Lock()
	if len(batches) != 0 {
		mu.Unlock()
		t.Fatalf("expected no immediate batch emission, got %d batches", len(batches))
	}
	mu.Unlock()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(batches) == 0 {
		t.Fatal("expected at least one emitted batch")
	}
	if len(batches[0]) != 2 {
		t.Fatalf("expected first batch size 2, got %d", len(batches[0]))
	}
}
