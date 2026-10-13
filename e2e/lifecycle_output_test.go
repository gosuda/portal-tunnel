package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
)

// lifecycleRecord mirrors one machine-readable relay_status output record.
type lifecycleRecord struct {
	Event      string `json:"event"`
	RelayURL   string `json:"relay_url"`
	State      string `json:"state"`
	PublicURL  string `json:"public_url,omitempty"`
	AliasURL   string `json:"alias_url,omitempty"`
	Deselected bool   `json:"deselected"`
}

// The machine-readable lifecycle output projects the real SDK exposure
// status: a ready record names the relay, the tenant-ready canonical URL,
// and the granted alias; deselection retracts it — all without parsing
// any human-readable log line.
func TestRelayLifecycleJSONLOutput(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer service.Close()
	target, err := url.Parse(service.URL)
	if err != nil {
		t.Fatalf("parse local service URL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay := startMembershipRelay(t, ctx)

	outputPipe, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity:  tunnel.IdentitySpec{Name: "lifecycle"},
		Relays:    tunnel.RelaySpec{URLs: []string{relay.relayURL}},
		Transport: tunnel.TransportSpec{Target: target.Host},
		Output:    "jsonl",
	})
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	outputCtx, outputCancel := context.WithCancel(ctx)
	runtime.StartRelayLifecycleWriter(outputCtx, outputWriter)
	t.Cleanup(outputCancel)

	ready := waitForLifecycleState(t, outputPipe, "ready", 30*time.Second)
	if ready.Event != "relay_status" || ready.RelayURL == "" {
		t.Fatalf("ready record = %+v, want relay_status with a relay URL", ready)
	}
	if ready.PublicURL == "" {
		t.Fatalf("ready record = %+v, want the tenant-ready canonical public URL", ready)
	}
	if ready.Deselected {
		t.Fatalf("ready record = %+v, want no deselection", ready)
	}

	// Deselection has an output analogue: removing the relay retracts the
	// previously advertised URL through the same status ownership.
	if err := runtime.Exposure.RemoveRelay(ready.RelayURL); err != nil {
		t.Fatalf("remove relay: %v", err)
	}
	deselected := waitForLifecycleDeselected(t, outputPipe, 15*time.Second)
	if !deselected.Deselected || deselected.PublicURL == "" {
		t.Fatalf("deselection record = %+v, want deselected with the retracted public URL", deselected)
	}
}

// scanLifecycleRecord reads output lines with timeout until one matches:
// state set and not deselected for a ready wait, deselected otherwise.
func scanLifecycleRecord(t *testing.T, pipe *os.File, timeout time.Duration, match func(lifecycleRecord) bool) lifecycleRecord {
	t.Helper()
	type result struct {
		record lifecycleRecord
		err    error
	}
	results := make(chan result, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for {
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					results <- result{err: err}
				}
				return
			}
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			var record lifecycleRecord
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				results <- result{err: err}
				return
			}
			if match(record) {
				results <- result{record: record}
				return
			}
		}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("read lifecycle output: %v", result.err)
		}
		return result.record
	case <-time.After(timeout):
		t.Fatalf("no matching lifecycle record within %v", timeout)
		return lifecycleRecord{}
	}
}

func waitForLifecycleState(t *testing.T, pipe *os.File, state string, timeout time.Duration) lifecycleRecord {
	t.Helper()
	return scanLifecycleRecord(t, pipe, timeout, func(record lifecycleRecord) bool {
		return record.State == state && !record.Deselected
	})
}

func waitForLifecycleDeselected(t *testing.T, pipe *os.File, timeout time.Duration) lifecycleRecord {
	t.Helper()
	return scanLifecycleRecord(t, pipe, timeout, func(record lifecycleRecord) bool {
		return record.Deselected
	})
}
