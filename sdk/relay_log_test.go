package sdk

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// The machine-readable relay lifecycle contract frames the authoritative
// SDK status logs: one structured record with the stable event name, the
// relay identity, lifecycle state, canonical URL, and the granted alias
// only while ready (issue #596). The projection is the documented
// contract; the SDK status paths remain the only owner of relay state.
func encodeRelayStatusLog(t *testing.T, status RelayStatus) map[string]any {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := zerolog.New(buf)
	relayStatusLogEvent(logger.Info(), status).Msg("")
	line := buf.String()
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("log event spans %d lines: %q", strings.Count(line, "\n")+1, line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("log record is not one JSON object: %v in %q", err, line)
	}
	return record
}

func TestRelayStatusLogEventReady(t *testing.T) {
	record := encodeRelayStatusLog(t, RelayStatus{
		RelayURL:  "https://relay.example.com",
		PublicURL: "https://myapp-identity.relay.example.com",
		AliasURL:  "https://myapp.relay.example.com",
		State:     RelayReady,
	})
	if record["event"] != "relay_status" || record["state"] != "ready" {
		t.Fatalf("record = %v, want event relay_status with state ready", record)
	}
	if record["relay_url"] != "https://relay.example.com" ||
		record["public_url"] != "https://myapp-identity.relay.example.com" {
		t.Fatalf("record URLs = %v, want relay and canonical public URL", record)
	}
	if record["alias_url"] != "https://myapp.relay.example.com" {
		t.Fatalf("record alias = %v, want the granted alias while ready", record["alias_url"])
	}
	if failure, ok := record["failure"]; ok {
		t.Fatalf("record failure = %v, want absent while ready", failure)
	}
	if record["deselected"] != false {
		t.Fatalf("record deselected = %v, want false while ready", record["deselected"])
	}
}

// A deselected tombstone preserves its last ready state and alias, so the
// projection must retract the alias: a removed relay never advertises one.
// A failure record classifies the failure instead.
func TestRelayStatusLogEventDeselectedAndFailed(t *testing.T) {
	deselected := encodeRelayStatusLog(t, RelayStatus{
		RelayURL:   "https://relay.example.com",
		PublicURL:  "https://myapp-identity.relay.example.com",
		AliasURL:   "https://myapp.relay.example.com",
		State:      RelayReady,
		Deselected: true,
	})
	if deselected["deselected"] != true {
		t.Fatalf("record = %v, want deselected true", deselected)
	}
	if alias, ok := deselected["alias_url"]; ok {
		t.Fatalf("record alias = %v, want retracted for a deselected relay", alias)
	}

	failed := encodeRelayStatusLog(t, RelayStatus{
		RelayURL: "https://relay.example.com",
		State:    RelayFailed,
		Failure:  RelayFailureMITM,
	})
	if failed["state"] != "failed" || failed["failure"] != "mitm" {
		t.Fatalf("record = %v, want failed with classified failure", failed)
	}
	if alias, ok := failed["alias_url"]; ok {
		t.Fatalf("record alias = %v, want absent on failure", alias)
	}

	connecting := encodeRelayStatusLog(t, RelayStatus{RelayURL: "https://relay.example.com", State: RelayConnecting})
	if connecting["state"] != "connecting" {
		t.Fatalf("record state = %v, want connecting", connecting["state"])
	}
}
