package tunnel

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// encodeRecord must stay the writer's exact record encoding: one compact
// JSON object per line, so consumers can stream-parse the output.
func encodeRecord(t *testing.T, status sdk.RelayStatus) relayLifecycleRecord {
	t.Helper()
	var record relayLifecycleRecord
	line, err := json.Marshal(relayLifecycleRecordFrom(status))
	if err != nil {
		t.Fatalf("marshal lifecycle record: %v", err)
	}
	if bytes := strings.Count(string(line), "\n"); bytes != 0 {
		t.Fatalf("record spans %d lines: %q", bytes+1, line)
	}
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatalf("unmarshal lifecycle record: %v", err)
	}
	return record
}

// The record projects the SDK RelayStatus snapshot: event identity, state,
// canonical public URL, and the granted alias for a ready relay. State is
// sourced from the SDK's authoritative status ownership; the projection is
// the only contract this test protects.
func TestRelayLifecycleRecordReady(t *testing.T) {
	record := encodeRecord(t, sdk.RelayStatus{
		RelayURL:  "https://relay.example.com",
		PublicURL: "https://myapp-identity.relay.example.com",
		AliasURL:  "https://myapp.relay.example.com",
		UDPAddr:   "https://relay.example.com:50000",
		TCPAddr:   "https://relay.example.com:50001",
		State:     sdk.RelayReady,
		Version:   "2.6.3",
	})
	if record.Event != "relay_status" || record.State != "ready" {
		t.Fatalf("record = %+v, want relay_status ready", record)
	}
	if record.RelayURL != "https://relay.example.com" ||
		record.PublicURL != "https://myapp-identity.relay.example.com" ||
		record.AliasURL != "https://myapp.relay.example.com" {
		t.Fatalf("record URLs = %+v, want relay, canonical, and granted alias", record)
	}
	if record.UDPAddr == "" || record.TCPAddr == "" || record.Version != "2.6.3" {
		t.Fatalf("record endpoints = %+v, want UDP, TCP, and version fields", record)
	}
	if record.Deselected || record.Failure != "" || record.Error != "" {
		t.Fatalf("record = %+v, want no failure, error, or deselection when ready", record)
	}
}

// A granted alias is shown only while the relay is ready: the failed and
// deselected projections must retract it, a terminal failure is classified
// in the failure field, and the bounded error stays on one line.
func TestRelayLifecycleRecordAliasOnlyWhenReady(t *testing.T) {
	failed := encodeRecord(t, sdk.RelayStatus{
		RelayURL: "https://relay.example.com",
		State:    sdk.RelayFailed,
		Failure:  sdk.RelayFailureTerminal,
		Err:      errors.New("terminal\nfailure"),
	})
	if failed.State != "failed" || failed.AliasURL != "" {
		t.Fatalf("failed record = %+v, want state failed with retracted alias", failed)
	}
	if failed.Failure != "terminal" {
		t.Fatalf("failed record failure = %q, want terminal", failed.Failure)
	}
	if failed.Error != "terminal failure" {
		t.Fatalf("failed record error = %q, want single-line bounded diagnostic", failed.Error)
	}

	deselected := encodeRecord(t, sdk.RelayStatus{
		RelayURL:   "https://relay.example.com",
		PublicURL:  "https://myapp-identity.relay.example.com",
		AliasURL:   "https://myapp.relay.example.com",
		State:      sdk.RelayReady,
		Deselected: true,
	})
	if deselected.Deselected != true {
		t.Fatalf("deselected record = %+v, want Deselected true", deselected)
	}

	connecting := encodeRecord(t, sdk.RelayStatus{RelayURL: "https://relay.example.com"})
	if connecting.State != "connecting" {
		t.Fatalf("connecting record state = %q, want connecting", connecting.State)
	}
}

func TestSpecValidateOutputValues(t *testing.T) {
	base := func(output string) Spec {
		return Spec{Output: output, Transport: TransportSpec{Target: "localhost:3000"}}
	}
	for _, valid := range []string{"", "text", "jsonl"} {
		if err := base(valid).Validate(); err != nil {
			t.Fatalf("Validate(output=%q) = %v, want nil", valid, err)
		}
	}
	if err := base("yaml").Validate(); err == nil {
		t.Fatal("Validate(output=yaml) = nil, want error")
	}
}
