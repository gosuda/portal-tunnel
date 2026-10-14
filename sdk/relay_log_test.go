package sdk

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func TestExposureRelayStatusLogsReadinessLossAndRecovery(t *testing.T) {
	const relayURL = "https://relay.example.com"
	const publicURL = "https://myapp-identity.relay.example.com"
	const aliasURL = "https://myapp.relay.example.com"
	exposure := newExposureStateTest(t, relayURL)
	var buf bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previousLogger })

	// Opening the first reverse session grants readiness. Closing the last
	// session reports connecting with the leased URLs still available;
	// recovery makes the same lease ready again.
	for _, state := range []RelayState{RelayReady, RelayConnecting, RelayReady} {
		exposure.setRelayStatus(relayURL, listenerStatus{
			state: state, publicURL: publicURL, aliasURL: aliasURL,
		})
	}

	decoder := json.NewDecoder(&buf)
	for _, state := range []string{"ready", "connecting", "ready"} {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatalf("decode %s lifecycle record: %v", state, err)
		}
		if record["event"] != "relay_status" || record["state"] != state ||
			record["relay_url"] != relayURL || record["public_url"] != publicURL {
			t.Fatalf("record = %v, want %s for relay %s with retained public URL", record, state, relayURL)
		}
		if state == "connecting" {
			if _, ok := record["alias_url"]; ok {
				t.Fatalf("connecting record = %v, want no alias", record)
			}
		} else if record["alias_url"] != aliasURL {
			t.Fatalf("ready record = %v, want granted alias %s", record, aliasURL)
		}
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected extra lifecycle record: %v, error: %v", extra, err)
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
