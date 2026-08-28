package sdk

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func captureLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() {
		log.Logger = prev
	})
	return &buf
}

func decodeLogObject(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("decode log json: %v\nraw: %s", err, buf.String())
	}
	return obj
}

func TestLogHTTPReadyEmitsPublicURLAndRelayURL(t *testing.T) {
	buf := captureLogger(t)
	logHTTPReady("0xabc", "https://app.example/path", "https://relay.example")
	obj := decodeLogObject(t, buf)

	if got, want := obj["message"], "service ready at https://app.example/path"; got != want {
		t.Fatalf("message = %v, want %q", got, want)
	}
	if got, want := obj["public_url"], "https://app.example/path"; got != want {
		t.Fatalf("public_url = %v, want %q", got, want)
	}
	if got, want := obj["relay_url"], "https://relay.example"; got != want {
		t.Fatalf("relay_url = %v, want %q", got, want)
	}
	if obj["public_url"] == obj["relay_url"] {
		t.Fatal("public_url must not equal relay_url")
	}
}

func TestReconciledRelayLogIsNotHTTPReady(t *testing.T) {
	buf := captureLogger(t)
	log.Info().Strs("listener_relays", []string{"https://relay.example"}).Msg("reconciled relay listeners")
	obj := decodeLogObject(t, buf)

	if got, want := obj["message"], "reconciled relay listeners"; got != want {
		t.Fatalf("message = %v, want %q", got, want)
	}
	if _, ok := obj["public_url"]; ok {
		t.Fatalf("reconcile log must not have public_url: %v", obj)
	}
}
