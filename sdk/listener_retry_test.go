package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestWaitRetryLogsFirstFailureAtWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })

	l := &listener{
		identity:  types.Identity{Address: "0xabc"},
		retryWait: time.Millisecond,
	}
	if !l.waitRetry(context.Background(), "lease registration", errors.New("boom"), 1, 0) {
		t.Fatal("waitRetry returned false")
	}

	var obj map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("decode log json: %v\nraw: %s", err, buf.String())
	}
	if got, want := obj["level"], "warn"; got != want {
		t.Fatalf("level = %v, want %q", got, want)
	}
	if got, want := obj["message"], "operation failed; retrying"; got != want {
		t.Fatalf("message = %v, want %q", got, want)
	}
	if got, want := obj["operation"], "lease registration"; got != want {
		t.Fatalf("operation = %v, want %q", got, want)
	}
}
