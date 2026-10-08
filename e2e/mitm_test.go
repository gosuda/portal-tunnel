package e2e_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// captureSDKLogs redirects the SDK's global zerolog logger into a locked
// buffer so the test can observe the probe verdict. The original logger and
// global level are restored at test end.
func captureSDKLogs(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{buf: &bytes.Buffer{}}
	previousLogger := log.Logger
	previousLevel := zerolog.GlobalLevel()
	log.Logger = zerolog.New(capture).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		zerolog.SetGlobalLevel(previousLevel)
		log.Logger = previousLogger
	})
	return capture
}

type logCapture struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) contains(needle string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Contains(c.buf.String(), needle)
}

func (c *logCapture) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// TestMITMSelfProbeRunsOnTenantTraffic is the live-loop proof of the
// restored responder path (#501): an exposure with --ban-mitm semantics
// registers against the in-process relay instead of failing the
// registration gate, the first tenant traffic arms the self-probe, the
// relay routes the probe connection through tenant TLS, the SDK terminates
// it via the keyless_tls t13server, the responder recognizes the probe
// nonce and compares exporter values, and the probe reports passthrough.
// Mismatch and timeout classification stays in the sdk unit tests; this
// pins the working loop end to end and keeps a clean relay from ever
// producing a suspicion verdict.
func TestMITMSelfProbeRunsOnTenantTraffic(t *testing.T) {
	logs := captureSDKLogs(t)

	// With the exporter capability restored, ban-mitm must not fail the
	// registration gate the way it did before #501.
	h := newHarness(t, sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}

	// The probe is asynchronous: poll the captured SDK log instead of
	// racing it. A verdict must arrive well inside the probe timeout.
	deadline := time.Now().Add(20 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !logs.contains("tls passthrough self-probe passed") {
		if logs.contains(types.MITMProbeReasonProbeTimeout) {
			t.Fatalf("mitm self-probe timed out instead of reporting passthrough; sdk logs: %s", logs.snapshot())
		}
		if logs.contains(types.MITMProbeReasonExporterMismatch) {
			t.Fatalf("clean relay produced an exporter mismatch verdict; sdk logs: %s", logs.snapshot())
		}
		if time.Now().After(deadline) {
			t.Fatalf("mitm self-probe did not report passthrough within 20s; sdk logs: %s", logs.snapshot())
		}
		<-tick.C
	}

	// The exposure must keep serving normally after the probe: ban-mitm
	// fired nothing on a clean relay.
	if got := h.get(publicURL); got != marker {
		t.Fatalf("post-probe tenant response = %q, want %q", got, marker)
	}
}
