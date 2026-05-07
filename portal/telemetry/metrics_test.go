package telemetry_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// metricFamilyByName gathers all metric families and returns the one with the
// given name, or nil if not found.
func metricFamilyByName(t *testing.T, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// assertRegisteredWithName verifies that collector c is already registered on
// prometheus.DefaultRegisterer by attempting to re-register it and expecting
// AlreadyRegisteredError.  It then confirms that the previously-registered
// collector's first described metric name equals wantName.
//
// This is the only approach that simultaneously proves (a) the collector is on
// the default registry and (b) the registered metric has the expected name, for
// both Vec and non-Vec collectors with no prior observations.
func assertRegisteredWithName(t *testing.T, c prometheus.Collector, wantName string) {
	t.Helper()
	err := prometheus.DefaultRegisterer.Register(c)
	if err == nil {
		// Re-registration succeeded — the collector was NOT on the default registry.
		// Undo the registration so the rest of the test suite is not affected.
		prometheus.DefaultRegisterer.Unregister(c)
		t.Fatalf("metric %q: collector was not registered on DefaultRegisterer before the test", wantName)
	}
	var are prometheus.AlreadyRegisteredError
	if !errors.As(err, &are) {
		t.Fatalf("metric %q: unexpected registration error: %v", wantName, err)
	}
	// are.ExistingCollector is the collector already on the registry.
	// Drain its Describe channel to confirm the expected metric name is present.
	ch := make(chan *prometheus.Desc, 32)
	go func() {
		are.ExistingCollector.Describe(ch)
		close(ch)
	}()
	found := false
	for d := range ch {
		// Desc.String() format: Desc{fqName: "the_name", help: "...", ...}
		s := d.String()
		const marker = `fqName: "`
		idx := 0
		for idx+len(marker) <= len(s) {
			if s[idx:idx+len(marker)] == marker {
				start := idx + len(marker)
				end := start
				for end < len(s) && s[end] != '"' {
					end++
				}
				if s[start:end] == wantName {
					found = true
				}
				break
			}
			idx++
		}
	}
	if !found {
		t.Errorf("metric %q: name not found in described metrics of existing collector", wantName)
	}
}

// TestMetricsRegistryPresence asserts that all 8 Phase-1 metrics are registered
// on prometheus.DefaultRegisterer.  It uses Register→AlreadyRegisteredError so
// Vec metrics with no prior observations are still detected (they are invisible
// to DefaultGatherer.Gather until the first label combination is used).
func TestMetricsRegistryPresence(t *testing.T) {
	want := []struct {
		name      string
		collector prometheus.Collector
		typ       dto.MetricType
	}{
		{"portal_discovery_relay_selected_total", telemetry.RelaySelectedTotal, dto.MetricType_COUNTER},
		{"portal_discovery_relay_pool_size", telemetry.RelayPoolSize, dto.MetricType_GAUGE},
		{"portal_discovery_rtt_seconds", telemetry.RTTSeconds, dto.MetricType_HISTOGRAM},
		{"portal_discovery_active_tunnels_per_relay", telemetry.ActiveTunnelsPerRelay, dto.MetricType_GAUGE},
		{"portal_discovery_selection_duration_seconds", telemetry.SelectionDurationSeconds, dto.MetricType_HISTOGRAM},
		{"portal_discovery_selection_skipped_total", telemetry.SelectionSkippedTotal, dto.MetricType_COUNTER},
		{"portal_discovery_failures_total", telemetry.FailuresTotal, dto.MetricType_COUNTER},
		{"portal_discovery_congestion_mode", telemetry.CongestionMode, dto.MetricType_GAUGE},
	}

	for _, tc := range want {
		t.Run(tc.name, func(t *testing.T) {
			// Primary check: collector is on DefaultRegisterer.
			assertRegisteredWithName(t, tc.collector, tc.name)
			// Secondary check: if the metric has observations, verify HELP and type.
			mf := metricFamilyByName(t, tc.name)
			if mf != nil {
				if mf.GetHelp() == "" {
					t.Errorf("metric %q has empty HELP string", tc.name)
				}
				if mf.GetType() != tc.typ {
					t.Errorf("metric %q: got type %v, want %v", tc.name, mf.GetType(), tc.typ)
				}
			}
		})
	}
}

// TestEmitFromTrace_CounterIncrement verifies that EmitFromTrace increments
// relay_selected_total for each output URL and records a selection duration.
// URL names are test-namespaced to avoid coupling to other tests that share the
// process-global relay-cardinality map.
func TestEmitFromTrace_CounterIncrement(t *testing.T) {
	r1 := "t-counter-r1"
	r2 := "t-counter-r2"

	// Capture baseline before the call.
	baseline := func(relay string) float64 {
		mf := metricFamilyByName(t, "portal_discovery_relay_selected_total")
		if mf == nil {
			return 0
		}
		for _, m := range mf.GetMetric() {
			var gotRelay, gotReason string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "relay":
					gotRelay = lp.GetValue()
				case "reason":
					gotReason = lp.GetValue()
				}
			}
			if gotRelay == relay && gotReason == "auto" {
				return m.GetCounter().GetValue()
			}
		}
		return 0
	}

	baseR1 := baseline(r1)
	baseR2 := baseline(r2)

	// Capture duration baseline before the single EmitFromTrace call.
	durationSampleCount := func() uint64 {
		mf := metricFamilyByName(t, "portal_discovery_selection_duration_seconds")
		if mf == nil || len(mf.GetMetric()) == 0 {
			return 0
		}
		return mf.GetMetric()[0].GetHistogram().GetSampleCount()
	}
	baseDur := durationSampleCount()

	telemetry.EmitFromTrace(telemetry.SelectionTrace{
		OutputURLs:    []string{r1, r2},
		SelectionTook: 50 * time.Millisecond,
		Congested:     false,
		NonLinear:     false,
	})

	// relay_selected_total delta must be 1 for each relay.
	afterR1 := baseline(r1)
	afterR2 := baseline(r2)
	if afterR1-baseR1 != 1 {
		t.Errorf("relay_selected_total{relay=%q,reason=auto}: delta want 1, got %v", r1, afterR1-baseR1)
	}
	if afterR2-baseR2 != 1 {
		t.Errorf("relay_selected_total{relay=%q,reason=auto}: delta want 1, got %v", r2, afterR2-baseR2)
	}

	// selection_duration_seconds delta must be exactly 1 for this invocation.
	afterDur := durationSampleCount()
	if afterDur-baseDur != 1 {
		t.Errorf("selection_duration_seconds sample delta want 1, got %d", afterDur-baseDur)
	}
}

// TestEmitFromTrace_CardinalityCap verifies the relay-label cardinality cap.
//
// We emit maxRelayLabelCardinality+1 distinct relay URLs and then assert:
//  1. relay="other" appears in relay_selected_total (overflow was bucketed).
//  2. Every emitted URL either appears as its own relay label OR caused "other"
//     to be incremented — i.e., no URL is silently dropped.
//
// Because relayBudget is process-global and prior tests may have consumed some
// slots, we emit enough URLs (maxRelayLabelCardinality+1 = 65) to guarantee at
// least one overflow regardless of prior state, then verify the above.
//
// URLs are namespaced as "t-cap-NNN" to isolate them from other tests.
func TestEmitFromTrace_CardinalityCap(t *testing.T) {
	const total = telemetry.MaxRelayLabelCardinality + 1 // 65

	// Build the set of our namespace URLs.
	ourURLs := make(map[string]struct{}, total)
	for i := 0; i < total; i++ {
		ourURLs[fmt.Sprintf("t-cap-%03d", i)] = struct{}{}
	}

	// relayReasonCounter returns the counter value for the given (relay, reason) pair.
	relayReasonCounter := func(relay, reason string) float64 {
		mf := metricFamilyByName(t, "portal_discovery_relay_selected_total")
		if mf == nil {
			return 0
		}
		for _, m := range mf.GetMetric() {
			var r, rs string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "relay":
					r = lp.GetValue()
				case "reason":
					rs = lp.GetValue()
				}
			}
			if r == relay && rs == reason {
				return m.GetCounter().GetValue()
			}
		}
		return 0
	}

	// Our traces are all non-congested non-nonlinear → reason="auto".
	baseOther := relayReasonCounter("other", "auto")

	for i := 0; i < total; i++ {
		url := fmt.Sprintf("t-cap-%03d", i)
		telemetry.EmitFromTrace(telemetry.SelectionTrace{
			OutputURLs:    []string{url},
			SelectionTook: time.Millisecond,
		})
	}

	mf := metricFamilyByName(t, "portal_discovery_relay_selected_total")
	if mf == nil {
		t.Fatal("portal_discovery_relay_selected_total not found")
	}

	// Collect the our-namespace relay labels that were admitted (got own slot).
	admittedOurs := make(map[string]struct{})
	for _, m := range mf.GetMetric() {
		var r string
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "relay" {
				r = lp.GetValue()
			}
		}
		if _, ok := ourURLs[r]; ok {
			admittedOurs[r] = struct{}{}
		}
	}

	afterOther := relayReasonCounter("other", "auto")
	overflowed := total - len(admittedOurs) // how many of our URLs were bucketed

	// Assert: at least one URL overflowed to "other".
	if overflowed <= 0 {
		t.Errorf("expected at least 1 URL to overflow to \"other\"; admitted=%d out of %d", len(admittedOurs), total)
	}

	// Assert: the counter delta for {relay="other",reason="auto"} matches the
	// number of our-namespace URLs that were not admitted (not merely inferred).
	delta := afterOther - baseOther
	if delta < float64(overflowed) {
		t.Errorf("relay_selected_total{relay=\"other\",reason=\"auto\"} delta want >=%d, got %.0f", overflowed, delta)
	}

	// Assert: admitted URL count never exceeds the cap.
	if len(admittedOurs) > telemetry.MaxRelayLabelCardinality {
		t.Errorf("admitted our-namespace relays: want <=%d, got %d", telemetry.MaxRelayLabelCardinality, len(admittedOurs))
	}
}

// TestMetrics_NoPIILabels iterates every gathered metric family and every label
// pair within and asserts that no label *name* equals "client_hash" or
// "local_address". This is the Phase 1 regression defense for acceptance #4.
func TestMetrics_NoPIILabels(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				name := lp.GetName()
				if name == "client_hash" || name == "local_address" {
					t.Errorf("PII label %q found in metric family %q", name, mf.GetName())
				}
			}
		}
	}
}
