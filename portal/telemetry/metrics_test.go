package telemetry_test

import (
	"fmt"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
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
	for i := range total {
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

	for i := range total {
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
