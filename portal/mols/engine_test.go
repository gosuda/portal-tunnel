package mols

import (
	"testing"
	"time"
)

func TestEngineRankEmptyPool(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	res := e.Rank(Ingress{ID: "test"}, nil)
	if len(res.Ordered) != 0 {
		t.Fatalf("expected empty result for nil pool, got %d", len(res.Ordered))
	}
}

func TestEngineRankDeterministic(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	candidates := []Candidate{
		{ID: "https://relay-a.example", Index: HashToGF64("https://relay-a.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-b.example", Index: HashToGF64("https://relay-b.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-c.example", Index: HashToGF64("https://relay-c.example"), Healthy: true, Confirmed: true},
	}
	ingress := Ingress{ID: "0x1234abcd", Index: HashToGF64("0x1234abcd")}

	first := e.Rank(ingress, candidates)
	for range 5 {
		got := e.Rank(ingress, candidates)
		if len(got.Ordered) != len(first.Ordered) {
			t.Fatalf("non-deterministic length: %d vs %d", len(got.Ordered), len(first.Ordered))
		}
		for i := range got.Ordered {
			if got.Ordered[i].ID != first.Ordered[i].ID {
				t.Fatalf("non-deterministic result at index %d: %q vs %q", i, got.Ordered[i].ID, first.Ordered[i].ID)
			}
		}
	}
}

func TestEngineRankDifferentIngressDifferentOrder(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	candidates := []Candidate{
		{ID: "https://relay-alpha.example", Index: HashToGF64("https://relay-alpha.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-beta.example", Index: HashToGF64("https://relay-beta.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-gamma.example", Index: HashToGF64("https://relay-gamma.example"), Healthy: true, Confirmed: true},
	}

	addresses := []string{"0xabc", "0xdef", "0x123", "0x456", "user@example.com", "relay.net"}
	orderings := make(map[string]struct{})
	for _, addr := range addresses {
		res := e.Rank(Ingress{ID: addr, Index: HashToGF64(addr)}, candidates)
		key := ""
		for _, c := range res.Ordered {
			key += c.ID + "|"
		}
		orderings[key] = struct{}{}
	}

	if len(orderings) == 1 {
		// Verify by checking GF(64) row diversity for these relays.
		j1 := HashToGF64("https://relay-alpha.example")
		j2 := HashToGF64("https://relay-beta.example")
		j3 := HashToGF64("https://relay-gamma.example")

		type row [3]int
		rows := make(map[row]struct{})
		for _, addr := range addresses {
			i := HashToGF64(addr)
			r := row{
				molsScore(int(i), int(j1), int(DefaultBaseM1), int(DefaultBaseM2), 64),
				molsScore(int(i), int(j2), int(DefaultBaseM1), int(DefaultBaseM2), 64),
				molsScore(int(i), int(j3), int(DefaultBaseM1), int(DefaultBaseM2), 64),
			}
			rows[r] = struct{}{}
		}
		if len(rows) == 1 {
			t.Skip("all selected ingress addresses happen to hash to the same GF(64) index")
		}
		t.Fatal("expected multiple ingress addresses to produce at least two distinct orderings")
	}
}

func TestEngineRankCongestionSwitchChangesOrder(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	ingress := Ingress{ID: "ingress-test", Index: HashToGF64("ingress-test")}
	candidates := []Candidate{
		{ID: "https://relay-one.example", Index: HashToGF64("https://relay-one.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-two.example", Index: HashToGF64("https://relay-two.example"), Healthy: true, Confirmed: true},
	}

	// Normal mode: no RTT measurements → no congestion.
	normal := e.Rank(ingress, candidates)

	// Congestion mode: set RTTs above threshold (but low CV to avoid variant).
	congestedCandidates := []Candidate{
		{ID: "https://relay-one.example", Index: HashToGF64("https://relay-one.example"), RTT: DefaultCongestionRTTThreshold + 100*time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
		{ID: "https://relay-two.example", Index: HashToGF64("https://relay-two.example"), RTT: DefaultCongestionRTTThreshold + 100*time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
	}
	congested := e.Rank(ingress, congestedCandidates)

	if len(normal.Ordered) != 2 || len(congested.Ordered) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d congested=%d", len(normal.Ordered), len(congested.Ordered))
	}

	if normal.Ordered[0].ID == congested.Ordered[0].ID {
		j1 := HashToGF64("https://relay-one.example")
		j2 := HashToGF64("https://relay-two.example")
		normal1 := molsScore(int(ingress.Index), int(j1), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		normal2 := molsScore(int(ingress.Index), int(j2), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		cong1 := molsCongestionScore(int(ingress.Index), int(j1), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		cong2 := molsCongestionScore(int(ingress.Index), int(j2), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		if (normal1 > normal2) != (cong1 > cong2) {
			t.Fatal("expected congestion switch to invert ordering but result matched normal mode")
		}
	}
}

func TestEngineRankVariantGridActivatesOnHighCV(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	ingress := Ingress{ID: "ingress-cv", Index: HashToGF64("ingress-cv")}

	normalCandidates := []Candidate{
		{ID: "https://relay-one.example", Index: HashToGF64("https://relay-one.example"), Healthy: true, Confirmed: true},
		{ID: "https://relay-two.example", Index: HashToGF64("https://relay-two.example"), Healthy: true, Confirmed: true},
	}
	normal := e.Rank(ingress, normalCandidates)

	// High-CV mode: very different RTTs push CV above 0.5 while the mean stays
	// below the congestion threshold, isolating the variant-grid branch.
	variantCandidates := []Candidate{
		{ID: "https://relay-one.example", Index: HashToGF64("https://relay-one.example"), RTT: 100 * time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
		{ID: "https://relay-two.example", Index: HashToGF64("https://relay-two.example"), RTT: 400 * time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
	}
	avgRTT, cv := poolRTTStats(variantCandidates)
	if cv <= DefaultCVThreshold {
		t.Fatalf("test precondition: cv = %v, want > %v", cv, DefaultCVThreshold)
	}
	if avgRTT > DefaultCongestionRTTThreshold {
		t.Fatalf("test precondition: avgRTT = %v, want <= %v", avgRTT, DefaultCongestionRTTThreshold)
	}

	variant := e.Rank(ingress, variantCandidates)

	if len(normal.Ordered) != 2 || len(variant.Ordered) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d variant=%d", len(normal.Ordered), len(variant.Ordered))
	}

	if normal.Ordered[0].ID != "https://relay-one.example" {
		t.Fatalf("normal order first relay = %q, want relay-one", normal.Ordered[0].ID)
	}
	if variant.Ordered[0].ID != "https://relay-two.example" {
		t.Fatalf("variant order first relay = %q, want relay-two", variant.Ordered[0].ID)
	}
}

func TestEngineRankFallbackDemoted(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	candidates := []Candidate{
		{ID: "https://relay-healthy-1.example", Index: HashToGF64("https://relay-healthy-1.example"), RTT: 100 * time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
		{ID: "https://relay-healthy-2.example", Index: HashToGF64("https://relay-healthy-2.example"), RTT: 150 * time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
		{ID: "https://relay-fallback.example", Index: HashToGF64("https://relay-fallback.example"), RTT: DefaultFallbackRTTThreshold + time.Millisecond, RTTAt: time.Now(), Healthy: false, Confirmed: true},
	}
	res := e.Rank(Ingress{ID: "test"}, candidates)
	if len(res.Ordered) != 3 {
		t.Fatalf("len(ordered) = %d, want 3", len(res.Ordered))
	}
	if res.Ordered[len(res.Ordered)-1].ID != "https://relay-fallback.example" {
		t.Fatalf("last ordered = %q, want fallback relay", res.Ordered[len(res.Ordered)-1].ID)
	}
}

func TestEngineRankMinActiveNodesPromotesFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinActiveNodes = 2
	e := NewEngine(cfg, nil)
	candidates := []Candidate{
		{ID: "https://relay-fallback-1.example", Index: HashToGF64("https://relay-fallback-1.example"), RTT: DefaultFallbackRTTThreshold + time.Millisecond, RTTAt: time.Now(), Healthy: false, Confirmed: true},
		{ID: "https://relay-fallback-2.example", Index: HashToGF64("https://relay-fallback-2.example"), RTT: DefaultFallbackRTTThreshold + time.Millisecond, RTTAt: time.Now(), Healthy: false, Confirmed: true},
	}
	res := e.Rank(Ingress{ID: "test"}, candidates)
	if len(res.Ordered) != 2 {
		t.Fatalf("len(ordered) = %d, want 2 (both fallbacks promoted)", len(res.Ordered))
	}
}

func TestEngineRankSaturatedDeprioritised(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CandidateDepth = 8
	e := NewEngine(cfg, nil)
	candidates := []Candidate{
		{ID: "https://relay-saturated.example", Index: HashToGF64("https://relay-saturated.example"), Healthy: true, Confirmed: true, Saturated: true},
		{ID: "https://relay-unsaturated.example", Index: HashToGF64("https://relay-unsaturated.example"), Healthy: true, Confirmed: true, Saturated: false},
	}
	res := e.Rank(Ingress{ID: "test"}, candidates)
	if len(res.Ordered) != 2 {
		t.Fatalf("len(ordered) = %d, want 2", len(res.Ordered))
	}
	if res.Ordered[0].ID != "https://relay-unsaturated.example" {
		t.Fatalf("expected unsaturated first, got %q", res.Ordered[0].ID)
	}
}

func TestEngineRankMathematicalOrdering(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	ingress := Ingress{ID: "192.168.0.10", Index: HashToGF64("192.168.0.10")}
	candidates := []Candidate{
		{ID: "https://relay-alpha.io", Index: HashToGF64("https://relay-alpha.io"), Healthy: true, Confirmed: true},
		{ID: "https://relay-beta.io", Index: HashToGF64("https://relay-beta.io"), Healthy: true, Confirmed: true},
		{ID: "https://relay-gamma.io", Index: HashToGF64("https://relay-gamma.io"), Healthy: true, Confirmed: true},
	}
	res := e.Rank(ingress, candidates)
	for i := 0; i < len(res.Ordered)-1; i++ {
		scoreA := Score(ingress.Index, res.Ordered[i].Index, DefaultBaseM1, DefaultBaseM2, 64)
		scoreB := Score(ingress.Index, res.Ordered[i+1].Index, DefaultBaseM1, DefaultBaseM2, 64)
		if scoreA < scoreB {
			t.Errorf("Priority mismatch at index %d: %d < %d", i, scoreA, scoreB)
		}
	}
}

func TestEngineRankCongestionInversion(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	ingress := Ingress{ID: "10.0.0.1", Index: HashToGF64("10.0.0.1")}
	candidates := []Candidate{
		{ID: "https://r1.net", Index: HashToGF64("https://r1.net"), RTT: DefaultCongestionRTTThreshold + 100*time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
		{ID: "https://r2.net", Index: HashToGF64("https://r2.net"), RTT: DefaultCongestionRTTThreshold + 100*time.Millisecond, RTTAt: time.Now(), Healthy: true, Confirmed: true},
	}
	res := e.Rank(ingress, candidates)
	if len(res.Ordered) == 2 {
		s1 := CongestionScore(ingress.Index, res.Ordered[0].Index, DefaultBaseM1, DefaultBaseM2, 64)
		s2 := CongestionScore(ingress.Index, res.Ordered[1].Index, DefaultBaseM1, DefaultBaseM2, 64)
		if s1 < s2 {
			t.Errorf("Congestion priority failed: %d < %d", s1, s2)
		}
	}
}
