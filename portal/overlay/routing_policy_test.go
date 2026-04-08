package overlay

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
)

func TestReverseSiameseComplementMirror(t *testing.T) {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	reverse := deriveReverseSiameseGrid(magic)
	complementConst := uint16(len(magic) + 1)

	row, col := 17, 9
	mirroredCol := molsSize - 1 - col
	got := reverse[row*molsSize+col]
	want := complementConst - magic[row*molsSize+mirroredCol]
	if got != want {
		t.Fatalf("reverse-siamese mismatch: got %d want %d", got, want)
	}
}

func TestBuildRouteSwitchesOnCongestion(t *testing.T) {
	p := NewRoutePolicy()
	candidates := []uint32{101, 102, 103, 104, 105}

	normal, err := p.BuildRouteWithLoad(42, candidates, 3, policy.NodeLoad{AvgLatencyMs: 20}, 100)
	if err != nil {
		t.Fatalf("normal route error: %v", err)
	}
	congested, err := p.BuildRouteWithLoad(42, candidates, 3, policy.NodeLoad{AvgLatencyMs: 180}, 100)
	if err != nil {
		t.Fatalf("congested route error: %v", err)
	}

	if len(normal) != 4 || len(congested) != 4 {
		t.Fatalf("unexpected route length normal=%d congested=%d", len(normal), len(congested))
	}

	if normal[0] != 42 || congested[0] != 42 {
		t.Fatalf("ingress must be first hop")
	}

	same := true
	for i := range normal {
		if normal[i] != congested[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("expected congestion route switch, got same route: %v", normal)
	}
}

func TestBuildRouteRejectsEmptyCandidates(t *testing.T) {
	p := NewRoutePolicy()
	_, err := p.BuildRoute(1, nil, 1, false)
	if err == nil {
		t.Fatal("expected error for empty candidates")
	}
}

func TestMagicOrthogonalLatinGridIsMagicSquare(t *testing.T) {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	if !isMagicSquare(magic) {
		t.Fatal("grid lost magic square invariants")
	}
}

func TestVariantGridIsMagicSquare(t *testing.T) {
	variant := buildMagicOrthogonalLatinGrid(variantMultiplierA, variantMultiplierB)
	if !isMagicSquare(variant) {
		t.Fatal("variant grid (non-linear load) lost magic square invariants")
	}
}

func TestUpdateNodeHealthAndActiveCount(t *testing.T) {
	p := NewRoutePolicy()
	p.UpdateNodeHealth(10, policy.RelayHealth{Healthy: true, PingLatencyMs: 5})
	p.UpdateNodeHealth(20, policy.RelayHealth{Healthy: true, PingLatencyMs: 8})
	p.UpdateNodeHealth(30, policy.RelayHealth{Healthy: false, PingLatencyMs: 200})

	if got := p.ActiveNodeCount(); got != 3 {
		t.Fatalf("ActiveNodeCount: got %d want 3", got)
	}
}

func TestMarkSlowFallbackEnforcesMinimum(t *testing.T) {
	p := NewRoutePolicy()
	// Register exactly minTopologyNodes active nodes.
	p.UpdateNodeHealth(1, policy.RelayHealth{Healthy: true, PingLatencyMs: 10})
	p.UpdateNodeHealth(2, policy.RelayHealth{Healthy: true, PingLatencyMs: 10})

	// Attempting to demote when only minTopologyNodes are active must be refused.
	if p.MarkSlowFallback(1) {
		t.Fatal("expected MarkSlowFallback to refuse – would violate min-2-nodes")
	}
	if p.ActiveNodeCount() != 2 {
		t.Fatal("active count must remain 2 after refused demotion")
	}

	// Add a third node, then demotion of one should succeed.
	p.UpdateNodeHealth(3, policy.RelayHealth{Healthy: true, PingLatencyMs: 10})
	if !p.MarkSlowFallback(1) {
		t.Fatal("expected MarkSlowFallback to succeed with 3 active nodes")
	}
	if p.ActiveNodeCount() != 2 {
		t.Fatalf("expected 2 active nodes after demotion, got %d", p.ActiveNodeCount())
	}
}

func TestMarkSlowFallbackIdempotent(t *testing.T) {
	p := NewRoutePolicy()
	p.UpdateNodeHealth(1, policy.RelayHealth{Healthy: true, PingLatencyMs: 5})
	p.UpdateNodeHealth(2, policy.RelayHealth{Healthy: true, PingLatencyMs: 5})
	p.UpdateNodeHealth(3, policy.RelayHealth{Healthy: true, PingLatencyMs: 5})

	if !p.MarkSlowFallback(1) {
		t.Fatal("first demotion must succeed")
	}
	// Second call on same node: already fallback, must return false.
	if p.MarkSlowFallback(1) {
		t.Fatal("second demotion of same node must return false")
	}
}

func TestFallbackNodesAreScoredLast(t *testing.T) {
	p := NewRoutePolicy()
	// Mark node 200 as fallback, nodes 101-105 are active.
	p.UpdateNodeHealth(200, policy.RelayHealth{Healthy: true, PingLatencyMs: 1, Fallback: true})
	for _, id := range []uint32{101, 102, 103, 104, 105} {
		p.UpdateNodeHealth(id, policy.RelayHealth{Healthy: true, PingLatencyMs: 10})
	}

	candidates := []uint32{101, 102, 103, 200, 104}
	route, err := p.BuildRoute(42, candidates, 4, false)
	if err != nil {
		t.Fatalf("BuildRoute error: %v", err)
	}
	// Node 200 should be last among the chosen hops if it appears at all.
	for i, hop := range route[1:] {
		if hop == 200 && i < len(route)-2 {
			t.Fatalf("fallback node 200 appeared at position %d before non-fallback nodes", i+1)
		}
	}
}

func TestNonLinearLoadUsesVariantGrid(t *testing.T) {
	p := NewRoutePolicy()
	// Register nodes with highly skewed latencies (CV >> 0.5) to trigger
	// non-linear detection.
	p.UpdateNodeHealth(100, policy.RelayHealth{Healthy: true, PingLatencyMs: 1})
	p.UpdateNodeHealth(200, policy.RelayHealth{Healthy: true, PingLatencyMs: 1000})

	candidates := []uint32{100, 200, 300, 400, 500}
	normal, err := p.BuildRoute(42, candidates, 3, false)
	if err != nil {
		t.Fatalf("normal route: %v", err)
	}

	// Without skewed nodes the same ingress/candidates/congested=false path
	// must use the magic grid.
	p2 := NewRoutePolicy()
	for _, id := range candidates {
		p2.UpdateNodeHealth(id, policy.RelayHealth{Healthy: true, PingLatencyMs: 10})
	}
	uniform, err := p2.BuildRoute(42, candidates, 3, false)
	if err != nil {
		t.Fatalf("uniform route: %v", err)
	}

	same := true
	for i := range normal {
		if normal[i] != uniform[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("expected non-linear route to differ from uniform route: %v", normal)
	}
}

func TestHeaderEncodeDecodeRoundTrip(t *testing.T) {
	h := Header{
		Version:    Version,
		Flags:      FlagKeepalive,
		MsgType:    Data,
		ErrorCode:  0,
		RouteID:    0xDEADBEEF,
		FlowID:     0xCAFEBABE,
		TTL:        10,
		MaxHops:    5,
		SrcNode:    0x11223344,
		DstNode:    0x55667788,
		BodyLength: 5, // set to match body length for comparison
	}
	body := []byte("hello")
	packet := Encode(h, body)
	if len(packet) != headerSize+len(body) {
		t.Fatalf("encoded size %d, want %d", len(packet), headerSize+len(body))
	}

	got, gotBody, err := Decode(packet)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if got != h {
		t.Fatalf("decoded header mismatch: got %+v want %+v", got, h)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("decoded body mismatch: got %q want %q", gotBody, body)
	}
}

func TestKeepaliveHeaderHasFlag(t *testing.T) {
	// Verify that Encode/Decode preserves FlagKeepalive without a live connection.
	h := Header{Version: Version, Flags: FlagKeepalive, MsgType: Keepalive, TTL: 1}
	pkt := Encode(h, nil)
	decoded, _, err := Decode(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Flags&FlagKeepalive == 0 {
		t.Fatal("FlagKeepalive not set in decoded keepalive header")
	}
}

func TestErrorCodeInHeader(t *testing.T) {
	h := Header{
		Version:   Version,
		MsgType:   Error,
		ErrorCode: ErrorTTLExpired,
		RouteID:   1,
		FlowID:    2,
		TTL:       32,
	}
	pkt := Encode(h, []byte{0, 0, 0, 99}) // 4-byte nodeID body
	decoded, body, err := Decode(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.ErrorCode != ErrorTTLExpired {
		t.Fatalf("ErrorCode: got %d want %d", decoded.ErrorCode, ErrorTTLExpired)
	}
	if len(body) != 4 {
		t.Fatalf("body length: got %d want 4", len(body))
	}
}
