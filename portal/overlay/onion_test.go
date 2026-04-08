package overlay

import (
	"bytes"
	"errors"
	"testing"
)

func TestOnionBuildAndPeel(t *testing.T) {
	route := []uint32{10, 20, 30, 40}
	keys, err := DeriveOnionKeys([]byte("seed-123"), len(route)-1, "test-route")
	if err != nil {
		t.Fatalf("DeriveOnionKeys() error = %v", err)
	}
	payload := []byte("secret-payload")
	onion, err := BuildOnionPayload(route, keys, payload, 10)
	if err != nil {
		t.Fatalf("BuildOnionPayload() error = %v", err)
	}

	layer := onion
	for i := 0; i < len(route)-1; i++ {
		next, ttl, inner, err := PeelOnionLayer(keys[i], layer)
		if err != nil {
			t.Fatalf("PeelOnionLayer(%d) error = %v", i, err)
		}
		if ttl != uint8(10-i) {
			t.Fatalf("ttl mismatch hop=%d got=%d want=%d", i, ttl, 10-i)
		}
		var wantHop uint32
		if i+2 < len(route) {
			wantHop = route[i+2]
		}
		if next != wantHop {
			t.Fatalf("next hop mismatch hop=%d got=%d want=%d", i, next, wantHop)
		}
		layer = inner
	}
	if !bytes.Equal(layer, payload) {
		t.Fatalf("payload mismatch got=%x want=%x", layer, payload)
	}
}

func TestOnionTTLTooSmall(t *testing.T) {
	route := []uint32{1, 2, 3}
	keys, err := DeriveOnionKeys([]byte("seed"), len(route)-1, "ttl")
	if err != nil {
		t.Fatalf("DeriveOnionKeys() error = %v", err)
	}
	if _, err := BuildOnionPayload(route, keys, []byte("data"), 1); !errors.Is(err, ErrTTLTooSmall) {
		t.Fatalf("expected ErrTTLTooSmall, got %v", err)
	}
}

func TestOnionIntegrity(t *testing.T) {
	route := []uint32{2, 3}
	keys, err := DeriveOnionKeys([]byte("seed"), len(route)-1, "integrity")
	if err != nil {
		t.Fatalf("DeriveOnionKeys() error = %v", err)
	}
	onion, err := BuildOnionPayload(route, keys, []byte("payload"), 5)
	if err != nil {
		t.Fatalf("BuildOnionPayload() error = %v", err)
	}
	onion[5] ^= 0xFF
	if _, _, _, err := PeelOnionLayer(keys[0], onion); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expected ErrIntegrity, got %v", err)
	}
}
