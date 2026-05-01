package pepper

import (
	"bytes"
	"testing"
)

func TestActiveCircuitRotatesIdentityAndSessionKey(t *testing.T) {
	first, err := NewActiveCircuit()
	if err != nil {
		t.Fatalf("new first circuit: %v", err)
	}
	defer first.Close()

	firstID := first.ID()
	firstPublic := first.PublicKey()
	firstKey := first.SessionKey()
	defer Zero(firstKey)

	second, err := NewActiveCircuit()
	if err != nil {
		t.Fatalf("new second circuit: %v", err)
	}
	defer second.Close()

	secondKey := second.SessionKey()
	defer Zero(secondKey)

	if firstID == 0 || second.ID() == 0 {
		t.Fatal("circuit id must be set")
	}
	if firstID == second.ID() {
		t.Fatal("circuit id did not rotate")
	}
	if firstPublic == second.PublicKey() {
		t.Fatal("x25519 public key did not rotate")
	}
	if bytes.Equal(firstKey, secondKey) {
		t.Fatal("session key did not rotate")
	}
}

func TestActiveCircuitCloseZeroesAndInvalidatesState(t *testing.T) {
	circuit, err := NewActiveCircuit()
	if err != nil {
		t.Fatalf("new circuit: %v", err)
	}
	if circuit.SessionKey() == nil {
		t.Fatal("session key missing before close")
	}

	if err := circuit.Close(); err != nil {
		t.Fatalf("close circuit: %v", err)
	}
	if circuit.ID() != 0 {
		t.Fatal("circuit id still set after close")
	}
	if circuit.SessionKey() != nil {
		t.Fatal("session key still available after close")
	}
	if circuit.PublicKey() != ([32]byte{}) {
		t.Fatal("public key still available after close")
	}
}
