package mols

import "testing"

func TestGF64MulIdentity(t *testing.T) {
	for i := range uint8(64) {
		if got := gf64Mul(1, i); got != i {
			t.Fatalf("gf64Mul(1, %d) = %d, want %d", i, got, i)
		}
		if got := gf64Mul(i, 1); got != i {
			t.Fatalf("gf64Mul(%d, 1) = %d, want %d", i, got, i)
		}
	}
}

func TestGF64MulZero(t *testing.T) {
	for i := range uint8(64) {
		if got := gf64Mul(0, i); got != 0 {
			t.Fatalf("gf64Mul(0, %d) = %d, want 0", i, got)
		}
	}
}

func TestGF64MulCommutativity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			if gf64Mul(a, b) != gf64Mul(b, a) {
				t.Fatalf("gf64Mul(%d, %d) != gf64Mul(%d, %d)", a, b, b, a)
			}
		}
	}
}

func TestGF64MulDistributivity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			for c := range uint8(8) {
				want := gf64Mul(a, b) ^ gf64Mul(a, c)
				got := gf64Mul(a, b^c)
				if got != want {
					t.Fatalf("gf64Mul(%d, %d^%d) = %d, want %d", a, b, c, got, want)
				}
			}
		}
	}
}

func TestHashToGF64InRange(t *testing.T) {
	inputs := []string{"", "a", "hello", "0x1234", "https://relay.example", "🔑"}
	for _, s := range inputs {
		v := hashToGF64(s)
		if v >= DefaultOrder {
			t.Fatalf("hashToGF64(%q) = %d, want < %d", s, v, DefaultOrder)
		}
	}
}
