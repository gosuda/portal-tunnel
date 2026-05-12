package mols

import "testing"

func TestMOLSScoreRange(t *testing.T) {
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
			if s < 1 || s > 64*64 {
				t.Fatalf("molsScore(%d, %d) = %d, out of range [1, 4096]", i, j, s)
			}
		}
	}
}

func TestMOLSScoreRowPermutation(t *testing.T) {
	for i := range uint8(64) {
		seen := make(map[int]struct{}, 64)
		for j := range uint8(64) {
			s := molsScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d in row i=%d", s, i)
			}
			seen[s] = struct{}{}
		}
		if len(seen) != 64 {
			t.Fatalf("row i=%d has %d unique scores, want %d", i, len(seen), 64)
		}
	}
}

func TestMOLSCongestionScoreRange(t *testing.T) {
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsCongestionScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
			if s < 1 || s > 64*64 {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, out of range", i, j, s)
			}
			want := (64*64 + 1) - molsScore(int(i), (64-1)-int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
			if s != want {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, want %d", i, j, s, want)
			}
		}
	}
}

func TestMOLSMagicRowSum(t *testing.T) {
	const magicSum = DefaultOrder * (DefaultOrder*DefaultOrder + 1) / 2 // 131104
	for i := range uint8(64) {
		var rowSum int
		for j := range uint8(64) {
			rowSum += molsScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		}
		if rowSum != magicSum {
			t.Fatalf("row i=%d sum = %d, want %d", i, rowSum, magicSum)
		}
	}
}

func TestMOLSMagicColumnSum(t *testing.T) {
	const magicSum = 64 * (64*64 + 1) / 2
	for j := range uint8(64) {
		var colSum int
		for i := range uint8(64) {
			colSum += molsScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
		}
		if colSum != magicSum {
			t.Fatalf("column j=%d sum = %d, want %d", j, colSum, magicSum)
		}
	}
}

func TestMOLSGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, 64*64)
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(int(i), int(j), int(DefaultBaseM1), int(DefaultBaseM2), 64)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d)", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != DefaultOrder*DefaultOrder {
		t.Fatalf("grid has %d unique values, want %d", len(seen), DefaultOrder*DefaultOrder)
	}
}

func TestMOLSVariantGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, 64*64)
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(int(i), int(j), int(DefaultVariantM1), int(DefaultVariantM2), 64)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d) in variant grid", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != DefaultOrder*DefaultOrder {
		t.Fatalf("variant grid has %d unique values, want %d", len(seen), DefaultOrder*DefaultOrder)
	}
}
