package mols

// gf64Mul performs multiplication in GF(2^6) with primitive polynomial x^6 + x + 1 (0x43).
func gf64Mul(a, b uint8) uint8 {
	a &= 0x3f
	b &= 0x3f
	var r uint8
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		if a&0x20 != 0 {
			a = ((a << 1) ^ 0x43) & 0x3f
		} else {
			a = (a << 1) & 0x3f
		}
		b >>= 1
	}
	return r
}

// gridOrderForSize returns the smallest supported MOLS grid order (64, 96, 128, ...)
// that can accommodate the relay pool size.  For orders above 64 we scale in
// increments of 32 and fall back to a linear-congruence score path.
func gridOrderForSize(poolSize int) int {
	if poolSize <= 64 {
		return 64
	}
	rem := poolSize % 32
	if rem == 0 {
		return poolSize
	}
	return poolSize + (32 - rem)
}

// hashToGF64 returns a deterministic value in [0, 63] for the input string.
func hashToGF64(s string) uint8 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return uint8(h & 0x3f)
}
