package mols

// Score computes the base MOLS score for a given ingress row and candidate column.
// It is exported so callers can reconstruct per-candidate scores for telemetry
// without duplicating the scoring logic.
func Score(ingressIdx, candidateIdx uint8, m1, m2 uint8, order int) int {
	return molsScore(int(ingressIdx)%order, int(candidateIdx)%order, int(m1), int(m2), order)
}

// CongestionScore returns the Reverse-Siamese complement of the base score.
func CongestionScore(ingressIdx, candidateIdx uint8, m1, m2 uint8, order int) int {
	return molsCongestionScore(int(ingressIdx)%order, int(candidateIdx)%order, int(m1), int(m2), order)
}

// molsScore computes the base MOLS score for a given ingress row i and
// candidate column j.  For order == 64 the computation uses GF(64);
// otherwise a linear-congruence fallback preserves deterministic uniqueness.
func molsScore(i, j, m1, m2, order int) int {
	if order == 64 {
		l1 := gf64Mul(uint8(m1), uint8(i)) ^ uint8(j)
		l2 := gf64Mul(uint8(m2), uint8(i)) ^ uint8(j)
		return int(l1)*order + int(l2) + 1
	}
	return ((m1*i+j)%order)*order + ((m2*i + j) % order) + 1
}

// molsCongestionScore returns the Reverse-Siamese complement of the base score.
func molsCongestionScore(i, j, m1, m2, order int) int {
	return (order*order + 1) - molsScore(i, (order-1)-j, m1, m2, order)
}
