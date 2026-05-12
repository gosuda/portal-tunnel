package mols

// HashToGF64 exports the deterministic GF(64) hash so that callers outside the
// package can pre-compute Candidate.Index and Ingress.Index without duplicating
// the hashing logic.
func HashToGF64(s string) uint8 {
	return hashToGF64(s)
}
