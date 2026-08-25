package vultr

import "testing"

// Registrars reject SHA-1 DS records; the SHA-256 digest must be preferred
// whenever the zone publishes both.
func TestPreferredDSRecordPrefersSHA256(t *testing.T) {
	t.Parallel()

	got := preferredDSRecord([]string{
		"example.com IN DNSKEY 257 3 13 abc",
		"example.com IN DS 27933 13 1 2d9ac457e5c11a104e25d971d0a6254562bddde7",
		"example.com IN DS 27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9",
	})
	if got != "27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9" {
		t.Fatalf("preferredDSRecord() = %q", got)
	}
}
