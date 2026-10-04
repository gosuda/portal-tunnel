package zonecache

import "testing"

func TestCandidates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		domain    string
		want      string
		wantCands []string
	}{
		{
			name:      "nested",
			domain:    "A.B.Example.COM.",
			want:      "a.b.example.com",
			wantCands: []string{"a.b.example.com", "b.example.com", "example.com"},
		},
		{
			name:      "apex",
			domain:    "example.com",
			want:      "example.com",
			wantCands: []string{"example.com"},
		},
		{name: "single label", domain: "localhost", want: "localhost"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, candidates := Candidates(tc.domain)
			if got != tc.want {
				t.Fatalf("Candidates(%q) normalized = %q, want %q", tc.domain, got, tc.want)
			}
			if len(candidates) != len(tc.wantCands) {
				t.Fatalf("Candidates(%q) = %v, want %v", tc.domain, candidates, tc.wantCands)
			}
			for i := range candidates {
				if candidates[i] != tc.wantCands[i] {
					t.Fatalf("Candidates(%q) = %v, want %v", tc.domain, candidates, tc.wantCands)
				}
			}
		})
	}
}

// The zone hosting the most specific matching candidate wins, and stored keys
// must be reachable from the normalized candidate space.
func TestLookupPrefersMostSpecificCandidate(t *testing.T) {
	t.Parallel()

	c := New()
	c.Set("Example.COM.", "z-apex")
	c.Set("b.example.com", "z-b")

	value, key, ok := c.Lookup([]string{"a.b.example.com", "b.example.com", "example.com"})
	if !ok || value != "z-b" || key != "b.example.com" {
		t.Fatalf("Lookup() = (%q, %q, %v), want (%q, %q, true)", value, key, ok, "z-b", "b.example.com")
	}

	value, key, ok = c.Lookup([]string{"a.example.com", "example.com"})
	if !ok || value != "z-apex" || key != "example.com" {
		t.Fatalf("Lookup() = (%q, %q, %v), want (%q, %q, true)", value, key, ok, "z-apex", "example.com")
	}
}

func TestCacheIgnoresEmptyKeysAndValues(t *testing.T) {
	t.Parallel()

	c := New()
	c.Set("", "z-empty-key")
	c.Set("example.com", "")
	c.Merge(map[string]string{"": "z-empty-key", "b.example.com": ""})

	if _, _, ok := c.Lookup([]string{"example.com", "b.example.com"}); ok {
		t.Fatal("Lookup() hit entries with empty keys or values")
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()

	c := New()
	c.Set("kept.example.com", "z-kept")
	c.Merge(map[string]string{
		"Example.COM.":     "z-apex",
		"b.example.com":    "z-b",
		"skip.example.com": "",
	})

	testCases := []struct {
		candidate string
		want      string
	}{
		{candidate: "b.example.com", want: "z-b"},
		{candidate: "example.com", want: "z-apex"},
		{candidate: "kept.example.com", want: "z-kept"},
		{candidate: "skip.example.com"},
	}
	for _, tc := range testCases {
		value, _, ok := c.Lookup([]string{tc.candidate})
		if tc.want == "" {
			if ok {
				t.Fatalf("Lookup(%q) = %q, want miss", tc.candidate, value)
			}
			continue
		}
		if !ok || value != tc.want {
			t.Fatalf("Lookup(%q) = (%q, %v), want (%q, true)", tc.candidate, value, ok, tc.want)
		}
	}
}
