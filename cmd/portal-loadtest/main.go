// Command portal-loadtest is a Phase 1 uniformity probe that measures
// how evenly MOLS relay selection distributes N synthetic clients
// across K synthetic relays. It runs entirely in-process — no running
// portal-tunnel server is required.
//
// Flags (Phase 1 only — -capacities and -selector are Phase 2):
//
//	-clients N      number of synthetic clients (default 100)
//	-relays  K      number of synthetic relays (default 5)
//
// Output: per-relay top-pick histogram, chi-square statistic against the
// uniform expected distribution N/K, and a p-value.
//
// P-value method: regularized upper incomplete gamma function Q(k/2, x/2),
// implemented via the series expansion (|x| < s+1) and continued-fraction
// expansion (x ≥ s+1) from Numerical Recipes §6.2. This gives accurate
// results even at small df values (e.g. df=4 for K=5).
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func main() {
	clients := flag.Int("clients", 100, "number of synthetic clients")
	relays := flag.Int("relays", 5, "number of synthetic relays")
	flag.Parse()

	if *clients <= 0 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -clients must be > 0")
		os.Exit(1)
	}
	if *relays <= 0 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -relays must be > 0")
		os.Exit(1)
	}
	now := time.Now().UTC()
	relayStates := make([]discovery.RelayState, *relays)
	for i := range relayStates {
		relayURL := fmt.Sprintf("https://test-relay-%d.example", i+1)
		rs := discovery.RelayState{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: relayURL,
			},
			LastSeenAt: now,
		}
		rs.Descriptor.IssuedAt = now
		rs.Descriptor.ExpiresAt = now.Add(24 * time.Hour)
		relayStates[i] = rs
	}

	// Generate N synthetic client states with UNIQUE LocalAddress values.
	// MOLS is deterministic on (LocalAddress, relayURL): duplicate addresses
	// would make all clients pick identically, falsely appearing as 100% imbalance.
	picks := make(map[string]int, *relays) // relay URL → count of clients that picked it first
	for i := 0; i < *clients; i++ {
		localAddr := fmt.Sprintf("synthetic-client-%d", i)
		outputURLs := discovery.RankRelayPool(relayStates, localAddr, 0)
		if len(outputURLs) == 0 {
			// All relays were filtered; skip this client.
			continue
		}
		picks[outputURLs[0]]++
	}

	// Collect and sort relay URLs for deterministic output.
	relayURLs := make([]string, 0, *relays)
	for i := range relayStates {
		relayURLs = append(relayURLs, relayStates[i].Descriptor.APIHTTPSAddr)
	}
	sort.Strings(relayURLs)

	expected := float64(*clients) / float64(*relays)

	// Chi-square statistic: Σ (observed - expected)^2 / expected
	var chi2 float64
	for _, url := range relayURLs {
		obs := float64(picks[url])
		diff := obs - expected
		chi2 += diff * diff / expected
	}

	df := *relays - 1

	// P-value: P(χ² > chi2 | df) = Q(df/2, chi2/2) = igamc(df/2, chi2/2)
	// using the regularized upper incomplete gamma function.
	pval := igamc(float64(df)/2.0, chi2/2.0)

	// Print results.
	header := fmt.Sprintf("portal-loadtest: N=%d clients, K=%d relays, mode=mols", *clients, *relays)
	fmt.Println(header)
	fmt.Printf("%-45s %6s  %8s\n", "relay", "picks", "expected")
	fmt.Println("---------------------------------------------------------------")
	for _, url := range relayURLs {
		fmt.Printf("%-45s %6d  %8.1f\n", url, picks[url], expected)
	}
	fmt.Printf("\nchi-square: %.4f\n", chi2)
	fmt.Printf("df: %d\n", df)
	fmt.Printf("p-value: %.4f\n", pval)
}

// igamc returns the regularized upper incomplete gamma function Q(s, x),
// also written Γ(s, x) / Γ(s). This equals 1 - P(s, x) where P(s, x) is
// the regularized lower incomplete gamma.
//
// For s < x+1 the continued-fraction expansion converges faster; otherwise
// the series expansion is used. Algorithm from Numerical Recipes §6.2
// (Press et al.). Accurate to ~1e-7 for the parameter ranges used here
// (s = df/2 ≥ 0.5, x = chi2/2 ≥ 0).
func igamc(s, x float64) float64 {
	if x < 0 || s <= 0 {
		return 1.0
	}
	if x == 0 {
		return 1.0
	}

	if x < s+1 {
		// Series expansion for the lower incomplete gamma P(s, x);
		// return Q = 1 - P.
		return 1.0 - gamSer(s, x)
	}
	// Continued-fraction expansion for Q(s, x) directly.
	return gamCF(s, x)
}

// gamSer computes P(s, x) via a series expansion. P(s, x) = e^(-x) * x^s *
// Σ_{n=0}^∞  x^n / Γ(s+n+1).
func gamSer(s, x float64) float64 {
	const maxIter = 200
	const eps = 3e-7

	ap := s
	del := 1.0 / s
	sum := del
	for range maxIter {
		ap++
		del *= x / ap
		sum += del
		if math.Abs(del) < math.Abs(sum)*eps {
			return sum * math.Exp(-x+s*math.Log(x)-lgamma(s))
		}
	}
	// Did not converge; return best estimate.
	return sum * math.Exp(-x+s*math.Log(x)-lgamma(s))
}

// gamCF computes Q(s, x) via a modified Lentz continued-fraction expansion.
func gamCF(s, x float64) float64 {
	const maxIter = 200
	const eps = 3e-7
	const fpMin = 1e-300

	b := x + 1.0 - s
	c := 1.0 / fpMin
	d := 1.0 / b
	h := d
	for i := 1; i <= maxIter; i++ {
		an := -float64(i) * (float64(i) - s)
		b += 2.0
		d = an*d + b
		if math.Abs(d) < fpMin {
			d = fpMin
		}
		c = b + an/c
		if math.Abs(c) < fpMin {
			c = fpMin
		}
		d = 1.0 / d
		del := d * c
		h *= del
		if math.Abs(del-1.0) < eps {
			break
		}
	}
	return math.Exp(-x+s*math.Log(x)-lgamma(s)) * h
}

// lgamma returns the natural log of the Gamma function using the standard
// library, which is accurate for all positive real inputs.
func lgamma(x float64) float64 {
	lg, _ := math.Lgamma(x)
	return lg
}
