// Command portal-loadtest is a Phase 1/2/3 uniformity probe that measures
// how evenly a relay-selection policy distributes N synthetic clients
// across K synthetic relays. It runs entirely in-process — no running
// portal-tunnel server is required.
//
// Flags:
//
//	-clients N            number of synthetic clients (default 100)
//	-relays  K            number of synthetic relays (default 5)
//	-multi-hop D          multi-hop depth (0 = priority/single-hop; ≥2 = multi-hop)
//	-selector mols|weighted  selector to test (default mols)
//	-capacities w1,...,wK per-relay capacity weights (default: all 1.0)
//	-lambda <float>       lambda for weighted selector (default 1.0)
//	-anonymity            enable AnonymityGrade on synthetic clients (opt-in /16+family diversity)
//	-anonymity-collide    put all relays in the same /16 (forces anonymity_grade relaxation)
//
// When -multi-hop > 0, the selector is automatically wrapped in
// diversity.New(selector) so hop-path diversity constraints apply.
//
// Output: per-relay top-pick histogram, chi-square statistic against the
// capacity-weighted expected distribution, p-value, and (when -multi-hop > 0)
// diversity acceptance lines.
//
// P-value method: regularized upper incomplete gamma function Q(k/2, x/2),
// implemented via the series expansion (|x| < s+1) and continued-fraction
// expansion (x ≥ s+1) from Numerical Recipes §6.2. This gives accurate
// results even at small df values (e.g. df=4 for K=5).
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/diversity"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/mols"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/weighted"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// lambdaSeedConstant is the multiplier applied to the saturation-distance
// signal when pre-seeding RelayState.LoadFactor for the weighted selector.
// A value of 5.0 means a relay with 90% capacity gap gets LoadFactor=4.5,
// which (with lambda=1.0) adds 4.5 to its final score — exceeding the
// maximum MOLS position spread of K-1=4 for K=5 relays.
const lambdaSeedConstant = 5.0

func main() {
	clients := flag.Int("clients", 100, "number of synthetic clients")
	relays := flag.Int("relays", 5, "number of synthetic relays")
	multiHop := flag.Int("multi-hop", 0, "multi-hop depth (0 = priority; ≥2 = multi-hop)")
	selectorName := flag.String("selector", "mols", "selector to test: mols or weighted")
	capacitiesStr := flag.String("capacities", "", "comma-separated per-relay capacity weights (default: all 1.0)")
	lambdaVal := flag.Float64("lambda", 1.0, "lambda weight for weighted selector (ignored for mols)")
	anonymity := flag.Bool("anonymity", false, "enable AnonymityGrade on synthetic clients (opt-in /16+family diversity)")
	anonymityCollide := flag.Bool("anonymity-collide", false, "put all relays in the same /16 (forces anonymity_grade relaxation; implies -anonymity)")
	flag.Parse()

	if *clients <= 0 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -clients must be > 0")
		os.Exit(1)
	}
	if *relays < 2 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -relays must be >= 2 (chi-square requires at least 1 degree of freedom)")
		os.Exit(1)
	}
	// MultiHopDepth ≤ 1 causes SelectMultiHop to return nil.
	// Reject 1 explicitly; 0 means priority mode.
	if *multiHop == 1 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -multi-hop=1 is not valid; use 0 for priority or ≥2 for multi-hop")
		os.Exit(1)
	}
	// -anonymity (without -anonymity-collide) assigns each relay a unique /16
	// in 10.0/16 … 10.255/16, giving 256 distinct buckets. Reject counts above
	// that to avoid silent collisions in the Subnet16 assignment.
	if *anonymity && !*anonymityCollide && *relays > 256 {
		fmt.Fprintln(os.Stderr, "portal-loadtest: -anonymity without -anonymity-collide supports at most 256 relays (unique /16 budget)")
		os.Exit(1)
	}

	// Parse and validate capacities.
	// capacitiesProvided tracks whether the user explicitly supplied -capacities.
	capacities := make([]float64, *relays)
	capacitiesProvided := *capacitiesStr != ""

	if capacitiesProvided {
		parts := strings.Split(*capacitiesStr, ",")
		if len(parts) != *relays {
			fmt.Fprintf(os.Stderr, "portal-loadtest: -capacities has %d values but -relays=%d; counts must match\n", len(parts), *relays)
			os.Exit(1)
		}
		for i, p := range parts {
			v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil || v <= 0 {
				fmt.Fprintf(os.Stderr, "portal-loadtest: -capacities[%d]=%q is not a valid positive number\n", i, p)
				os.Exit(1)
			}
			capacities[i] = v
		}
	} else {
		// Default: all-equal weights → uniform expected distribution.
		for i := range capacities {
			capacities[i] = 1.0
		}
	}

	// Validate selector name.
	switch *selectorName {
	case "mols", "weighted":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "portal-loadtest: -selector=%q is not valid; use mols or weighted\n", *selectorName)
		os.Exit(1)
	}

	mode := "priority"
	if *multiHop >= 2 {
		mode = "multihop"
	}

	// Build K synthetic relay states. We construct discovery.RelayState values
	// directly (not via RelaySet.InsertAnnounced) because the public announce
	// path requires real EVM-signed descriptors. The selector is called directly
	// so that no signature gate runs.
	//
	// For priority mode: states without an observed descriptor (LastSeenAt zero)
	// are accepted into the auto pool by SelectPriorityWithTrace — the
	// expiry/protocol gates only fire when hasObservedDescriptor() is true.
	//
	// For multi-hop mode: SelectMultiHopWithTrace requires hasObservedDescriptor,
	// a non-expired ExpiresAt, and HasOverlayPeer()==true. We populate those
	// fields with dummy-but-valid values using a far-future ExpiresAt and a
	// syntactically valid WireGuard public key placeholder.
	now := time.Now().UTC()
	relayStates := make([]discovery.RelayState, *relays)
	for i := range relayStates {
		relayURL := fmt.Sprintf("https://test-relay-%d.example", i+1)
		rs := discovery.RelayState{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: relayURL,
			},
		}
		if mode == "multihop" {
			// Populate the fields required by SelectMultiHopWithTrace's eligibility
			// gates: hasObservedDescriptor (LastSeenAt non-zero), valid ExpiresAt,
			// and HasOverlayPeer() = SupportsOverlay && WireGuardPublicKey != "" &&
			// WireGuardPort in [1, 65535].
			rs.LastSeenAt = now
			rs.Descriptor.IssuedAt = now
			rs.Descriptor.ExpiresAt = now.Add(24 * time.Hour)
			rs.Descriptor.SupportsOverlay = true
			rs.Descriptor.WireGuardPublicKey = fmt.Sprintf("synthetic-wg-key-%d", i+1)
			rs.Descriptor.WireGuardPort = 51820
		}
		// Assign Subnet16 for anonymity diversity testing.
		// -anonymity-collide: all relays in the same /16 (forces relaxation).
		// -anonymity: each relay in its own /16 (enables clean diversity).
		// Valid second octets are 0–255, so at most 256 unique /16 slots in 10.x.
		// The relay-count guard above already rejects -relays > 256 for this mode.
		if *anonymityCollide {
			rs.Descriptor.Subnet16 = "10.0"
		} else if *anonymity {
			rs.Descriptor.Subnet16 = "10." + strconv.Itoa(i)
		}
		relayStates[i] = rs
	}

	// Pre-seed LoadFactor for weighted selector when non-uniform capacities are
	// provided. High-capacity relays get LoadFactor=0; lower-capacity relays get
	// a proportional penalty so the weighted selector steers traffic toward the
	// most capable relays.
	//
	// Pre-seeding only applies when BOTH conditions hold:
	//   1. -selector=weighted
	//   2. -capacities was explicitly provided (unequal weights intended)
	// When -capacities is omitted, all LoadFactor values stay 0 and weighted
	// degenerates to pure MOLS — matching the mols selector result exactly.
	if *selectorName == "weighted" && capacitiesProvided {
		maxCap := 0.0
		for _, c := range capacities {
			if c > maxCap {
				maxCap = c
			}
		}
		for i := range relayStates {
			// loadSeed ∈ [0, 1]: 0 for the highest-capacity relay, approaching 1
			// for relays furthest from max capacity.
			loadSeed := (maxCap - capacities[i]) / maxCap
			relayStates[i].LoadFactor = lambdaSeedConstant * loadSeed
			relayStates[i].LastUpdated = now
		}
	}

	// Build the selector.
	var policy discovery.Selector
	switch *selectorName {
	case "weighted":
		policy = weighted.New(
			mols.New(),
			weighted.WithLambda(*lambdaVal),
			weighted.WithEpsilon(0.1),
			weighted.WithBeta(1.0),
		)
	default: // "mols"
		policy = mols.New()
	}
	// Wrap in diversity selector for multi-hop mode so hop-path diversity
	// constraints are applied. Priority mode is passed through unchanged.
	if mode == "multihop" {
		policy = diversity.New(policy)
	}

	// -anonymity-collide implies -anonymity (sets AnonymityGrade on clients).
	effectiveAnonymity := *anonymity || *anonymityCollide

	// Generate N synthetic client states with UNIQUE LocalAddress values.
	// MOLS is deterministic on (LocalAddress, relayURL): duplicate addresses
	// would make all clients pick identically, falsely appearing as 100% imbalance.
	ctx := context.Background()
	picks := make(map[string]int, *relays) // relay URL → count of clients that picked it first

	// Per-client path tracking for diversity acceptance checks (multi-hop only).
	dupPathClients := 0       // clients whose path contained a duplicate URL
	subnet16CollidePaths := 0 // clients whose path contained a Subnet16 collision
	stateByURL := make(map[string]discovery.RelayState, *relays)
	for _, rs := range relayStates {
		stateByURL[rs.Descriptor.APIHTTPSAddr] = rs
	}

	for i := 0; i < *clients; i++ {
		cs := discovery.ClientState{
			LocalAddress:  fmt.Sprintf("synthetic-client-%d", i),
			MultiHopDepth: *multiHop,
			// Set MaxActiveRelays to K so all relays are ranked and returned.
			// This is required for the weighted selector to reorder across the full
			// pool — without it MOLS caps output at 3, hiding low-position relays
			// from the weighted penalty step.
			MaxActiveRelays: *relays,
			AnonymityGrade:  effectiveAnonymity,
		}
		var outputURLs []string
		if mode == "multihop" {
			outputURLs, _ = policy.SelectMultiHop(ctx, relayStates, cs)
		} else {
			outputURLs, _ = policy.SelectPriority(ctx, relayStates, cs)
		}
		if len(outputURLs) == 0 {
			// All relays were filtered; skip this client.
			continue
		}
		picks[outputURLs[0]]++

		// Diversity acceptance checks (multi-hop only).
		if mode == "multihop" {
			seenURLs := make(map[string]struct{}, len(outputURLs))
			seenSubnets := make(map[string]struct{}, len(outputURLs))
			hasDup := false
			hasSubnetCollide := false
			for _, u := range outputURLs {
				if _, dup := seenURLs[u]; dup {
					hasDup = true
				}
				seenURLs[u] = struct{}{}
				if rs, ok := stateByURL[u]; ok {
					if s := rs.Descriptor.Subnet16; s != "" {
						if _, dup := seenSubnets[s]; dup {
							hasSubnetCollide = true
						}
						seenSubnets[s] = struct{}{}
					}
				}
			}
			if hasDup {
				dupPathClients++
			}
			if hasSubnetCollide {
				subnet16CollidePaths++
			}
		}
	}

	// Collect and sort relay URLs for deterministic output.
	relayURLs := make([]string, 0, *relays)
	for i := range relayStates {
		relayURLs = append(relayURLs, relayStates[i].Descriptor.APIHTTPSAddr)
	}
	sort.Strings(relayURLs)

	// Build per-relay expected distribution based on capacities.
	// The capacities slice is positional (relay i in relayStates), but the
	// output is sorted by URL. Build a URL→capacity map to look up by sorted URL.
	urlToCapacity := make(map[string]float64, *relays)
	for i := range relayStates {
		urlToCapacity[relayStates[i].Descriptor.APIHTTPSAddr] = capacities[i]
	}

	sumCapacity := 0.0
	for _, w := range capacities {
		sumCapacity += w
	}

	expectedByURL := make(map[string]float64, *relays)
	for _, url := range relayURLs {
		expectedByURL[url] = float64(*clients) * urlToCapacity[url] / sumCapacity
	}

	// Chi-square statistic: Σ (observed - expected)^2 / expected
	var chi2 float64
	for _, url := range relayURLs {
		obs := float64(picks[url])
		exp := expectedByURL[url]
		diff := obs - exp
		chi2 += diff * diff / exp
	}

	df := *relays - 1

	// P-value: P(χ² > chi2 | df) = Q(df/2, chi2/2) = igamc(df/2, chi2/2)
	// using the regularized upper incomplete gamma function.
	pval := igamc(float64(df)/2.0, chi2/2.0)

	// Print results.
	if mode == "multihop" {
		if *selectorName == "weighted" {
			fmt.Printf("selector: weighted+diversity (lambda=%.1f, epsilon=0.1, beta=1.0)\n", *lambdaVal)
		} else {
			fmt.Printf("selector: %s+diversity\n", *selectorName)
		}
	} else {
		if *selectorName == "weighted" {
			fmt.Printf("selector: weighted (lambda=%.1f, epsilon=0.1, beta=1.0)\n", *lambdaVal)
		} else {
			fmt.Printf("selector: %s\n", *selectorName)
		}
	}
	fmt.Printf("clients: %d  relays: %d  mode: %s\n", *clients, *relays, mode)
	if effectiveAnonymity {
		collideNote := ""
		if *anonymityCollide {
			collideNote = " (collide mode: all same /16)"
		}
		fmt.Printf("anonymity-grade: enabled%s\n", collideNote)
	}
	fmt.Println()

	fmt.Printf("%-45s %6s  %8s\n", "relay", "picks", "expected")
	fmt.Println("---------------------------------------------------------------")
	for _, url := range relayURLs {
		fmt.Printf("%-45s %6d  %8.1f\n", url, picks[url], expectedByURL[url])
	}
	fmt.Printf("\nchi-square: %.4f  df: %d  p-value: %.4f\n", chi2, df, pval)

	// Diversity acceptance lines (multi-hop only).
	if mode == "multihop" {
		fmt.Println()
		if dupPathClients == 0 {
			fmt.Println("zero duplicate-relay paths: PASS")
		} else {
			fmt.Printf("zero duplicate-relay paths: FAIL (%d/%d clients had duplicate hops)\n", dupPathClients, *clients)
		}
		if effectiveAnonymity {
			if subnet16CollidePaths == 0 {
				fmt.Println("zero /16 collisions: PASS")
			} else {
				fmt.Printf("zero /16 collisions: FAIL (%d/%d clients had /16 collisions)\n", subnet16CollidePaths, *clients)
			}
		}
		// Print final relaxation event counter values from the Prometheus registry.
		var relaxedAnonymity, relaxedRoleSep float64
		if mfs, err := prometheus.DefaultGatherer.Gather(); err == nil {
			for _, mf := range mfs {
				if mf.GetName() != "portal_discovery_diversity_relaxed_total" {
					continue
				}
				for _, m := range mf.GetMetric() {
					for _, lp := range m.GetLabel() {
						if lp.GetName() != "reason" {
							continue
						}
						switch lp.GetValue() {
						case "anonymity_grade":
							relaxedAnonymity = m.GetCounter().GetValue()
						case "role_separation":
							relaxedRoleSep = m.GetCounter().GetValue()
						}
					}
				}
			}
		}
		fmt.Printf("relaxation event metric: anonymity_grade=%d  role_separation=%d\n",
			int(relaxedAnonymity), int(relaxedRoleSep))
	}
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
	for n := 0; n < maxIter; n++ {
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
