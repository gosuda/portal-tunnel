# Relay Route Selection: Architectural Evaluation (MOLS vs. Rendezvous Hashing)

This document provides a comparative analysis of relay selection algorithms evaluated for `portal-tunnel`:
1. **MOLS (Mutually Orthogonal Latin Squares)**: Dynamic finite-field combinatorial grid allocation.
2. **HRW (Highest Random Weight / Rendezvous Hashing)**: Independent pseudo-random weight mapping ($W = \text{hash}(c, r)$).

Both algorithms were evaluated under identical synthetic network conditions to measure load distribution, failure isolation, and operational overhead.

---

## 1. Algorithm Overview & Core Hypotheses

### MOLS (Mutually Orthogonal Latin Squares)
- **Concept**: Arranges relays and clients into an $N \times N$ discrete grid where $N$ is the candidate pool size. Multipliers $(m_1, m_2)$ coprime to $N$ form two orthogonal Latin squares to assign coordinates to relays.
- **Design Intent**: Seeks mathematically exact uniform dispersion across both primary and secondary candidate slots, minimizing initial load variance across static topologies.
- **Hypothesis**: Given a known, relatively stable cluster, combinatorial orthogonality provides provable deterministic spreading without relying on probabilistic hashing balance.

### HRW (Highest Random Weight / Rendezvous Hashing)
- **Concept**: Evaluates an independent 64-bit pseudo-random weight function $W(c, r) = \text{hash}(c \mathbin{\Vert} r)$ for every client-relay pair and sorts descending.
- **Design Intent**: Prioritizes monotonicity (minimal disruption) and robustness in asynchronous, gossip-based discovery environments where candidate pools change dynamically.
- **Hypothesis**: A stateless volunteer network experiences frequent membership changes ($N \to N-1$). Monotonicity ($1/N$ migration) prevents global reconnection storms and provides robust degradation regardless of whether nodes share a consistent view of $N$.

---

## 2. Empirical Benchmark Results

Evaluated across 700 synthetic clients on 7 relays ($N = 7$), as well as even non-prime orders ($N = 6$):

| Scenario & Metric | Baseline MOLS (`main`) | Dual-Orthogonal MOLS (PR #354) | HRW Rendezvous (PR #356) |
| :--- | :---: | :---: | :---: |
| **Primary Load Distribution** ($N=7$, 700 clients)<br>*(Min ~ Max, Ideal: 100 / 14.3%)* | 98 ~ 103 (Peak: 14.7%) | 82 ~ 118 (Peak: 16.9%) | 90 ~ 110 (Peak: 15.7%) |
| **Primary Chi-Square Statistic ($\chi^2$)**<br>*(Lower indicates closer to uniform)* | **0.16** | 7.78 | 4.74 |
| **Secondary Herd Concentration**<br>*(Busiest primary node drops; 2nd-place distribution)* | **1 node (100.0% stampede)**<br>❌ Total herd collapse | 6 nodes (Max share: 28.8%)<br>✅ Orthogonally dispersed | 6 nodes (Max share: 20.9%)<br>✅ Statistically dispersed |
| **Unaffected Client Reshuffle on Node Drop**<br>*($N=7 \to N=6$, clients not on dropped node)* | **82.4% reshuffled** (492 / 597)<br>❌ Cascading churn | **81.1% reshuffled** (472 / 582)<br>❌ Cascading churn | **0.0% reshuffled (0 / 590)**<br>✅ Zero unnecessary churn |
| **Even Order Performance ($N=6$, Euler Order)**<br>*(600 clients across 6 relays)* | **300:300 (50.0% peak share)**<br>❌ Euler modulo collapse | 93 ~ 106 (Peak: 17.7%)<br>✅ Handled by fallback | 82 ~ 110 (Peak: 18.3%)<br>✅ Native uniform spread |
| **Microbenchmark Execution Speed ($K=10$)** | **291 ns/op** | 291 ns/op | 1,106 ns/op |
| **Code Footprint & Mathematical Complexity** | High (coprime search, GCD, grid mapping) | High (dual targets, cross-distance bonus) | **Low (single hash & sort)** |

---

## 3. Comparative Trade-offs

### A. Stability Under Dynamic Topology ($N \to N \pm 1$)
- **MOLS**: Because grid coordinates are computed modulo $N$, adding or removing a single relay shifts the entire coordinate space. Over $80\%$ of unaffected clients change their primary relay, causing widespread connection churn.
- **HRW**: Guarantees the **monotonicity property**. When relay $k$ drops, only clients connected to $k$ migrate to their respective second choices. Unaffected clients experience **0% churn**.

### B. Gossip Discovery & Eventual Consistency
- **MOLS**: Requires all participants to share an identical view of $N$ and relay sorting order. If client A discovers 10 relays and client B discovers 9 relays, their coordinate frames diverge completely.
- **HRW**: Evaluates pairwise affinity $h(c, r)$. If two clients share a subset of relays, the relative ranking of those relays is invariant to the total pool size.

### C. Load Uniformity vs. Execution Cost
- **MOLS**: Achieves near-ideal uniform distribution ($\chi^2 = 0.16$) on fixed prime orders and executes in sub-microsecond time ($\approx 290\text{ ns}$).
- **HRW**: Exhibits slightly higher statistical variance ($\chi^2 = 4.74$) and higher CPU cost ($\approx 1,100\text{ ns}$ due to $K$ hash invocations). In practice, route planning occurs at tunnel establishment rather than per-packet, making the $0.8\,\mu\text{s}$ difference negligible against wire latency.

---

## 4. References

1. Thaler, D. G., & Ravishankar, C. V. (1998). *Using name-based mappings to increase hit rates*. IEEE/ACM Transactions on Networking, 6(1), 1-14.
2. Karger, D., Lehman, E., Leighton, T., Panigrahy, R., Levine, M., & Lewin, D. (1997). *Consistent hashing and random trees: Distributed caching protocols for relieving hot spots on the World Wide Web*. ACM STOC.
3. Bose, R. C., Shrikhande, S. S., & Parker, E. T. (1960). *Further results on the construction of mutually orthogonal Latin squares and the falsity of Euler's conjecture*. Canadian Journal of Mathematics, 12, 189-203.
4. Raghavarao, D. (1971). *Constructions and Combinatorial Problems in Design of Experiments*. John Wiley & Sons.
