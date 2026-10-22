# Relay behavior: evidence and local responses

This catalog describes the observations Portal currently owns and the decisions
they support. It is not a malicious-relay detector or a network-wide trust score.
Keep it aligned with the owning code when a signal or response changes.

A signature establishes who signed a statement. A direct discovery response
establishes what that endpoint served at that time. Neither establishes honest
forwarding, independent ownership, or the absence of attacks on other clients.
`RelayVerified` has exactly this limited direct-observation meaning.

## Observation ownership and provenance

| Existing owner | Observation and provenance | Limit |
| --- | --- | --- |
| `sdk/mitm.go` | Locally matched/mismatched exporters on an armed self-probe connection | A timeout is inconclusive; a successful sample does not clear unsampled traffic. Explicitly permitted cache TLS termination is not itself malice. #645 owns probe coverage and adaptive evasion. |
| `sdk.Exposure`, `sdk/listener.go` | Local listener readiness, failures, and membership; `discoveryFailureKind` maps local failures to `Controller.Report` | Readiness is not an end-to-end visitor success measurement. Individual proxy stream errors are not automatically per-relay listener failures. |
| `portal/discovery/RelaySet` | Signed descriptors, direct-target promotion, signing-key rollback anchors, local RTT/failure/suppression state | Gossip remains a candidate. Signed capability/load fields remain claims, even after a successful direct poll. |
| `portal/discovery/Refresher` | HTTPS discovery response and locally measured request RTT; protocol mismatch is tracked separately | Discovery RTT includes network/server work and is not tenant stream latency. Configured bootstrap endpoints have explicit local-address exceptions. |
| `portal/discovery/Controller` | Trusted local failure input, selection intent and operator add/remove actions | `Report` does not verify evidence: never translate an untrusted peer accusation into `FailureMITM`. |
| MOLS in `portal/discovery/mols.go` | Existing eligibility and ranking over the locally retained pool | URL diversity is not operator independence. It is not a second source of security truth. |
| Relay ingress/lease owners | Local admission, authorization and resource-limit outcomes | Abusive visitors or tenants do not establish that the forwarding relay is malicious. These counters are not independently verified remote attestations. |

Descriptor signature/normalization belongs to `relay_descriptor.go`; freshness,
rollback, takeover and candidate admission belong to `RelaySet`. Public-address
dialing and redirect rejection belong to `public_relay.go`. Do not duplicate
these decisions in the SDK or add a parallel ranking/evidence registry.

## Attack catalog and current disposition

Each row names a capability, usable observation, competing explanation or
evasion, and the response currently justified. "Unavailable" means the signal
does not exist in current telemetry, not that the attack cannot occur.

| Pattern / attacker capability | Observable evidence | Benign explanation / evasion | Disposition |
| --- | --- | --- | --- |
| Selective TLS termination or replay/stream modification by a forwarding relay | Local exporter mismatch for a sampled passthrough-required TLS connection; endpoint content verification where an application already supplies it | Timeout, unsupported exporter, loss, and opted-in cache termination differ from mismatch. A relay can pass probes and attack a different source, time, fingerprint or exposure. | Keep existing opt-in local MITM block behavior. No new content inspection or broader confidentiality guarantee; #645 owns TLS experiments. |
| Selective drops, resets, stalls, misrouting or corrupt forwarding | Listener/handshake failures when they reach the SDK; an application can verify its own endpoint result | Restarts, congestion, overload and loss can produce the same failure. A relay can keep discovery healthy while breaking tenant traffic; per-visitor comparative stream evidence is unavailable. | Existing runtime suppression/retry. No permanent malice label from failure counts. Passing discovery must not erase active-listener suppression. |
| Signed false capability claims or misleading readiness | Advertised transport flags versus locally observed negotiation/result; direct protocol-version mismatch | Rolling upgrades, endpoint configuration and different protocol versions; attacker succeeds only on probes | Keep compatibility eligibility separate from health. No new capability canary or claim that signatures prove transport works. |
| Unsigned, stale, rolled-back, tampered or conflicting descriptors; URL takeover | Signature failure, expiry, signing-key rollback anchor, current URL binding, and conflicting canonical signed contents at the same URL/key/issuance time | Clock error, incorrectly reused issuance timestamps and legitimate rotation; attacker rotates URLs/keys or waits for a fresh timestamp | Reject a same-time contradiction while retaining the previous observation; allow identical retransmissions and newer updates. No durable equivocation evidence store exists; conflicts after eviction or across clients are not detected. |
| RTT inflation, flapping or load manipulation to influence selection | Local discovery RTT samples, pressure and active/discovery failure history | Geography, route changes, load, protocol differences and visitor mix; self-reported load can be fabricated | Existing bounded ranking/backoff only. Cross-relay causal attribution and malicious-intent detection are unavailable. |
| Connection floods, handshake amplification or capacity starvation | Local ingress/lease/SDK bounds and protocol failures | An honest relay may carry abusive visitors; congestion is not evidence about its operator | Enforce the owning admission limits. Do not convert visitor abuse into a relay security ban. |
| DNS rebinding, redirects, certificate/hostname or control-plane anomalies | Local public-address vetting, HTTPS validation, redirect refusal and lease authorization results | DNS deployment changes, expiry and configuration mistakes; attacker behaves differently by resolver/egress | Keep existing endpoint validation and bounded retries. Independent DNS/CT observers and cross-vantage certificate history are unavailable. |
| Sybil/colluding identities, fabricated accusations and strategic probe success | Verified signing keys, candidate provenance and local observations | Many URLs/keys may be one operator; an honest operator may run several relays. Independent identities or reporter honesty cannot be inferred from URL counts. | Gossip cannot promote a peer or sanction another relay. Keep candidate/collection limits. Verified Sybils and identity/URL churn remain limitations; no majority vote or global blacklist. |

Economic deterrence, operator independence and attack success before exclusion
are not established by these observations. A relay pool supplies alternatives,
not independent probe egress, trusted witnesses or a trusted majority.

## Responses, expiry and recovery

- **Local verified security failure:** the existing SDK exporter decision may
  report `FailureMITM` when blocking is enabled. `Controller.Report` then bans
  that URL in its local `RelaySet`. A valid advertisement cannot clear it;
  `AddRelay` is the explicit operator override. This is process-local URL state,
  not an identity-wide, persisted or network-wide ban. Other URLs under the same
  signing key are not automatically sanctioned.
- **Runtime or terminal listener failure:** existing suppression starts at one
  minute and is capped at five minutes; duplicate reports during suppression
  do not manufacture extra strikes. A successful discovery response alone does
  not remove it. Eligibility can recover after expiry without accusing anyone.
- **Discovery failure:** the refresher owns direct recovery; protocol mismatch
  is incompatible metadata, not a failed health probe. Long-unhealthy pool
  removal has its existing 72-hour expiry. That availability policy is distinct
  from a local security ban.
- **Untrusted remote claims:** signed gossip may supply candidate descriptors;
  peer release/incompatibility claims do not replace direct observations. There
  is no remotely authorized input for issuing `Controller.Report` sanctions.
- **Conflicting signed descriptor:** all ingestion paths reject changes to the
  canonical signed contents for a retained URL/key/`IssuedAt`. Direct discovery
  returns an error without clearing recovery state or prior incompatibility;
  gossip cannot alter the retained record or impose a ban. Identical cached
  descriptors remain valid recovery responses, and newer issuance times allow
  changed capabilities. Multiple URLs under one key are not contradictions.
  This checks local consistency, not intent, and adds no evidence history.

Candidate eviction and observation maps have configured limits; RTT history
retains at most 100 samples per relay. Rollback anchors expire after their replay
window but have no separate hard identity-count cap: high signing-key churn can
grow that map within the window. Bootstrap and banned URL entries are pinned;
local security bans require operator intervention. Do not claim that the whole
pool is strictly count-bounded or automatically expires. These existing retention
limits must be included in any churn/memory measurement before adding history.
No visitor payloads, new per-connection histories, shared accusations or
additional monitoring tasks are introduced by this catalog.

## Executable evidence and its limits

These are owner-level regressions with scripted inputs, not measured detection
rates or live adversarial network experiments. A test that supplies
`FailureMITM` checks policy after classification, not the TLS classifier.

| Scenario | Existing evidence / added regression | Observable result and limit |
| --- | --- | --- |
| A relay passes discovery after a tenant-runtime failure; an ordinary outage supplies the same failure input | `portal/discovery/controller_test.go::TestControllerPassingDiscoveryDoesNotClearRuntimeSuppression` | Only the healthy alternative is selected during backoff; both recover after time advances. Does not generate real resets or distinguish intent. |
| A banned relay submits a valid descriptor, followed by explicit operator re-add | `controller_test.go::TestControllerLocalSecurityBanSurvivesDiscoveryUntilOperatorOverride` | Advertisement cannot clear the ban or exclude the healthy peer; operator override restores eligibility. No exporter verification occurs here. |
| A reporter advertises several distinct signing identities, forged victim capabilities and false peer metadata | `portal/discovery/announce_test.go::TestColludingGossipCannotReplaceLocalRelayEvidence` | Only directly observed targets remain selectable; forged descriptors/peer metadata do not replace healthy local evidence. Does not prevent directly verified Sybils. |
| Validly signed same-URL/key/time capability contradiction through announce, gossip or direct discovery, with healthy and recovering controls | `announce_test.go::TestSignedDescriptorConflictPreservesLocalObservation` and `TestDescriptorConflictGuardAllowsRetransmissionAndFreshUpdates` | Retains the previous record and eligibility/recovery state; direct contradiction returns an error. Identical retransmissions recover, newer statements update, and same-key multi-URL operation remains allowed. This is admission evidence, not a live equivocation detection rate. |
| Stale, expired, takeover and per-identity candidate flooding inputs | Existing `announce_test.go` rollback/takeover/cap tests and `relayset_test.go::TestDescriptorsDropsExpiredSignedRelayDescriptor` | Rejects these bounded admission cases; no claim of complete equivocation or identity-churn detection. |
| Protocol upgrades and observed latency/congestion | Existing `relayset_test.go::TestApplyRelayDiscoveryResponseCollectsRelaysDespiteProtocolMismatch` and `mols_test.go` | Distinguishes compatibility/eligibility/ranking from security sanctions; no QoS-maliciousness classifier. |
| Exporter match/mismatch and a real tenant-triggered probe | Existing `sdk/mitm_test.go::TestMITMProbeCompletionClassifiesExporter` and `e2e/mitm_test.go::TestMITMSelfProbeRunsOnTenantTraffic` | Owner classification and that process scenario only. Selective pass-on-probe experiments remain with #645. |

For a production selection policy beyond existing responses, first obtain
controlled end-to-end evidence across both attack and honest-control runs:

- Pair the same tenant workload and transport with comparable relay paths;
  label ground truth at the controlled attacker/endpoint, not from the detector
  under evaluation. Record configuration, protocol, load and route differences.
- Include selective drops, corruption, resets, delay, probe-only success,
  identity churn/collusion, and fabricated claims. Pair these with packet loss,
  overload, restart, clock/deployment changes and distinct honest paths. A local
  injected failure does not substitute for this campaign.
- Report detections over observable attacked samples, false security actions
  over honest controls, time from attack to observation/action, successful
  attacks before action, healthy-selection loss, and incremental CPU/network
  work. Also report unsampled/unobservable attacks and their denominator; probe
  matches are not negatives for those connections.
- Vary source/ASN, TLS fingerprint, time and exposure identity where the attack
  conditions on them. State which egress and observers are actually independent.
  Compare outcomes of separate TLS sessions, not their raw exporter bytes.

These network measurements and attacker bypass costs are **not yet measured**.
Retain only bounded aggregate or cryptographically verifiable evidence with a
declared expiry; do not collect visitor IP/payload histories to fill the gaps.
Do not ship automatic cross-relay accusations, ML classification or new
sanctions until a distinguishable signal and safe recovery rule are demonstrated.

Outcome for now: reuse existing admission, verification, ranking and local
recovery for the supported rows; acknowledge the unobservable cases. #646 remains
open for network experiments and any separately justified minimal policy. #537
owns the broader trust discussion; service-content votes in #472 are not
relay-behavior evidence.
