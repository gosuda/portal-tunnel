# Relay overlay ownership

Status: accepted after resetting the first IVNP implementation.

## Context

Portal's multi-hop route model and WireGuard relay mesh have been removed. The
remaining system has one simple path: a tunnel client registers a lease with a
public relay and opens a direct reverse connection to that same relay.

IVNP provides optional relay-to-relay reachability and owns its internal
multi-hop routing. The first implementation proved that gateway/ingress
separation, delegated authorization, failure isolation, and route replacement
are real requirements. It also spread those requirements through the generic
SDK listener, discovery route, server, and authentication packages. That
implementation is intentionally removed before a replacement is built.

## Decision

Portal core owns:

- public relay discovery, admission, health, load, and selection;
- the public hostname and lease lifecycle at the ingress relay;
- tenant authorization and the direct reverse connection baseline; and
- public transport policy and telemetry.

One overlay implementation owns:

- gateway selection from Portal-admitted relay descriptors;
- ingress and gateway destination mapping;
- scoped reverse capabilities and their validation;
- overlay dial, listen, framing, peer verification, and capacity limits;
- overlay-specific failure classification and retry; and
- gateway replacement without replacing the ingress lease.

IVNP owns tunnel construction, internal router selection, NAT-independent
reachability, and volunteer middle transit. Portal must not configure an IVNP
hop count, discover IVNP middle routers, or construct an intermediate path.

## Boundary

The SDK-facing contract is a generic reverse endpoint. It contains a URL, an
opaque reverse-only capability, and an expiry. It does not expose IVNP
destinations, ingress/gateway topology, or overlay-specific error types.
The capability is also bound to one lease instance, so replacing a lease
invalidates credentials issued for the previous instance.

In direct mode the ingress lease registry issues an endpoint for itself. When
the overlay is enabled, the ingress overlay implementation selects a gateway
and replaces only that endpoint issuance. Its delegated capability is
short-lived and bound to the ingress lease, ingress destination, and selected
gateway. It cannot mutate, renew, or delete the lease. The ingress lease bearer
token is never sent to the gateway.

The gateway applies a source-IP request budget before validating the capability,
then reserves both per-source and global connection capacity before dialing.
Signatures establish identity, not admission: caller-created ingress identities
must share the source's budget. The capability carries the signed endpoint
evidence required to reach the ingress, so execution does not require the gateway
and ingress discovery catalogs to have converged. The ingress remains the final
authority: it verifies
the authenticated overlay peer and capability before offering the connection to
the lease's reverse queue.

The generic SDK listener only opens and maintains the returned reverse
endpoint. Endpoint refresh is independent from lease registration, so replacing
a failed gateway cannot unregister the public hostname or recreate its lease.

The Portal server starts and stops the overlay runtime and supplies narrow
admission and lease-stream interfaces. Overlay protocol framing, HTTP upgrade,
bridging, and retry state do not live on `Server` or `leaseRecord`.

Discovery returns public relay priorities and signed relay descriptors. Its
generic `Route` remains `{RelayURL, Explicit}`. It does not return an overlay
execution plan or perform overlay dial/listen operations.

## Failure and lifecycle rules

- Direct reverse connections remain available when the optional overlay is
  disabled or unavailable.
- Invalid overlay configuration fails startup. Failure after optional overlay
  startup marks only the overlay unavailable and does not stop public ingress.
- Public HTTPS failures affect the corresponding relay's public health.
  Overlay route failures do not.
- Gateway capacity is bounded before any expensive dial and released on every
  terminal path.
- Capability expiry is no later than the ingress lease or signed endpoint
  evidence it depends on.
- Overlay shutdown closes listeners, pending dials, and bridged connections.
- UDP backhaul remains direct until an overlay implementation explicitly owns
  and documents UDP semantics.

## Implementation order

1. Keep the direct-only baseline and remove stale multi-hop documentation and
   state.
2. Introduce the generic reverse-endpoint contract and use it for the direct
   path without changing behavior.
3. Add one overlay owner with narrow Portal admission and lease-stream ports.
4. Implement IVNP entirely behind that boundary.
5. Add gateway replacement and optional-overlay failure handling before
   exposing the feature flag.

No WireGuard compatibility layer, Portal hop routes, `/sdk/hop`, worker catalog,
or second lease lifecycle will be reintroduced.

## Acceptance criteria

- `sdk/listener.go` contains no IVNP, gateway, ingress-destination, or
  overlay-route logic.
- `discovery.Route` contains only the selected public relay and whether it was
  explicit.
- a gateway change preserves the ingress lease and public hostname;
- the gateway never receives the ingress lease bearer token;
- a valid route works without mutual discovery-catalog convergence;
- overlay failure cannot stop healthy public ingress or poison public relay
  health; and
- NATed middle routers remain invisible to Portal discovery and the SDK.
