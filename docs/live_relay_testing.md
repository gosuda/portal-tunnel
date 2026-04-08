# Live Relay Testing Suite

The live relay test suite exercises a production Portal relay over the public
network. It does not spin up any mock services - every request targets the real
server you specify via flags and fails fast when the relay is unhealthy.

## Prerequisites

- Go toolchain `1.26.1` (or newer) on `PATH`.
- Network reachability to the target relay's HTTPS API.
- Optional: custom CA bundle for self-hosted relays (`--live_relay_ca`).

## Running the suite

Pass the relay host via `--live_relay_domain` (a shorthand for
`https://<domain>`), or specify a full base URL with `--live_relay_url`:

```bash
go test ./tests/live_relay \
  --live_relay_domain relay.example.com \
  --live_latency_samples 5 \
  --live_overlay_max_hops 4
```

Commonly used flags:

| Flag | Description |
|------|-------------|
| `--live_relay_domain` | Relay domain (scheme inferred as `https://`). |
| `--live_relay_url` | Explicit relay base URL, useful when the API lives behind a custom port or path. |
| `--live_relay_ca` | PEM file containing additional CA roots (self-hosted or staging relays). |
| `--live_overlay_max_hops` | Maximum overlay hops (ingress excluded) to evaluate. |
| `--live_latency_samples` | Probe count per relay when collecting latency metrics. |
| `--live_public_hostname` | Optional public hostname to verify via `/tunnel/status`. |
| `--live_request_timeout` | Per-request timeout (default `5s`). |
| `--live_congestion_threshold` | Overlay congestion threshold in milliseconds (default `200`). |

## What the tests cover

| Test | Coverage |
|------|----------|
| `TestLiveRelayDomainSecurity` | Validates TLS handshake parameters and `/sdk/domain` protocol compatibility. |
| `TestLiveRelayDiscoveryOverlayRoute` | Pulls the live discovery snapshot, measures peer latency, and derives the Tor-style overlay route/TTL profile. |
| `TestLiveRelayNetworkQuality` | Collects per-relay success rates and latency percentiles, optionally verifying `/tunnel/status` for a tenant hostname. |

Each probe shares the same flag set so you can rerun individual tests in
isolation (via `-run`) without re-stating configuration.
