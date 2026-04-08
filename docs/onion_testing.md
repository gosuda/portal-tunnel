# Onion Transport Testing Playbook

This playbook documents how to exercise the Tor-style onion transport exactly as
implemented in `portal/overlay/onion.go`. The simulator drives the production
builder/peeler code – there are no mocks, shortcuts, or test-only branches.

## Prerequisites

- Go toolchain `1.26.1` (or newer) available on `PATH`.
- `scripts/run_onion_sim.sh` executable (already committed).
- Optional: `GOTOOLCHAIN` env var if your default Go version differs from the
  repo’s `go.mod`.

## 1. Build-time sanity (unit + lint)

```bash
go test ./...
$(go env GOPATH)/bin/golangci-lint run ./cmd/... ./portal/... ./sdk/... ./types/...
```

These commands hit the real onion implementation. No test stubs exist – the
same code path ships in release builds.

## 2. Multi-relay onion simulation

```bash
./scripts/run_onion_sim.sh \
  --relays 6 \
  --hops 4 \
  --payload "l7-health-check" \
  --ttl 12 \
  --epochs 5 \
  --churn-every 2
```

What happens:

1. The script runs `go run ./cmd/onion-sim` with the specified flags.
2. `cmd/onion-sim` provisions six virtual relays, each with a unique 32-bit ID
   and documentation-prefix public IP (e.g., `198.51.100.12`).
3. It feeds those IDs into `overlay.BuildOnionPayload`, deriving hop keys via
   HKDF and layering ChaCha20-Poly1305 encryption exactly like production.
4. Each simulated relay runs in its own goroutine and calls
   `overlay.PeelOnionLayer`. When `nextHop=0`, the hop treats itself as the
   terminal exit, exactly mirroring how real relays behave.
5. The program streams log lines so you can inspect the ingress, each hop’s TTL,
   and the final payload verification without attaching a debugger.
6. The built-in state machine rotates through `steady → churn → recover`
   control states. Every `--churn-every` epochs a churn epoch swaps out at least
   `--churn-span` relays (default = `max(1, hops/3)`), simulating large routing
   changes; the following epoch enters `recover`, restoring a rotated baseline
   order so you can observe convergence.

Expected output (abridged):

```
[epoch 01 state=steady] ingress relay-sin-exit(198.51.100.13) -> hops 4, payload="l7-health-check", ttl=12 (Δ +5 / -0 nodes)
[epoch 01 state=steady hop=relay-nyc-edge 198.51.100.10] ttl=11 -> next hop relay-lon-core(198.51.100.11)
...
[epoch 02 state=churn] ingress relay-ams-exit(198.51.100.17) -> hops 4, payload="l7-health-check", ttl=12 (Δ +4 / -4 nodes)
[epoch 02 state=churn hop=relay-tyo-exit 198.51.100.14] ttl=10 -> next hop relay-gru-core(198.51.100.18)
[epoch 03 state=recover hop=relay-fra-core 198.51.100.12] terminal decrypted payload (16 bytes)
```

If any hop fails integrity, TTL budgeting, or next-hop validation, the program
exits non-zero with a descriptive error (e.g., “expected next hop …”). There is
no mock path – failures are showing production logic issues.

## 3. Long-running and custom scenarios

- Adjust `--epochs`, `--churn-every`, `--churn-span`, or `--state-seed` to model
  long-lived overlays with periodic rebalancing. Example: `--epochs 30
  --churn-every 5 --churn-span 3` mimics a rebalance every fifth epoch by
  swapping at least three relays.
- `--relays` / `--hops` still set the anonymity set size; constraint:
  `hops < relays`.
- Pass structured payloads (e.g., JSON) via `--payload "$(cat payload.json)"` to
  inspect how arbitrary bytes survive the circuit.
- Use `--label` to swap HKDF labels; the builder will derive a distinct key
  schedule allowing you to explore deterministic key rotation strategies.

## 4. Failure forensics

When the simulator reports an error:

1. Re-run with `--timeout` bumped (default 10s) if the environment is slow.
2. Capture the log; it lists every relay ID/IP, letting you replay the exact
   sequence by reusing the same IDs inside another script or debugger session.
3. Because the simulator’s goroutines are thin wrappers around
   `PeelOnionLayer`, any failure strongly suggests a bug in the production
   builder, peeler, or TTL math – investigate those files directly.

This workflow ensures testing always hits real code paths and that reviewers can
audit the exact commands you ran to validate anonymity and routing semantics.
