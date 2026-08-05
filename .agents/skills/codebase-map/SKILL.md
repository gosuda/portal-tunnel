---
name: codebase-map
description: Where things live in the portal-tunnel repo (sdk/portal/types/utils/cmd/discovery/x402/frontend/extensions) and where new code belongs. Use when locating functionality or deciding where to add code.
---

# portal-tunnel codebase map

Portal is a zero-knowledge tunneling relay + local runtime: exposes local HTTP/TCP/UDP services through self-hosted or public relays with end-to-end tenant TLS, ECH SNI hiding, MITM self-probe, multi-hop routing, and x402 payments.

## Top-level packages
- `sdk/` — **client side**. Tunnel exposure and relay API client, listener/session management, HTTP routing + proxying, MITM detection. Entry points: `sdk/expose.go`, `sdk/listener.go`, `sdk/http.go`, `sdk/proxy.go`, `sdk/mitm.go`. x402 route protection is applied here (`sdk/http.go`).
- `portal/` — **relay side**. API/server lifecycle (`portal/api_server.go`, `portal/server.go`), leases, proxying, identity, keyless TLS/ECH, overlay transports, policy, telemetry, ACME.
  - `portal/discovery/` — relay gossip: `announce.go` (rate limiting), `refresher.go` (poll descriptors + `POST /discovery/announce` self-announce + peer refresh), `relayset.go` (validated pool, bans, route-planning state), `relaystate.go`, `mols.go` (route scoring).
  - `portal/x402/` — payment gating: `handler.go`, `payment.go`, `casper.go`, `x402.go`, embedded browser `client.js`. Facilitator mounts at `/api/x402` only when `X402_ENABLED`.
- `types/` — **shared contracts**: protocol/API/data models, identity & transport types, x402 types, and public path constants (`types/paths.go`). `types/types.go` unmarshals the embedded `config.toml`/`registry.json`. Put shared constants and public path strings HERE.
- `utils/` — shared **stateless** helpers: API encoding, command dispatch (`utils/cmd.go`), files, paths, HTTP, name/network/TLS normalization, snapshots.
- `cmd/` — executables: `cmd/portal-tunnel` (client CLI), `cmd/relay-server` (relay + embedded SPA), `cmd/portal-loadtest` (`make load-test`), plus demo/payment apps.
- `frontend/` — React + Tailwind SPA (Vite). Built and embedded into the relay binary at `cmd/relay-server/dist/app` (`//go:embed dist/*`). Dev server at `http://localhost:5173`; point at a live relay with `VITE_PORTAL_API_BASE_URL`.
- `docs/` — SvelteKit docs site (`make build-docs`, uses bun).
- `extensions/vscode/` — VS Code extension (start/stop tunnel commands, relay/host/name settings).

## Root files
- `config.toml` — embedded release version + protocol versions (via `manifest.go`).
- `registry.json` — embedded default public relay list → `types.BootstrapRelays`.
- `manifest.go` — `//go:embed` of the two files above.
- `docker-compose.yml` / `Dockerfile` — relay container build/deploy.

## Where new code belongs (AGENTS.md)
- Shared contract / constant / public path → `types/` (one owner, no duplication).
- Stateless transform reused across packages → `utils/`.
- Stateful/domain logic → its real owner in `sdk/` or `portal/` (resolve complexity in the lowest coherent owner, expose minimum surface).
- Avoid speculative abstraction, wrappers with no boundary, and dead fields; remove stale code while nearby.
