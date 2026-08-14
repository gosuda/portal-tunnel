---
name: testing-relay-server
description: How to build and run the portal-tunnel relay-server locally for HTTP/browser testing of the embedded SPA frontend and admin/policy APIs.
---

# Testing the relay-server locally

## Build
- Go 1.26+ at `/usr/local/go/bin` (add to PATH); frontend needs Node 22+ for vite.
- `make build-frontend` → populates `cmd/relay-server/dist/app` (required before server build; missing assets make startup fail with a 'make build-frontend' error).
- `make build-server-bin` → `bin/relay-server`.

## Run
```
ADMIN_TOKEN=<token> IDENTITY_PATH=/tmp/pt-id ./bin/relay-server serve --sni-port 8443
```
- Default `--sni-port 443` fails to bind unprivileged — always override.
- API/frontend on https://localhost:4017 (self-signed TLS; use `curl -k`; plain HTTP returns 400).
- Env vars: API_PORT (4017), PORTAL_FRONTEND_DIR (dir-backed SPA, cache disabled → live-editable), LANDING_PAGE_ENABLED, ADMIN_TOKEN.

## Policy API
- `GET/POST /api/policy` with `Authorization: Bearer $ADMIN_TOKEN`.
- POST requires the FULL settings object (e.g. `{"approval_mode":"auto","landing_page_enabled":true,"udp":{"enabled":false,"max_leases":0},"tcp_port":{"enabled":false,"max_leases":0}}`); partial bodies get 400 invalid_mode.
- State persists to `<IDENTITY_PATH>/policy.json`.

## Gotchas
- When killing the server from a shell, use `pkill -x relay-server` — `pkill -f` patterns containing the binary path match your own shell command and kill it.
- Reserved root prefixes that must never serve the SPA: `/api`, `/sdk`, `/discovery`, `/v1` (types.ReservedRootPrefixes in `types/paths.go`).
