---
name: relay-server-config
description: Full environment-variable / flag reference for configuring the portal-tunnel relay-server (cmd/relay-server), plus how config is embedded and how Docker/Compose deploys it. Use when configuring, deploying, or debugging a relay.
---

# relay-server configuration

Entrypoint `cmd/relay-server/main.go`, dispatched by `utils.RunCommands` (`""`/`serve` → serve, `help`). Every flag has an env fallback parsed by `utils.{String,Bool,Int}FlagEnv` at flag-init time (`utils/cmd.go`); flags are declared in `main.go ~79-117`. `--help` shows usage/examples only, not flags.

## Core env vars / flags (default)
| Env | Default | Purpose |
|---|---|---|
| `PORTAL_URL` | `https://localhost` | portal base URL (`--portal-url`) |
| `PORTAL_FRONTEND_DIR` | empty | custom SPA dir; empty = embedded (`--frontend-dir`) |
| `IDENTITY_PATH` | `./.portal-certs` | identity/cert + `policy.json` dir (`--identity-path`) |
| `API_PORT` | `4017` | HTTPS API + frontend (`--api-port`) |
| `SNI_PORT` | `443` | public SNI ingress (`--sni-port`) — cannot bind unprivileged; override locally |
| `WIREGUARD_PORT` | `51820` | (`--wireguard-port`) |
| `EMBEDDED_DNS_PORT` | `53` | embedded authoritative DNS (`--embedded-dns-port`) — default provider; needs 53/tcp+udp and `CAP_NET_BIND_SERVICE` in containers |
| `ADMIN_TOKEN` | empty | bearer token for admin/policy APIs (`--admin-token`) |
| `LANDING_PAGE_ENABLED` | `false` | (`--landing-page-enabled`) |
| `DISCOVERY` | `false` | enable gossip; needs `BOOTSTRAPS` (`--discovery`) |
| `BOOTSTRAPS` | empty | comma-separated bootstrap relay URLs (`--bootstraps`) |
| `TRUST_PROXY_HEADERS` | `false` | trust XFF etc. (`--trust-proxy-headers`) |
| `TRUSTED_PROXY_CIDRS` | empty | (`--trusted-proxy-cidrs`) |
| `UDP_ENABLED` / `TCP_ENABLED` | `false` | non-HTTP lease transports |
| `MIN_PORT` / `MAX_PORT` | `0` / `0` | lease port range; `0` disables |
| `PPROF_ENABLED` / `PPROF_ADDR` | `false` / `127.0.0.1:6060` | pprof |
| `X402_ENABLED` / `X402_TESTNET` / `X402_PAY_TO` | `false` / `false` / empty | mounts facilitator under `/api/x402` only when enabled |

Embedded DNS is the default `ACME_DNS_PROVIDER` (empty value): `EMBEDDED_DNS_PORT` (default 53). External provider creds remain env-bound: `ACME_DNS_PROVIDER`, `CLOUDFLARE_TOKEN`, GCP (`GCP_PROJECT_ID`+aliases, `GCP_MANAGED_ZONE`+aliases), Hetzner (`HETZNER_API_TOKEN`/`HCLOUD_TOKEN`), AWS Route53 (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`/`AWS_REGION`→defaults us-east-1 downstream/`AWS_HOSTED_ZONE_ID`/`AWS_DNSSEC_KMS_KEY_ARN`), `VULTR_API_KEY`, `NJALLA_TOKEN`, `ENS_GASLESS_ENABLED` (unsupported with embedded). Never hardcode these — reference as env vars / secrets.

## Reserved API surface (types/paths.go)
Root-host trees that must never fall through to the SPA: `types.ReservedRootPrefixes` = `/api`, `/sdk`, `/discovery`, `/v1`. x402 public paths `/x402/prepare`, `/x402/client.js`; relay facilitator `/api/x402/{supported,verify,settle}`. Discovery: `/discovery`, `/discovery/announce` (only when `DISCOVERY=true`).

## Admin/policy API
`GET/POST /api/policy` with `Authorization: Bearer $ADMIN_TOKEN`. POST requires the FULL settings object (partial bodies → 400 `invalid_mode`). Persists to `$IDENTITY_PATH/policy.json`.

## Config embedding & Docker
- `config.toml` (version/protocol) and `registry.json` (default relays) are embedded via `manifest.go` and parsed in `types/types.go`.
- `docker-compose.yml` runs `ghcr.io/gosuda/portal:2`, publishes TCP 443 + TCP/UDP 53 (embedded DNS, `cap_add: NET_BIND_SERVICE`) + UDP WireGuard port, and passes the above env vars.
- `Dockerfile`: Node 22 stage builds the frontend into `cmd/relay-server/dist/app`, then `make build-server-bin` compiles the Go relay.
