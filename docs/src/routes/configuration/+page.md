---
title: Configuration Reference
description: Complete reference for all Portal environment variables, CLI flags, and configuration files.
---

# Configuration Reference

Complete reference for all Portal environment variables, CLI flags, and configuration files.

## Relay Server Environment Variables

The relay server (`relay-server`) reads configuration from environment variables. Each variable corresponds to a CLI flag of the same shape (e.g. `PORTAL_URL` → `--portal-url`). CLI flags take precedence over environment variables when both are set.

### Core

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PORTAL_URL` | `https://localhost:4017` | string | Public base URL of this relay server |
| `IDENTITY_PATH` | `./.portal-certs` | string | Directory path for relay identity, admin state, and TLS materials |
| `API_PORT` | `4017` | int | Admin/API server listen port |
| `SNI_PORT` | `443` | int | TCP SNI router listen port |
| `WIREGUARD_PORT` | `51820` | int | Public and listen UDP port for relay discovery overlay |

### Transport

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `MIN_PORT` | `0` | int | Inclusive minimum port for UDP and raw TCP transports (`0` = disabled) |
| `MAX_PORT` | `0` | int | Inclusive maximum port for UDP and raw TCP transports (`0` = disabled) |
| `UDP_ENABLED` | `false` | bool | Enable UDP relay transport; requires a valid `MIN_PORT`/`MAX_PORT` range |
| `TCP_ENABLED` | `false` | bool | Enable raw TCP port transport; requires a valid `MIN_PORT`/`MAX_PORT` range |

### Features

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `LANDING_PAGE_ENABLED` | `false` | bool | Enable the landing page by default when no admin setting has been saved yet |
| `DISCOVERY` | `false` | bool | Serve relay discovery endpoints and poll discovery peers |
| `BOOTSTRAPS` | `""` | string | Additional bootstrap relay API URLs used for discovery expansion (comma-separated) |

### Proxy

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `TRUST_PROXY_HEADERS` | `false` | bool | Trust `X-Forwarded-*` and `X-Real-IP` headers from trusted proxies |
| `TRUSTED_PROXY_CIDRS` | `""` | string | Trusted proxy CIDR allowlist for forwarded headers (comma-separated); defaults to private/loopback ranges when `TRUST_PROXY_HEADERS` is enabled |

### TLS

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `ACME_DNS_PROVIDER` | `""` | string | DNS provider for managed DNS-01/A-record sync, ECH HTTPS records, and ENS gasless DNSSEC/TXT automation (`cloudflare` \| `gcloud` \| `hetzner` \| `route53` \| `vultr`); leave empty to use manual `fullchain.pem`/`privatekey.pem` from `IDENTITY_PATH` |
| `ENS_GASLESS_ENABLED` | `false` | bool | Enable ENS gasless DNS import automation for the managed DNS zone and lease hostnames |

### Admin

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `HEADLESS_SHELL_URL` | `""` | string | Headless Chrome CDP WebSocket URL for thumbnail generation (e.g. `ws://headless-shell:9222`) |

### Diagnostics

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PPROF_ENABLED` | `false` | bool | Enable the relay pprof diagnostics HTTP server |
| `PPROF_ADDR` | `127.0.0.1:6060` | string | pprof listen address when enabled; keep it on loopback unless the port is protected |

### Cloudflare

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `CLOUDFLARE_TOKEN` | | string | Cloudflare DNS API token; required when `ACME_DNS_PROVIDER=cloudflare` |

### Google Cloud

| Variable | Aliases | Default | Type | Description |
|----------|---------|---------|------|-------------|
| `GCP_PROJECT_ID` | `GOOGLE_CLOUD_PROJECT`, `GCLOUD_PROJECT`, `GCE_PROJECT` | | string | Google Cloud project ID for Cloud DNS automation; auto-detected from ADC or GCE metadata when omitted |
| `GCP_MANAGED_ZONE` | `GCP_ZONE`, `GCE_ZONE_ID` | | string | Explicit Google Cloud DNS managed zone name or numeric ID override |
| `GOOGLE_APPLICATION_CREDENTIALS` | | | string | Path to GCP service account key file (standard ADC; used by the GCP client library) |

### Hetzner

| Variable | Aliases | Default | Type | Description |
|----------|---------|---------|------|-------------|
| `HETZNER_API_TOKEN` | `HCLOUD_TOKEN` | | string | Hetzner Cloud API token for DNS automation; required when `ACME_DNS_PROVIDER=hetzner` |

### AWS

| Variable | Aliases | Default | Type | Description |
|----------|---------|---------|------|-------------|
| `AWS_ACCESS_KEY_ID` | | | string | AWS access key ID for Route53 static credentials; uses the default AWS credential chain when omitted |
| `AWS_SECRET_ACCESS_KEY` | | | string | AWS secret access key for Route53 static credentials |
| `AWS_SESSION_TOKEN` | | | string | AWS session token for Route53 temporary credentials |
| `AWS_REGION` | `AWS_DEFAULT_REGION` | `us-east-1` | string | AWS region for Route53 and Route53-backed DNS-01 |
| `AWS_HOSTED_ZONE_ID` | | | string | Explicit Route53 hosted zone ID override |
| `AWS_DNSSEC_KMS_KEY_ARN` | | | string | AWS KMS key ARN used to create a Route53 DNSSEC key-signing key when needed |

### Vultr

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `VULTR_API_KEY` | | string | Vultr API key for DNS automation; required when `ACME_DNS_PROVIDER=vultr` |

---

## Portal Tunnel CLI Flags

The `portal expose` subcommand accepts the following flags. Flags that read from environment variables are noted in the **Env Var** column.

### Connection

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--relays` | | string | _(registry)_ | Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https) |
| `--discovery` | | bool | `true` | Include public registry relays and discover additional relay bootstraps |
| `--multi-hop` | `MULTI_HOP` | string | | Ordered multi-hop relay API URLs, comma-separated |
| `--multi-hop-depth` | `MULTI_HOP_DEPTH` | int | `0` | Automatically select one multi-hop route with this hop count; 0 or 1 disables multi-hop |
| `--max-active-relays` | `MAX_ACTIVE_RELAYS` | int | `3` | Maximum auto-selected relays to keep connected; explicit relays are always included |
| `--ban-mitm` | `BAN_MITM` | bool | `true` | Ban relay when the MITM self-probe detects TLS termination |

### Identity

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--identity-path` | `IDENTITY_PATH` | string | `identity.json` | Identity JSON file path |
| `--identity-json` | `IDENTITY_JSON` | string | | Identity JSON payload; overrides `--identity-path` contents and is persisted there when both are set |

### Lease

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--name` | | string | _(auto)_ | Public hostname prefix (single DNS label); auto-generated when omitted |
| `--description` | | string | | Service description metadata |
| `--tags` | | string | | Service tags metadata (comma-separated) |
| `--owner` | | string | | Service owner metadata |
| `--thumbnail` | | string | | Service thumbnail URL metadata |
| `--hide` | | bool | `false` | Hide service from relay listing screens |

### Routing

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--http-route` | | string | | HTTP route mapping in `PATH=UPSTREAM` form; repeat to aggregate multiple local HTTP services behind one public URL |

### Transport

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--udp` | `UDP_ENABLED` | bool | `false` | Enable public UDP relay in addition to the default stream path |
| `--udp-addr` | `UDP_ADDR` | string | | Local UDP target address for relayed datagrams (`host:port` or port only); defaults to the target when `--udp` is enabled |
| `--tcp` | `TCP_ENABLED` | bool | `false` | Request a dedicated TCP port on the relay for raw TCP services (no TLS; e.g., Minecraft, game servers) |

The `portal list` subcommand accepts the following flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | _(registry)_ | Additional Portal relay server API URLs (comma-separated) |
| `--default-relays` | bool | `true` | Include public registry relays |

---

## Configuration Files

### `config.toml`

`portal agent run` reads the platform default `config.toml` and starts one managed process for all declared tunnels. Relative paths are resolved from the config file directory. The config file must exist before the agent is started.

Default paths:

| OS | Config | Default identity |
|----|--------|------------------|
| Linux user | `$XDG_CONFIG_HOME/portal-tunnel/agent/config.toml` or `~/.config/portal-tunnel/agent/config.toml` | `$XDG_DATA_HOME/portal-tunnel/agent/identity.json` or `~/.local/share/portal-tunnel/agent/identity.json` |
| Linux root | `/etc/portal-tunnel/agent/config.toml` | `/var/lib/portal-tunnel/agent/identity.json` |
| macOS user | `~/Library/Application Support/Portal Tunnel/Agent/config.toml` | `~/Library/Application Support/Portal Tunnel/Agent/identity.json` |
| macOS root | `/Library/Application Support/Portal Tunnel/Agent/config.toml` | `/Library/Application Support/Portal Tunnel/Agent/identity.json` |
| Windows | `%ProgramData%\Portal Tunnel\Agent\config.toml` | `%ProgramData%\Portal Tunnel\Agent\identity.json` |

```toml
[agent]
control_addr = "127.0.0.1:4018"
service_name = "portal-agent"

[[tunnels]]
id = "web"
name = "myapp"
target = "127.0.0.1:3000"
relays = ["https://portal.example.com"]
discovery = false
description = "Managed web tunnel"
tags = ["web"]

[[tunnels]]
id = "frontend-api"
name = "myapp"

[[tunnels.http_routes]]
prefix = "/api"
upstream = "http://127.0.0.1:3001"

[[tunnels.http_routes]]
prefix = "/"
upstream = "http://127.0.0.1:5173"
```

Agent fields:

| Field | Default | Description |
|-------|---------|-------------|
| `state_dir` | Platform default state directory | Stores the local control endpoint token and runtime state |
| `control_addr` | `127.0.0.1:4018` | Loopback-only local control API address |
| `service_name` | `portal-agent` | OS service name |
| `allowed_wallets` | empty | Wallet addresses allowed to read local agent status through wallet auth; empty allows any wallet on the loopback auth endpoint |

The local agent dashboard and mutating control API calls use the bearer token in
the agent state directory. Wallet-authenticated agent requests are read-only and
can only read `/v1/agent/status`.

Tunnel fields mirror `portal expose` flags:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable tunnel ID used by the agent dashboard |
| `target` | string | Local TCP target, equivalent to the `portal expose <target>` argument |
| `http_routes` | table array | HTTP route mappings; cannot be combined with `target` or `udp` |
| `relays` | string array | Explicit relay API URLs |
| `discovery` | bool | Include registry and relay discovery expansion |
| `multi_hop` | string array | Ordered multi-hop relay path |
| `multi_hop_depth` | int | Automatically select one multi-hop route with this depth |
| `identity_path` | string | Tunnel identity JSON file path. When omitted, one tunnel uses the platform default `identity.json`; multiple tunnels use `<state-dir>/<tunnel-id>/identity.json` |
| `identity_json` | string | Identity JSON payload; overrides `identity_path` contents and is persisted there when both are set |
| `udp`, `udp_addr`, `tcp` | bool/string | UDP and raw TCP relay options |
| `description`, `tags`, `owner`, `thumbnail`, `hide` | mixed | Lease metadata shown by relays |

For a task-oriented walkthrough, see [Portal Agent](/portal-agent).

### `identity.json`

Stores the secp256k1 identity used to sign tunnel sessions and relay descriptors. `portal expose` treats `--identity-path` as a direct JSON file path. `relay-server` treats `IDENTITY_PATH` as a state directory and stores this file at `IDENTITY_PATH/identity.json`.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable label for this identity |
| `address` | string | Derived EVM address used for SIWE and identity ownership |
| `public_key` | string | Compressed secp256k1 public key hex |
| `private_key` | string | secp256k1 private key hex; keep secret |
| `wireguard_public_key` | string | Relay-only WireGuard overlay public key when discovery is enabled |
| `wireguard_private_key` | string | Relay-only WireGuard overlay private key when discovery is enabled |
| `encrypted_client_hello_seed` | string | Relay-only HKDF salt for deriving the ECH HPKE private key; generated automatically when missing; keep secret |

The same identity file or state directory can be reused across restarts to keep a stable address.

### `admin_settings.json`

Persists admin-panel state for the relay server. Managed automatically by the relay on write; do not edit manually while the server is running.

Relay admin settings are stored at `IDENTITY_PATH/admin_settings.json`.

---

## ACME DNS Provider Configuration

Set `ACME_DNS_PROVIDER` (or `--acme-dns-provider`) to one of the values below to enable DNS-backed automation. Portal uses the same provider for DNS-01 challenges, managed A records, ECH HTTPS records, and optional ENS gasless DNS records.

When this variable is empty the relay server falls back to manually supplied `fullchain.pem` and `privatekey.pem` files in `IDENTITY_PATH`.

For ENS gasless behavior and wallet authentication details, see [Wallet and ENS](/wallet-and-ens).

### Cloudflare (`cloudflare`)

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDFLARE_TOKEN` | Yes | Cloudflare DNS API token with `Zone:DNS:Edit` permission |

### Google Cloud DNS (`gcloud`)

| Variable | Required | Description |
|----------|----------|-------------|
| `GCP_PROJECT_ID` | No | Google Cloud project ID; auto-detected from ADC or GCE metadata when omitted |
| `GCP_MANAGED_ZONE` | No | Cloud DNS managed zone name or numeric ID; inferred from the portal domain when omitted |
| `GOOGLE_APPLICATION_CREDENTIALS` | No | Path to a service account key JSON file; uses Application Default Credentials when omitted |

### AWS Route53 (`route53`)

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | No | Access key ID; uses the default AWS credential chain (instance profile, env, `~/.aws/credentials`) when omitted |
| `AWS_SECRET_ACCESS_KEY` | No | Secret access key; required when `AWS_ACCESS_KEY_ID` is set |
| `AWS_SESSION_TOKEN` | No | Session token for temporary credentials |
| `AWS_REGION` | No | AWS region; defaults to `us-east-1` |
| `AWS_HOSTED_ZONE_ID` | No | Route53 hosted zone ID; inferred from the portal domain when omitted |
| `AWS_DNSSEC_KMS_KEY_ARN` | No | KMS key ARN for DNSSEC key-signing key creation |

### Hetzner DNS (`hetzner`)

| Variable | Required | Description |
|----------|----------|-------------|
| `HETZNER_API_TOKEN` | Yes | Hetzner Cloud API token with DNS zone and RRSet write access |

Note: Hetzner DNS does not support provider-side DNSSEC signing, so `ACME_DNS_PROVIDER=hetzner` supports ACME, A records, and HTTPS/ECH records, but not ENS gasless DNSSEC automation.

### Vultr DNS (`vultr`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VULTR_API_KEY` | Yes | Vultr API key with DNS domain, record, and DNSSEC write access |
