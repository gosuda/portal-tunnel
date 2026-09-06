---
title: Configuration Reference
description: Complete reference for all Portal environment variables, CLI flags, and configuration files.
---

# Configuration Reference

Complete reference for all Portal environment variables, CLI flags, and configuration files.

## Checking a Real Deployment

This page describes what each variable means. To see what a specific deployment
is actually doing, ask the binary rather than reading a table:

```bash
docker compose run --rm -T portal config
```

It prints every key with its effective value and where that value came from,
names any key nothing reads, and reports which features are off and what is
missing.

Run it **inside the container, without `--env-file`**. Compose has already
combined `.env` with the defaults declared in `docker-compose.yml`, so the
report then describes the environment `docker compose up` will actually
provide. `--env-file` reads a file on its own, against the relay binary's
defaults — `MIN_PORT` is `0` there and `40000` under Compose — so a file that
sets only `PORTAL_URL` and `UDP_ENABLED=true` is reported as
`udp-transport blocked` although the deployment would enable it. Use it to
inspect a file in isolation, not to predict a deployment:

```bash
relay-server config                    # this process environment
relay-server config --env-file .env    # one file, against relay defaults
```

`relay-server config --format env` regenerates the full list from the flag
definitions, and `make check-env-example` fails when this page or
`.env.example` stops mentioning a key.

## Relay Server Environment Variables

The relay server (`relay-server`) reads configuration from environment variables. Each variable corresponds to a CLI flag of the same shape (e.g. `PORTAL_URL` → `--portal-url`). CLI flags take precedence over environment variables when both are set.

A value that cannot be parsed is a startup error rather than a silent fallback:
`DISCOVERY=yes` fails immediately instead of resolving to `false`.

### Core

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PORTAL_URL` | `https://localhost` | string | Public HTTPS origin of this relay server and embedded dashboard |
| `PORTAL_FRONTEND_DIR` | `""` | string | Custom SPA directory containing `index.html`; empty uses the frontend embedded in the Portal binary |
| `IDENTITY_PATH` | `./.portal-certs` | string | Directory path for relay identity, policy state, and TLS materials |
| `API_PORT` | `4017` | int | Admin/API server listen port |
| `SNI_PORT` | `443` | int | TCP SNI router listen port; non-standard values are intended for local testing, while the bundled public deployment requires `443` |
| `WIREGUARD_PORT` | `51820` | int | Public and listen UDP port for relay discovery overlay |

### Optional HTTP redirect listener

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `HTTP_REDIRECT_ENABLED` | `false` | bool | Enable the redirect-only listener (`--http-redirect-enabled`) |
| `HTTP_REDIRECT_ADDR` | `:80` | string | TCP listen address (`--http-redirect-addr`); use `127.0.0.1:18080` for local testing |
| `HTTP_REDIRECT_HSTS` | `false` | bool | Include `Strict-Transport-Security: max-age=31536000` on redirects (`--http-redirect-hsts`) |

Every request receives **301 Moved Permanently** to the normalized configured
`PORTAL_URL`, never to a request Host or forwarded-header destination. Request
paths and queries are discarded; this does not implement per-tenant redirects.
Existing URL normalization retains a configured base path, removes trailing
slashes and the legacy `/relay` suffix, and drops configured queries/fragments.
Enabling redirects requires an explicit absolute HTTPS `PORTAL_URL` without
credentials and with a valid port; HTTPS scheme spelling is case-insensitive.
The listen address must use `host:port` syntax (bracket IPv6 addresses) with a
numeric port from 0 to 65535; port 0 requests an automatically assigned port.
`relay-server config` reports invalid targets or listen-address syntax as
`blocked`. Reporting only validates configuration: it does not resolve listen
hosts or bind sockets, so `enabled` is not a readiness check. Bind failures,
including occupied ports or unavailable hosts, still fail startup.
Disabled mode preserves existing loopback HTTP-to-HTTPS URL normalization.
Shutdown releases the listener. The listener uses bounded read, write, and idle
timeouts.

**Browsers ignore HSTS received over HTTP.** This optional insecure-response
header does not protect clients or establish HSTS. Effective HSTS must be served
over HTTPS by the destination. This option does not change HTTPS or tenant
policy and does not add `includeSubDomains` or `preload`.

```bash
relay-server --portal-url https://localhost:14017 --api-port 14017 --sni-port 14443 --http-redirect-enabled --http-redirect-addr 127.0.0.1:18080
curl -i -H "Host: untrusted.example" "http://127.0.0.1:18080/ignored?secret=value"
```

For bundled Compose, set `HTTP_REDIRECT_ENABLED=true`, retain
`HTTP_REDIRECT_ADDR=:80`, and add `"80:80"` to the portal service's `ports`.
Changing the container listen port also requires changing this mapping. Open
TCP 80 in the firewall; binding privileged ports may require OS permissions.

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
| `DISCOVERY` | `false` | bool | Serve relay discovery endpoints and poll discovery peers |
| `BOOTSTRAPS` | `""` | string | Additional bootstrap relay API URLs used for discovery expansion (comma-separated) |
| `LANDING_PAGE_ENABLED` | `false` | bool | Initial dashboard landing-page visibility; admin changes are persisted in the relay policy state |

### Payments

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `X402_ENABLED` | `false` | bool | Enable relay-owned Sui x402 facilitator endpoints under `/api/x402` for future control-plane payments |
| `X402_TESTNET` | `false` | bool | Use Sui testnet for relay-owned x402 facilitator payments; `false` uses Sui mainnet |
| `X402_PAY_TO` | `""` | string | Sui payment recipient address for relay-owned control-plane x402 resources |

### Proxy

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `TRUST_PROXY_HEADERS` | `false` | bool | Trust `X-Forwarded-*` and `X-Real-IP` headers from trusted proxies |
| `TRUSTED_PROXY_CIDRS` | `""` | string | Trusted proxy CIDR allowlist for forwarded headers (comma-separated); defaults to private/loopback ranges when `TRUST_PROXY_HEADERS` is enabled |

### TLS

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `ACME_DNS_PROVIDER` | `""` | string | DNS provider for managed DNS-01/A-record sync, the relay ECH record, opt-in tunnel ECH records, and ENS gasless DNSSEC/TXT automation (`embedded` \| `cloudflare` \| `gcloud` \| `hetzner` \| `njalla` \| `route53` \| `vultr`); unset defaults to `embedded`; valid manual `fullchain.pem`/`privatekey.pem` in `IDENTITY_PATH` overrides issuance only when neither `acme-account.key` nor `acme-registration.json` exists |
| `ENS_GASLESS_ENABLED` | `false` | bool | Enable ENS gasless DNS import automation for a public relay domain and lease hostnames through the selected DNS provider. With `embedded`, local records are signed and the operator publishes the DS at the parent zone; Cloudflare, Google Cloud DNS, Route53, and Vultr use their provider APIs. Hetzner and Njalla do not support ENS DNSSEC automation |

### Embedded DNS

> This section is the canonical reference for embedded DNS configuration. The deployment and self-hosting guides link here rather than restating the details.

Serves the relay base domain from an authoritative DNS server embedded in the relay process, so no DNS provider API credentials are required. It is the default provider when `ACME_DNS_PROVIDER` is unset. Delegate the base domain once at the parent zone (`NS portal.example.com -> ns.portal.example.com` with glue `A` pointing at the relay public IP) and open `53/tcp` + `53/udp`. Containers running without root need `CAP_NET_BIND_SERVICE` to bind the default port. A answers for the apex and every covered name are synthesized from the relay public IPv4; ACME DNS-01 TXT and tunnel ECH HTTPS records are served directly. DNSSEC signing is always enabled; ENS TXT automation remains opt-in with `ENS_GASLESS_ENABLED=true`.

The relay automatically generates a single ECDSA P-256 CSK (DNSSEC algorithm 13) in `IDENTITY_PATH/dnssec-csk.json`. Preserve and back up this file with the identity volume across restarts, container replacement, and migration: deleting or replacing it changes the DNSKEY and breaks validation against an existing parent DS. On Unix the key is created with mode `0600` (new directories `0700`); permissive existing keys, symlinks, malformed keys, and keys for another zone fail startup rather than triggering automatic replacement. On Windows a protected DACL limits the key file to the running account and SYSTEM, including temporary key files from creation. On Windows, only directories created by the embedded provider receive private directory ACLs. Existing directory and sibling-file ACLs are left unchanged: ownership and write/control access must be trusted to the running account, SYSTEM, or built-in Administrators; unrelated read/list/traverse access is allowed. Unsafe or unsupported Windows directory policies fail startup rather than being silently rewritten; correct those policies explicitly before restarting. On Linux, the configured signing directory and existing key must be owned by the effective service UID or root. Directories with group/other write bits fail startup, including writable Linux POSIX access-ACL mask bits; safe read/traverse sharing remains allowed. This deliberately rejects a writable ACL mask even when its current entries are more restrictive. Existing directories, keys, and sibling files are inspected without changing their ownership or permissions. Correct unsafe storage explicitly before restarting; Linux checks run before temporary-key creation and on existing-key loads. macOS and other non-Linux, non-Windows targets retain the existing mode-based private-key check, but do not validate directory ownership or extended ACLs. In particular, macOS extended ACLs can grant access despite restrictive mode bits: operators must independently secure both the directory and key ownership/ACLs. The Linux ACL-mask policy is not a macOS security guarantee. Use trusted ancestor directories on every platform. Operators and cleanup jobs must not rename, remove, or replace signing-store directories during initialization; failed-creation rollback coordinates cooperating relay initializers, not external namespace replacement.

The signing store must permit its required file and directory durability operations, including when an existing key is loaded. A visible key name may still belong to a concurrent creator whose publication has not finished flushing; read-only or search-only storage that cannot establish this durability barrier is not supported. Flush failures fail startup without replacing the key.

After NS/glue delegation is reachable, copy the `ds_record` from the relay startup log into a **DS record at the parent zone** for the delegated domain. `EnsureDNSSEC()` exports the same full DS record (SHA-256 digest, digest type 2); with ENS enabled it is also exposed in ENS status. Configure the key tag, algorithm, digest type, and digest exactly as exported. Parent DS publication is manual. The embedded provider reports `pending` even while signing locally: Portal does not authenticate the parent chain, so `ens.verified` remains false even after you publish the DS. The parent must itself have a valid DNSSEC chain to a trust anchor for public validation. Verify delegation and signatures before publishing the DS, and never publish the CSK private file. Losing the key requires coordinated parent DS replacement; automatic rollover is not implemented.

Authoritative RRsets, including apex DNSKEY and denial-of-existence NSEC records, are signed. Signatures last 24 hours, tolerate five minutes of clock skew, and refresh before answering after 12 hours; keep the host clock synchronized. A finite wildcard zone preserves synthesized addresses even below explicit TXT/HTTPS owners and their ancestors. When no public IPv4 is configured yet, genuinely absent names return authenticated NXDOMAIN; existing owners without the requested type return NODATA. DNSSEC records accompany responses only when requested with EDNS DO (or queried directly), and large UDP responses require TCP retry.

External managed providers (`cloudflare`, `gcloud`, `hetzner`, `njalla`, `route53`, `vultr`) are deprecated, emit configuration warnings, and receive no new features. Their implementations and settings remain supported in this release; removal is reserved for a future major release. Keep any vendor as the **parent** DNS provider and delegate only the relay subdomain to embedded DNS. Manual/external certificate ownership remains supported via `fullchain.pem` and `privatekey.pem` when neither ACME state file is present. Certificate loading itself needs no vendor API credentials, and the embedded provider needs none for DNS/ECH management. Selecting an external provider still uses its APIs for DNS/ECH publication and, when `ENS_GASLESS_ENABLED=true`, for ENS/DNSSEC synchronization before certificate loading; a manual certificate does not bypass those credentials.

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `EMBEDDED_DNS_PORT` | `53` | int | Listen port for the embedded authoritative DNS server (UDP and TCP) |

### Diagnostics

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PPROF_ENABLED` | `false` | bool | Enable the relay pprof diagnostics HTTP server |
| `PPROF_ADDR` | `127.0.0.1:6060` | string | pprof listen address when enabled; keep it on loopback unless the port is protected |
| `PPROF_PORT` | `6060` | int | Host port published for the pprof listener, read by Docker Compose rather than the relay. Only takes effect when the matching port mapping in `docker-compose.yml` is uncommented, which exposes it to the host |

### Admin

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `ADMIN_TOKEN` | | string | Bearer token source for relay admin and policy APIs; set a long random value for production relays |

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

### Njalla

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `NJALLA_TOKEN` | | string | Njalla API token for DNS automation; required when `ACME_DNS_PROVIDER=njalla` |

---

## Portal Tunnel CLI Flags

The `portal expose` subcommand accepts the following flags. Flags that read from environment variables are noted in the **Env Var** column.

### Connection

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--relays` | | string | _(registry)_ | Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https) |
| `--discovery` | | bool | `true` | Include public registry relays and discover additional relay bootstraps |
| `--multi-hop` | `MULTI_HOP` | string | | Ordered multi-hop relay API URLs, comma-separated |
| `--multi-hop-depth` | `MULTI_HOP_DEPTH` | int | `0` | Automatically create this-depth multi-hop routes for every eligible entry relay; 0 or 1 disables multi-hop |
| `--max-active-relays` | `MAX_ACTIVE_RELAYS` | int | `3` | Maximum auto-selected single-hop relays to keep connected; multi-hop uses every eligible relay as an entry; explicit relays are always included |
| `--ban-mitm` | `BAN_MITM` | bool | `false` | Ban relay when the MITM self-probe detects TLS termination |

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
| `--x402-pay-to` | | string | | Payment recipient address for this tunnel |
| `--x402-testnet` | | bool | `false` | Use Sui testnet when `--x402-network` is omitted |
| `--x402-network` | | string | | Optional Sui or Casper CAIP-2 network |
| `--x402-asset` | | string | | wCSPR CEP-18 contract hash required by Casper |
| `--x402-endpoint` | | string | | Optional Sui RPC or Casper facilitator endpoint; repeatable |
| `--x402-facilitator-token` | `CSPR_CLOUD_API_KEY` | string | | Casper facilitator authorization token |

### Routing

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--http-route` | | string | | HTTP route mapping in `PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]` form; repeat to aggregate multiple local HTTP services behind one public URL; route amounts require `--x402-pay-to` |

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
id = "api"
name = "myapp"
x402_pay_to = "0x..."
x402_testnet = true

[[tunnels.http_routes]]
prefix = "/api"
upstream = "http://127.0.0.1:3001"
methods = ["GET"]
amount = "0.01"

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
can only read `/agent/status`.

Tunnel fields mirror `portal expose` flags:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable tunnel ID used by the agent dashboard |
| `target` | string | Local TCP target, equivalent to the `portal expose <target>` argument |
| `http_routes` | table array | HTTP route mappings; cannot be combined with `target` or `udp` |
| `relays` | string array | Explicit relay API URLs |
| `discovery` | bool | Include registry and relay discovery expansion |
| `multi_hop` | string array | Ordered multi-hop relay path |
| `multi_hop_depth` | int | Automatically create this-depth multi-hop routes for every eligible entry relay |
| `ech` | bool | Enable ECH hostname privacy for TLS stream tunnels; defaults to `false` |
| `identity_path` | string | Tunnel identity JSON file path. When omitted, one tunnel uses the platform default `identity.json`; multiple tunnels use `<state-dir>/<tunnel-id>/identity.json` |
| `identity_json` | string | Identity JSON payload; overrides `identity_path` contents and is persisted there when both are set |
| `udp`, `udp_addr`, `tcp` | bool/string | UDP and raw TCP relay options |
| `description`, `tags`, `owner`, `thumbnail`, `hide` | mixed | Lease metadata shown by relays |
| `x402_pay_to` | string | Payment recipient for paid HTTP routes |
| `x402_testnet` | bool | Use Sui testnet when `x402_network` is omitted; omitted or `false` uses Sui mainnet |
| `x402_network` | string | Optional CAIP-2 network: `sui:mainnet`, `sui:testnet`, `casper:casper`, or `casper:casper-test` |
| `x402_asset` | string | wCSPR CEP-18 contract hash; required for Casper payments |
| `x402_endpoints` | string array | Optional Sui RPC endpoints or Casper facilitator URL; Casper uses the first endpoint |
| `x402_facilitator_token` | string | Casper facilitator authorization token; when omitted, the agent uses `CSPR_CLOUD_API_KEY` |
| `http_routes[].amount` | string | Optional human payment amount, such as `0.01`, for one HTTP route prefix; requires `x402_pay_to` |
| `http_routes[].methods` | string array | Optional HTTP methods that require payment on that route; empty means every method |

When any routed HTTP entry has `amount`, the tunnel also serves
`/x402/client.js` and `/x402/prepare` on the public tunnel origin. Browser
frontends served by another route in the same tunnel can import
`/x402/client.js` and use `x402Fetch()` for Sui payments. Casper clients read
the 402 requirements from the protected resource, sign them with a compatible
external SDK, and retry with `PAYMENT-SIGNATURE` or `X-PAYMENT`; the embedded
browser client remains Sui-only. Payment is enforced by the tunnel before the
request reaches the upstream.

#### x402 payment networks

| Network | Asset | Decimals | Facilitator |
|---|---|---|---|
| `sui:mainnet`, `sui:testnet` | USDC gasless stablecoin | 6 | Built-in Sui facilitator |
| `casper:casper`, `casper:casper-test` | wCSPR CEP-18 token | 9 | `https://x402-facilitator.cspr.cloud`, overridable per payment |

Casper has no Go chain SDK, so `casper:*` payments delegate `/verify` and
`/settle` to a remote x402 facilitator over HTTP. The wCSPR CEP-18 contract
hash differs per network deployment, so it must be set as the payment asset.
The default CSPR.cloud facilitator requires an access token in
`CSPR_CLOUD_API_KEY`; use `x402_facilitator_token` only when the agent service
cannot receive that environment variable.

```toml
x402_network = "casper:casper-test"
x402_asset = "hash-..."
x402_pay_to = "account-hash-..."
x402_endpoints = ["https://x402-facilitator.cspr.cloud"]
```

For a task-oriented walkthrough, see [Portal Agent](/portal-agent).

### `identity.json`

Stores the secp256k1 identity used to sign tunnel sessions and relay descriptors. `portal expose` treats `--identity-path` as a direct JSON file path. `relay-server` treats `IDENTITY_PATH` as a state directory and stores this file at `IDENTITY_PATH/identity.json`.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable label for this identity |
| `address` | string | Derived EVM address used for SIWE and identity ownership |
| `public_key` | string | Compressed secp256k1 public key hex |
| `private_key` | string | secp256k1 private key hex; keep secret |
| `mnemonic` | string | BIP-39 mnemonic used to derive the secp256k1 identity key; keep secret |
| `derivation_path` | string | EVM derivation path for `mnemonic`; defaults to `m/44'/60'/0'/0/0` |
| `wireguard_public_key` | string | Relay-only WireGuard overlay public key when discovery is enabled |
| `wireguard_private_key` | string | Relay-only WireGuard overlay private key when discovery is enabled |
| `encrypted_client_hello_seed` | string | Relay-only HKDF salt for deriving the ECH HPKE private key; generated automatically when missing; keep secret |

When `mnemonic` is present, Portal derives the private key at `derivation_path`
and preserves the mnemonic form when rewriting `identity.json`. The same
identity file or state directory can be reused across restarts to keep a stable
address.

### `policy.json`

Persists relay policy state. Managed automatically by the relay on write; do not edit manually while the server is running.

Relay policy settings are stored at `IDENTITY_PATH/policy.json`.

---

## ACME DNS Provider Configuration

Set `ACME_DNS_PROVIDER` (or `--acme-dns-provider`) to one of the values below to enable DNS-backed automation. Portal uses the same provider for DNS-01 challenges, managed A records, the relay root HTTPS/ECH record, tenant A and HTTPS/ECH records for tunnels with `ech = true`, and optional ENS gasless DNS records. The default `ech = false` tunnel mode does not create tenant ECH DNS records.

An empty value selects `embedded`, the canonical managed backend; see [Embedded DNS](#embedded-dns) for NS/glue delegation, DS setup, and persistent signing-key requirements. The external providers below are deprecated but remain available until a future major release. Valid manually supplied `fullchain.pem` and `privatekey.pem` files in `IDENTITY_PATH` take precedence over managed certificate issuance only when neither `acme-account.key` nor `acme-registration.json` exists, regardless of provider selection. If either ACME state file remains, Portal treats the PEM files as managed certificate material. Manual overrides do not disable embedded A-record serving, ECH publication, or opt-in ENS automation through the selected provider.

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

### Njalla DNS (`njalla`)

| Variable | Required | Description |
|----------|----------|-------------|
| `NJALLA_TOKEN` | Yes | Njalla API token with DNS record write access |

Note: Njalla supports managed ACME, A records, TXT records, and HTTPS/ECH records. Portal does not automate Njalla DNSSEC signing, so `ACME_DNS_PROVIDER=njalla` does not support ENS gasless DNSSEC automation.

### Vultr DNS (`vultr`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VULTR_API_KEY` | Yes | Vultr API key with DNS domain, record, and DNSSEC write access |
