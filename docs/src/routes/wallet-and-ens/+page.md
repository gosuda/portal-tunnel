---
title: Wallet and ENS
description: How Portal uses local identities, admin tokens, SIWE, and ENS gasless DNS import.
---

# Wallet and ENS

Portal uses Ethereum-style signatures in several different places. They are
related, but they do not all mean "connect a browser wallet".

## Identity Surfaces

| Surface | Key material | Purpose |
|---------|--------------|---------|
| Tunnel identity | Local `identity.json` secp256k1 private key, or BIP-39 mnemonic plus derivation path | Signs SIWE lease registration challenges |
| Relay identity | Relay `IDENTITY_PATH/identity.json` secp256k1 private key, or BIP-39 mnemonic plus derivation path | Signs relay descriptors, lease access tokens, and ENS base-domain address |
| Relay admin token | `ADMIN_TOKEN` | Signs in to `/admin` and authorizes relay policy changes |
| Agent wallet | Optional browser wallet allowlist | Reads loopback agent status through `/agent/status` |
| ENS gasless DNS | DNSSEC plus `ENS1 ...` TXT records | Lets ENS-aware clients resolve the relay domain and lease hostnames to Portal identities |

## Tunnel SIWE Registration

Tunnel registration always uses a SIWE challenge internally:

1. The tunnel creates or loads a local identity from `identity.json`.
2. The tunnel asks the relay for `/sdk/register/challenge`.
3. The relay returns a SIWE message with statement `Register a portal lease`.
4. The tunnel signs that message with the local identity private key using
   Ethereum `personal_sign` semantics.
5. The relay verifies the signature and returns a lease-scoped access token.
6. The access token is used for renew, unregister, reverse connect, keyless
   signing access, and UDP backhaul authentication.

This does not require MetaMask or a user wallet. It is accountless identity
proof based on the local tunnel key. `identity.json` may store a raw
`private_key`, or a BIP-39 `mnemonic` with `derivation_path` such as
`m/44'/60'/0'/0/0`.

There is no `--auth siwe` flag. The current CLI command is:

```bash
portal expose 3000 --name myapp
```

Use a stable identity path when the lease identity must survive working
directory changes:

```bash
portal expose 3000 \
  --name myapp \
  --identity-path ~/.config/portal/myapp.identity.json
```

The public lease name is a single DNS label such as `myapp`. It is not an ENS
name such as `alice.eth`.

## Relay Admin Token Login

The relay admin API uses a configured token. Set `ADMIN_TOKEN` to a long random
value before exposing the admin UI or policy API.

Example:

```bash
ADMIN_TOKEN=$(openssl rand -hex 32)
```

Admin token flow:

1. `POST /api/admin/auth/login` with `{ "token": "<admin-token>" }`.
2. The relay returns an `access_token`.
3. Admin endpoints require `Authorization: Bearer <access_token>`.

The token returned by login is the configured admin token; browser logout clears
the local stored token.

## Agent Wallet Login

The local agent also exposes SIWE wallet auth endpoints:

```text
/agent/auth/challenge
/agent/auth/login
/agent/auth/logout
/agent/auth/status
```

Agent wallet access is intentionally narrow:

- `agent.allowed_wallets` restricts which wallet addresses can sign in.
- when `allowed_wallets` is empty, any wallet can sign in to the loopback auth
  endpoint.
- wallet-authenticated requests can read `/agent/status`.
- config mutation, tunnel changes, relay changes, shutdown
  still require the bearer token in `<state_dir>/agent-endpoint.json`.

Example:

```toml
[agent]
allowed_wallets = ["0x1234567890abcdef1234567890abcdef12345678"]
```

See [Portal Agent](/portal-agent) for the control API details.

## ENS Gasless DNS Import

ENS gasless DNS import is optional relay-side DNS automation. It is separate
from tunnel registration and admin token login.

When enabled, Portal uses the configured DNS provider to:

- enable or inspect DNSSEC for the relay base domain
- publish `ENS1 ...` TXT records for the base domain
- publish `ENS1 ...` TXT records for lease hostnames
- keep A records for lease hostnames in sync with the relay public IPv4
- remove lease hostname records when leases unregister or expire

Lease registration and removal enqueue DNS changes to a single worker. Successful
TXT changes are not repeated by the periodic maintenance pass; only failed
changes are retried. Lease A records are checked again when the relay public IPv4
changes, while DNSSEC is checked periodically only until Portal reports it as
verified.

Portal writes TXT values in this shape:

```text
ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 <address>
```

The base-domain address is the relay identity address. Lease hostname addresses
come from the tunnel identity that registered each lease.

ENS gasless automation does not perform an onchain ENS claim transaction. It
only prepares DNSSEC-backed DNS records for ENS-aware clients.

## Enable ENS Gasless

Requirements:

- public relay domain, not `localhost`
- `ACME_DNS_PROVIDER=cloudflare`, `gcloud`, `route53`, or `vultr`
- provider credentials with DNS write access
- `ENS_GASLESS_ENABLED=true`
- DNSSEC active at the parent zone

Hetzner and Njalla are supported for managed ACME DNS automation, but not for ENS gasless automation because Portal does not automate DNSSEC signing for those providers.

Example:

```bash
PORTAL_URL=https://portal.example.com
IDENTITY_PATH=/portal-certs
ACME_DNS_PROVIDER=cloudflare
CLOUDFLARE_TOKEN=cf_xxxxxxxxxxxxxxxxx
ENS_GASLESS_ENABLED=true
```

The same provider is used for ACME DNS-01, managed A records, the relay root
HTTPS/ECH record, tenant HTTPS/ECH records for tunnels that explicitly enable
ECH, DNSSEC, and ENS TXT records. The default tunnel mode does not create tenant
ECH records. If manual `fullchain.pem` and `privatekey.pem`
already exist under `IDENTITY_PATH`, Portal keeps using those certificate files
and still uses the provider for ENS/DNS automation.

## DNSSEC And Registrar State

DNSSEC has two sides:

- the DNS provider signs the hosted zone
- the registrar publishes the DS record at the parent zone

Portal can automate provider-side setup for supported providers. It cannot
always publish the registrar-side DS record. If `/sdk/domain` reports a pending
DNSSEC state and a `ds_record`, copy that DS record into the registrar's DNSSEC
settings and wait for propagation.

## Check ENS Status

The relay exposes ENS status through `/sdk/domain`:

```bash
curl https://portal.example.com/sdk/domain
```

Relevant response fields:

| Field | Meaning |
|-------|---------|
| `ens.enabled` | ENS gasless automation is enabled for a non-local relay domain |
| `ens.verified` | Portal considers DNSSEC active and the last sync successful |
| `ens.provider` | DNS provider used for automation |
| `ens.address` | Base-domain ENS address, usually the relay identity address |
| `ens.dnssec_state` | Provider DNSSEC state |
| `ens.ds_record` | DS record that may need registrar publication |
| `ens.message` | Provider-specific DNSSEC guidance |
| `ens.last_error` | Last ENS/DNS sync error |

The relay frontend shows an `ENS verified` badge when `ens.verified` is true.

DNS checks:

```bash
dig +short DS portal.example.com
dig +short TXT portal.example.com
dig +short TXT myapp.portal.example.com
```

Expected TXT records start with `ENS1`.

## Troubleshooting

`ENS_GASLESS_ENABLED=true` fails at startup:

- set `ACME_DNS_PROVIDER`
- provide the provider credentials
- use a public `PORTAL_URL`, not localhost

`ens.verified` stays false:

- publish the DS record at the registrar
- wait for DNSSEC propagation
- check `ens.last_error` from `/sdk/domain`
- confirm the provider token can edit DNS records

A lease hostname has no ENS TXT record:

- confirm the tunnel is registered and not expired
- confirm the hostname is under the relay base domain
- check relay logs for `ensure ens gasless txt` or provider errors

## Next Steps

- [Deployment](/deployment#ens-gasless-automation): production setup
- [Security Model](/security-model): identity and TLS trust boundaries
- [Portal Agent](/portal-agent): local durable tunnel management
