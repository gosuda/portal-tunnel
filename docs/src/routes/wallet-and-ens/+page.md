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
- config mutation, tunnel changes, relay changes, shutdown, and multi-hop edits
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
changes, while DNSSEC is synchronized periodically while `ens.verified` is
false. Embedded DNS remains unverified and continues synchronization because
local signing does not authenticate parent delegation.

Portal writes TXT values in this shape:

```text
ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 <address>
```

The base-domain address is the relay identity address. Lease hostname addresses
come from the tunnel identity that registered each lease.

ENS gasless automation does not perform an onchain ENS claim transaction. It
only prepares DNSSEC-backed DNS records for ENS-aware clients.

## Enable ENS Gasless

Requirements for every supported provider:

- public relay domain, not `localhost`
- `ENS_GASLESS_ENABLED=true` (the default is `false`)
- a DNSSEC-capable provider and a valid DNSSEC chain through the parent zone for ENS clients to validate the records

For the preferred **embedded** setup, leave `ACME_DNS_PROVIDER` unset or set it to `embedded`, configure NS/glue delegation to the relay, and persist `IDENTITY_PATH/dnssec-csk.json`. Embedded DNS signs the ENS TXT records and exports a DS when its local listeners start and in ENS status; after delegation is reachable, publish that DS at the parent zone. No DNS API credentials are needed. Local signing does not verify parent publication: embedded status remains `pending` and `ens.verified=false` because Portal does not authenticate the parent chain. See [Embedded DNS](/configuration#embedded-dns) for trust-chain and key-persistence requirements.

External providers remain available, though deprecated until a future major release. They do not start embedded DNS and do not use its port, NS/glue setup, or `dnssec-csk.json`:

| Provider | ENS DNSSEC setup |
|----------|------------------|
| `cloudflare` | DNS API token with DNS write/DNSSEC access; publish the exported DS at the registrar unless Cloudflare Registrar handles it |
| `gcloud` | Application Default Credentials with Cloud DNS write access; signing and DS details come from the selected managed zone |
| `route53` | AWS credentials with Route53 DNSSEC access and an active key-signing key; `AWS_DNSSEC_KMS_KEY_ARN` is needed if Portal must create that key |
| `vultr` | API key with DNS record and DNSSEC write access; publish the exported DS at the registrar |
| `hetzner`, `njalla` | Managed ACME/DNS remains supported, but ENS DNSSEC automation is unsupported |

Provider signing states do not by themselves prove registrar DS publication or successful ENS resolution. For all providers, verify the public chain separately.

Embedded example:

```bash
PORTAL_URL=https://portal.example.com
IDENTITY_PATH=/portal-certs
ACME_DNS_PROVIDER=embedded
ENS_GASLESS_ENABLED=true
```

The same provider is used for ACME DNS-01, managed A records, the relay root
HTTPS/ECH record, tenant HTTPS/ECH records for tunnels that explicitly enable
ECH, DNSSEC, and ENS TXT records. The default tunnel mode does not create tenant
ECH records. Valid manual `fullchain.pem` and `privatekey.pem`
under `IDENTITY_PATH` override certificate issuance only when neither
`acme-account.key` nor `acme-registration.json` exists. Portal still uses the
selected provider for ENS/DNS automation, so external providers still require
API access even with a manual certificate.

## DNSSEC And Registrar State

DNSSEC has two sides:

- the DNS provider signs the hosted zone
- the registrar publishes the DS record at the parent zone

Portal can automate provider-side setup for supported providers. It cannot
always publish the registrar-side DS record. If `/sdk/domain` reports a pending
DNSSEC state and a `ds_record`, publish that DS in the parent zone after
checking delegation and wait for propagation. Embedded DNS remains `pending`
even afterward: Portal does not authenticate the parent chain or automatically
set `ens.verified=true`. ENS-aware clients can still validate and resolve the
signed TXT records independently of that diagnostic flag.

## Check ENS Status

The relay exposes ENS status through `/sdk/domain`:

```bash
curl https://portal.example.com/sdk/domain
```

Relevant response fields:

| Field | Meaning |
|-------|---------|
| `ens.enabled` | ENS gasless automation is enabled for a non-local relay domain |
| `ens.verified` | Legacy provider-state diagnostic: a recognized active external-provider state and a successful last sync; not an authenticated parent-chain or ENS resolution check. Always false for embedded DNS |
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

- with embedded DNS, verify the persisted signing key is readable only by the relay account and that the DNS port can bind; check NS/glue delegation before publishing its DS
- with Cloudflare, Google Cloud DNS, Route53, or Vultr, verify the selected provider's credentials and DNSSEC permissions; Hetzner and Njalla do not support ENS automation
- use a public `PORTAL_URL`, not localhost

`ens.verified` stays false:

- this is expected with embedded DNS, including after DS propagation; Portal does not authenticate its parent chain, and synchronization continues
- check `ens.last_error` and provider-specific `ens.message` from `/sdk/domain`
- with an external provider, confirm its credentials can edit DNS records and inspect its reported DNSSEC state; the legacy flag recognizes `active`, `on`, `signing`, and `transfer`, not Vultr's `enabled` state
- validate delegation, parent DS, and signed ENS TXT resolution independently; a false diagnostic flag does not prevent ENS clients from resolving a valid chain

A lease hostname has no ENS TXT record:

- confirm the tunnel is registered and not expired
- confirm the hostname is under the relay base domain
- check relay logs for `ensure ens gasless txt` or provider errors

## Next Steps

- [Deployment](/deployment#ens-gasless-automation): production setup
- [Security Model](/security-model): identity and TLS trust boundaries
- [Portal Agent](/portal-agent): local durable tunnel management
