---
title: SIWE Authentication
description: How Portal uses SIWE for tunnel registration, application access, and local agent status access.
---

# SIWE Authentication

Portal uses Sign-In with Ethereum (SIWE) in three separate places:

- tunnel registration, signed automatically by the local tunnel identity
- optional tunnel-side access control for exposed HTTP applications
- optional browser wallet login for local agent status access

For the full operational guide, see [Wallet and ENS](/wallet-and-ens).

## Tunnel Registration

`portal expose` and `portal agent` create or load a local secp256k1 identity
from `identity.json`. During registration, the relay returns a SIWE challenge
with statement `Register a portal lease`; the tunnel signs it with the local
identity private key and receives a lease access token.

`identity.json` can store the signing key directly as `private_key`, or store a
BIP-39 `mnemonic` with `derivation_path` and let Portal derive the key at load
time.

This flow is automatic. It does not require a browser wallet.

```bash
portal expose 3000 --name myapp
```

## Application Access

Add `--auth` to require a browser wallet login before Portal forwards an HTTP
request to the application:

```bash
portal expose 3000 --auth
portal expose 3000 --auth --auth-allow 0x1234...
```

With no `--auth-allow`, any wallet that proves control of its address can sign
in. Repeat `--auth-allow` to restrict access to specific Ethereum addresses.
Portal keeps the two-minute, single-use challenge and the 24-hour signed
session local to the tunnel endpoint. The cookie is `Secure`, `HttpOnly`, and
`SameSite=Lax`; relay-issued lease tokens are not used for application access.

Inbound `X-Portal-User` and `X-Portal-Auth` headers are always removed. Add
`--auth-identity-headers` to inject the verified address and `siwe` auth method
after login. Upstreams must only trust these headers when they cannot be
reached except through this local Portal proxy.

Application auth covers proxied HTTP routes, static sites, and x402 endpoints.
It cannot be combined with raw TCP/UDP or relay static caching.

## Agent Wallet Status Access

Relay admin access uses `ADMIN_TOKEN`, not SIWE.

The local agent also exposes `/agent/auth/*` wallet endpoints. Agent wallet
sessions can read `/agent/status`; tunnel mutations still require the local
bearer token stored in the agent state directory.

## ENS

Portal does not use ENS names as tunnel names. Tunnel names are single DNS
labels such as `myapp`.

Relay operators can optionally enable ENS gasless DNS import. In that mode,
Portal manages DNSSEC and `ENS1 ...` TXT records for the relay domain and lease
hostnames so ENS-aware clients can resolve them to Portal identity addresses.

## Next Steps

- [Wallet and ENS](/wallet-and-ens): detailed wallet and ENS behavior
- [Security Model](/security-model): encryption and identity boundaries
- [Configuration](/configuration): full configuration reference
